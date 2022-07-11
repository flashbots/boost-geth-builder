package builder

import (
	"bytes"
	"encoding/json"
	"html/template"
	"math/big"
	"net/http"
	_ "os"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/gorilla/mux"

	"github.com/flashbots/go-boost-utils/bls"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

type PubkeyHex string

type ValidatorData struct {
	Pubkey       PubkeyHex
	FeeRecipient boostTypes.Address `json:"feeRecipient"`
	GasLimit     uint64             `json:"gasLimit"`
	Timestamp    uint64             `json:"timestamp"`
}

type IBeaconClient interface {
	isValidator(pubkey PubkeyHex) bool
	getProposerForNextSlot(requestedSlot uint64) (PubkeyHex, error)
	onForkchoiceUpdate() (uint64, error)
}

type IRelay interface {
	GetValidatorForSlot(nextSlot uint64) (ValidatorData, error)
	GetValidatorsStats() string
	handleRegisterValidator(w http.ResponseWriter, req *http.Request)
}

type Backend struct {
	beaconClient IBeaconClient
	relay        IRelay

	builderSecretKey            *bls.SecretKey
	builderPublicKey            boostTypes.PublicKey
	serializedBuilderPoolPubkey hexutil.Bytes
	fd                          ForkData
	builderSigningDomain        boostTypes.Domain
	proposerSigningDomain       boostTypes.Domain
	enableBeaconChecks          bool

	bestDataLock sync.Mutex
	bestHeader   *boostTypes.ExecutionPayloadHeader
	bestPayload  *boostTypes.ExecutionPayload
	profit       *big.Int

	indexTemplate *template.Template
}

type ForkData struct {
	GenesisForkVersion    string
	BellatrixForkVersion  string
	GenesisValidatorsRoot string
}

func NewBackend(sk *bls.SecretKey, bc IBeaconClient, relay IRelay, fd ForkData, builderSigningDomain boostTypes.Domain, proposerSigningDomain boostTypes.Domain, enableBeaconChecks bool) *Backend {
	pkBytes := bls.PublicKeyFromSecretKey(sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	_, err := bc.onForkchoiceUpdate()
	if err != nil {
		log.Error("could not initialize beacon client", "err", err)
	}

	indexTemplate, err := parseIndexTemplate()
	if err != nil {
		log.Error("could not parse index template", "err", err)
		indexTemplate = nil
	}
	return &Backend{
		beaconClient:                bc,
		relay:                       relay,
		builderSecretKey:            sk,
		builderPublicKey:            pk,
		serializedBuilderPoolPubkey: pkBytes,

		fd:                    fd,
		builderSigningDomain:  builderSigningDomain,
		proposerSigningDomain: proposerSigningDomain,
		enableBeaconChecks:    enableBeaconChecks,
		indexTemplate:         indexTemplate,
	}
}

func (b *Backend) handleIndex(w http.ResponseWriter, req *http.Request) {
	if b.indexTemplate == nil {
		http.Error(w, "not available", http.StatusInternalServerError)
	}

	validatorsStats := b.relay.GetValidatorsStats()

	header := b.bestHeader
	headerData, err := json.MarshalIndent(header, "", "  ")
	if err != nil {
		headerData = []byte{}
	}

	payload := b.bestPayload
	payloadData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		payloadData = []byte{}
	}

	statusData := struct {
		Pubkey                string
		ValidatorsStats       string
		GenesisForkVersion    string
		BellatrixForkVersion  string
		GenesisValidatorsRoot string
		BuilderSigningDomain  string
		ProposerSigningDomain string
		Header                string
		Blocks                string
	}{hexutil.Encode(b.serializedBuilderPoolPubkey), validatorsStats, b.fd.GenesisForkVersion, b.fd.BellatrixForkVersion, b.fd.GenesisValidatorsRoot, hexutil.Encode(b.builderSigningDomain[:]), hexutil.Encode(b.proposerSigningDomain[:]), string(headerData), string(payloadData)}

	if err := b.indexTemplate.Execute(w, statusData); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (b *Backend) handleStatus(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type httpErrorResp struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func respondError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(httpErrorResp{code, message}); err != nil {
		http.Error(w, message, code)
	}
}

func (b *Backend) handleGetHeader(w http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	slot, err := strconv.Atoi(vars["slot"])
	if err != nil {
		respondError(w, http.StatusBadRequest, "incorrect slot")
		return
	}
	parentHashHex := vars["parent_hash"]
	pubkeyHex := PubkeyHex(strings.ToLower(vars["pubkey"]))

	// Do not validate slot separately, it will create a race between slot update and proposer key
	if nextSlotProposer, err := b.beaconClient.getProposerForNextSlot(uint64(slot)); err != nil || nextSlotProposer != pubkeyHex {
		log.Error("getHeader requested for public key other than next slots proposer", "requested", pubkeyHex, "expected", nextSlotProposer)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Only check if slot is within a couple of the expected one, otherwise will force validators resync
	vd, err := b.relay.GetValidatorForSlot(uint64(slot))
	if err != nil {
		respondError(w, http.StatusBadRequest, "unknown validator")
		return
	}
	if vd.Pubkey != pubkeyHex {
		respondError(w, http.StatusBadRequest, "unknown validator")
		return
	}

	b.bestDataLock.Lock()
	bestHeader := b.bestHeader
	profit := b.profit
	b.bestDataLock.Unlock()

	if bestHeader == nil || bestHeader.ParentHash.String() != parentHashHex {
		respondError(w, http.StatusBadRequest, "unknown payload")
		return
	}

	bid := boostTypes.BuilderBid{
		Header: bestHeader,
		Value:  *new(boostTypes.U256Str).FromBig(profit),
		Pubkey: b.builderPublicKey,
	}
	signature, err := boostTypes.SignMessage(&bid, b.builderSigningDomain, b.builderSecretKey)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	response := &boostTypes.GetHeaderResponse{
		Version: "bellatrix",
		Data:    &boostTypes.SignedBuilderBid{Message: &bid, Signature: signature},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
}

func (b *Backend) handleGetPayload(w http.ResponseWriter, req *http.Request) {
	payload := new(boostTypes.SignedBlindedBeaconBlock)
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		respondError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	if len(payload.Signature) != 96 {
		respondError(w, http.StatusBadRequest, "invalid signature")
		return
	}

	nextSlotProposerPubkeyHex, err := b.beaconClient.getProposerForNextSlot(payload.Message.Slot)
	if err != nil {
		if b.enableBeaconChecks {
			respondError(w, http.StatusBadRequest, "unknown validator")
			return
		}
	}

	nextSlotProposerPubkeyBytes, err := hexutil.Decode(string(nextSlotProposerPubkeyHex))
	if err != nil {
		if b.enableBeaconChecks {
			respondError(w, http.StatusBadRequest, "unknown validator")
			return
		}
	}

	ok, err := boostTypes.VerifySignature(payload.Message, b.proposerSigningDomain, nextSlotProposerPubkeyBytes[:], payload.Signature[:])
	if !ok || err != nil {
		if b.enableBeaconChecks {
			respondError(w, http.StatusBadRequest, "invalid signature")
			return
		}
	}

	b.bestDataLock.Lock()
	bestHeader := b.bestHeader
	bestPayload := b.bestPayload
	b.bestDataLock.Unlock()

	log.Info("Received blinded block", "payload", payload, "bestHeader", bestHeader)

	if bestHeader == nil || bestPayload == nil {
		respondError(w, http.StatusInternalServerError, "no payloads")
		return
	}

	if !ExecutionPayloadHeaderEqual(bestHeader, payload.Message.Body.ExecutionPayloadHeader) {
		respondError(w, http.StatusBadRequest, "unknown payload")
		return
	}

	response := boostTypes.GetPayloadResponse{
		Version: "bellatrix",
		Data:    bestPayload,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		respondError(w, http.StatusInternalServerError, "internal server error")
		return
	}
}

func (b *Backend) onForkchoice(payloadAttributes *beacon.PayloadAttributesV1) {
	dataJson, err := json.Marshal(payloadAttributes)
	if err == nil {
		log.Info("FCU", "data", string(dataJson))
	}
	// if payloadAttributes.SuggestedFeeRecipient == common.Address{}
	nextSlot, err := b.beaconClient.onForkchoiceUpdate()
	if err != nil {
		return
	}

	if payloadAttributes != nil {
		if vd, err := b.relay.GetValidatorForSlot(nextSlot); err == nil {
			payloadAttributes.SuggestedFeeRecipient = [20]byte(vd.FeeRecipient)
			payloadAttributes.GasLimit = vd.GasLimit
		}
	}
}

func (b *Backend) newSealedBlock(data *beacon.ExecutableDataV1, block *types.Block) {
	dataJson, err := json.Marshal(data)
	if err == nil {
		log.Info("newSealedBlock", "data", string(dataJson))
	}
	payload := executableDataToExecutionPayload(data)
	payloadHeader, err := payloadToPayloadHeader(payload, data)
	if err != nil {
		log.Error("could not convert payload to header", "err", err)
		return
	}

	b.bestDataLock.Lock()
	b.bestHeader = payloadHeader
	b.bestPayload = payload
	b.profit = new(big.Int).Set(block.Profit)
	b.bestDataLock.Unlock()
}

func payloadToPayloadHeader(p *boostTypes.ExecutionPayload, data *beacon.ExecutableDataV1) (*boostTypes.ExecutionPayloadHeader, error) {
	txs := boostTypes.Transactions{data.Transactions}
	txroot, err := txs.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return &boostTypes.ExecutionPayloadHeader{
		ParentHash:       p.ParentHash,
		FeeRecipient:     p.FeeRecipient,
		StateRoot:        p.StateRoot,
		ReceiptsRoot:     p.ReceiptsRoot,
		LogsBloom:        p.LogsBloom,
		Random:           p.Random,
		BlockNumber:      p.BlockNumber,
		GasLimit:         p.GasLimit,
		GasUsed:          p.GasUsed,
		Timestamp:        p.Timestamp,
		ExtraData:        data.ExtraData,
		BaseFeePerGas:    p.BaseFeePerGas,
		BlockHash:        p.BlockHash,
		TransactionsRoot: [32]byte(txroot),
	}, nil
}

func executableDataToExecutionPayload(data *beacon.ExecutableDataV1) *boostTypes.ExecutionPayload {
	transactionData := make([]hexutil.Bytes, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = hexutil.Bytes(tx)
	}

	return &boostTypes.ExecutionPayload{
		ParentHash:    [32]byte(data.ParentHash),
		FeeRecipient:  [20]byte(data.FeeRecipient),
		StateRoot:     [32]byte(data.StateRoot),
		ReceiptsRoot:  [32]byte(data.ReceiptsRoot),
		LogsBloom:     boostTypes.Bloom(types.BytesToBloom(data.LogsBloom)),
		Random:        [32]byte(data.Random),
		BlockNumber:   data.Number,
		GasLimit:      data.GasLimit,
		GasUsed:       data.GasUsed,
		Timestamp:     data.Timestamp,
		ExtraData:     data.ExtraData,
		BaseFeePerGas: *new(boostTypes.U256Str).FromBig(data.BaseFeePerGas),
		BlockHash:     [32]byte(data.BlockHash),
		Transactions:  transactionData,
	}
}

func ExecutionPayloadHeaderEqual(l *boostTypes.ExecutionPayloadHeader, r *boostTypes.ExecutionPayloadHeader) bool {
	return l.ParentHash == r.ParentHash && l.FeeRecipient == r.FeeRecipient && l.StateRoot == r.StateRoot && l.ReceiptsRoot == r.ReceiptsRoot && l.LogsBloom == r.LogsBloom && l.Random == r.Random && l.BlockNumber == r.BlockNumber && l.GasLimit == r.GasLimit && l.GasUsed == r.GasUsed && l.Timestamp == r.Timestamp && l.BaseFeePerGas == r.BaseFeePerGas && bytes.Equal(l.ExtraData, r.ExtraData) && l.BlockHash == r.BlockHash && l.TransactionsRoot == r.TransactionsRoot
}
