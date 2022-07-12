package builder

import (
	"bytes"
	"encoding/json"
	_ "os"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/beacon"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"

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
	SubmitBlock(msg *BuilderSubmitBlockRequest) error
	GetValidatorForSlot(nextSlot uint64) (ValidatorData, error)
}

type Builder struct {
	beaconClient IBeaconClient
	relay        IRelay

	builderSecretKey     *bls.SecretKey
	builderPublicKey     boostTypes.PublicKey
	builderSigningDomain boostTypes.Domain
}

func NewBuilder(sk *bls.SecretKey, bc IBeaconClient, relay IRelay, builderSigningDomain boostTypes.Domain) *Builder {
	pkBytes := bls.PublicKeyFromSecretKey(sk).Compress()
	pk := boostTypes.PublicKey{}
	pk.FromSlice(pkBytes)

	_, err := bc.onForkchoiceUpdate()
	if err != nil {
		log.Error("could not initialize beacon client", "err", err)
	}

	return &Builder{
		beaconClient:     bc,
		relay:            relay,
		builderSecretKey: sk,
		builderPublicKey: pk,

		builderSigningDomain: builderSigningDomain,
	}
}

func (b *Builder) onForkchoice(payloadAttributes *beacon.PayloadAttributesV1) {
	dataJson, err := json.Marshal(payloadAttributes)
	if err == nil {
		log.Info("FCU", "data", string(dataJson))
	}

	nextSlot, err := b.beaconClient.onForkchoiceUpdate()
	if err != nil {
		return
	}

	payloadAttributes.Slot = nextSlot

	if payloadAttributes != nil {
		if vd, err := b.relay.GetValidatorForSlot(nextSlot); err == nil {
			payloadAttributes.SuggestedFeeRecipient = [20]byte(vd.FeeRecipient)
			payloadAttributes.GasLimit = vd.GasLimit
		}
	}
}

func (b *Builder) newSealedBlock(data *beacon.ExecutableDataV1, block *types.Block, payloadAttributes *beacon.PayloadAttributesV1) {
	dataJson, err := json.Marshal(data)
	if err == nil {
		log.Info("newSealedBlock", "data", string(dataJson))
	}
	payload := executableDataToExecutionPayload(data)

	vd, err := b.relay.GetValidatorForSlot(payloadAttributes.Slot)
	if err != nil {
		log.Error("could not get validator while submitting block", "err", err, "slot", payloadAttributes.Slot)
		return
	}

	pubkey, err := boostTypes.HexToPubkey(string(vd.Pubkey))
	if err != nil {
		log.Error("could not parse pubkey", "err", err, "pubkey", vd.Pubkey)
		return
	}

	value := new(boostTypes.U256Str).FromBig(block.Profit)
	blockBidMsg := BuilderSubmitBlockRequestMessage{
		Slot:                 payloadAttributes.Slot,
		ParentHash:           payload.ParentHash,
		BlockHash:            payload.BlockHash,
		BuilderPubkey:        b.builderPublicKey,
		ProposerPubkey:       pubkey,
		ProposerFeeRecipient: boostTypes.Address(payloadAttributes.SuggestedFeeRecipient),
		Value:                *value,
	}

	/* signature, err := boostTypes.SignMessage(blockBidMsg, b.builderSigningDomain, b.builderSecretKey)
	if err != nil {
		log.Error("could not sign builder bid", "err", err)
		return
	} */

	signature := boostTypes.Signature{}
	blockSubmitReq := BuilderSubmitBlockRequest{
		Signature:        signature,
		Message:          blockBidMsg,
		ExecutionPayload: *payload,
	}

	err = b.relay.SubmitBlock(&blockSubmitReq)
	if err != nil {
		log.Error("could not submit block", "err", err)
		return
	}
}

func payloadToPayloadHeader(p *boostTypes.ExecutionPayload) (*boostTypes.ExecutionPayloadHeader, error) {
	txs := boostTypes.Transactions{
		Transactions: [][]byte{},
	}
	for i, tx := range p.Transactions {
		txs.Transactions[i] = []byte(tx)
	}
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
		ExtraData:        boostTypes.ExtraData(p.ExtraData),
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
