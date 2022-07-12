package builder

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	boostTypes "github.com/flashbots/go-boost-utils/types"
	"github.com/flashbots/mev-boost/server"
)

type testRelay struct {
	validator ValidatorData
}

func (r *testRelay) SubmitBlock(msg *BuilderSubmitBlockRequest) error {
	return nil
}
func (r *testRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	return r.validator, nil
}
func (r *testRelay) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
}

type RemoteRelay struct {
	endpoint string
	client   http.Client

	localRelay *LocalRelay

	validatorsLock       sync.RWMutex
	validatorSyncOngoing bool
	currentSlot          uint64
	lastRequestedSlot    uint64
	validatorSlotMap     map[uint64]ValidatorData
}

func NewRemoteRelay(endpoint string, localRelay *LocalRelay) (*RemoteRelay, error) {
	r := &RemoteRelay{
		endpoint:             endpoint,
		client:               http.Client{Timeout: time.Second},
		localRelay:           localRelay,
		validatorSyncOngoing: false,
		currentSlot:          0,
		lastRequestedSlot:    0,
		validatorSlotMap:     make(map[uint64]ValidatorData),
	}

	err := r.updateValidatorsMap(0, 3)
	return r, err
}

type GetValidatorRelayResponse []struct {
	Slot  string `json:"slot"`
	Entry struct {
		Message struct {
			FeeRecipient string `json:"fee_recipient"`
			GasLimit     string `json:"gas_limit"`
			Timestamp    string `json:"timestamp"`
			Pubkey       string `json:"pubkey"`
		} `json:"message"`
		Signature string `json:"signature"`
	} `json:"entry"`
}

func (r *RemoteRelay) updateValidatorsMap(currentSlot uint64, retries int) error {
	r.validatorsLock.Lock()
	if r.validatorSyncOngoing {
		r.validatorsLock.Unlock()
		return errors.New("sync is ongoing")
	}
	r.validatorSyncOngoing = true
	r.validatorsLock.Unlock()

	newMap, err := r.getSlotValidatorMapFromRelay()
	for err != nil && retries > 0 {
		time.Sleep(time.Second)
		newMap, err = r.getSlotValidatorMapFromRelay()
		retries -= 1
	}
	r.validatorsLock.Lock()
	r.validatorSyncOngoing = false
	if err == nil {
		r.validatorSlotMap = newMap
		r.lastRequestedSlot = currentSlot
	}
	r.validatorsLock.Unlock()

	log.Info("Updated validators", "new", newMap, "for slot", currentSlot)

	return nil
}

func (r *RemoteRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	// next slot is expected to be the actual chain's next slot, not something requested by the user!
	// if not sanitized it will force resync of validator data and possibly is a DoS vector

	r.validatorsLock.RLock()
	defer r.validatorsLock.RUnlock()

	r.currentSlot = nextSlot
	if r.lastRequestedSlot == 0 || nextSlot/32 > r.lastRequestedSlot/32 {
		// Every epoch request validators map
		go func() {
			err := r.updateValidatorsMap(nextSlot, 1)
			if err != nil {
				log.Error("could not update validators map", "err", err)
			}
		}()
	}

	if r.localRelay != nil {
		localValidator, err := r.localRelay.GetValidatorForSlot(nextSlot)
		if err == nil {
			log.Info("Validator registration overwritten by local data", "slot", nextSlot, "validator", localValidator)
			return localValidator, nil
		}
	}

	vd, found := r.validatorSlotMap[nextSlot]
	if found {
		return vd, nil
	}

	return ValidatorData{}, errors.New("validator not found")
}

type BuilderSubmitBlockRequestMessage struct {
	Slot                 uint64               `json:"slot,string"`
	ParentHash           boostTypes.Hash      `json:"parent_hash" ssz-size:"32"`
	BlockHash            boostTypes.Hash      `json:"block_hash" ssz-size:"32"`
	BuilderPubkey        boostTypes.PublicKey `json:"builder_pubkey" ssz-size:"48"`
	ProposerPubkey       boostTypes.PublicKey `json:"proposer_pubkey" ssz-size:"48"`
	ProposerFeeRecipient boostTypes.Address   `json:"proposer_fee_recipient" ssz-size:"32"`
	Value                boostTypes.U256Str   `json:"value" ssz-size:"32"`
}

type BuilderSubmitBlockRequest struct {
	Signature        boostTypes.Signature             `json:"signature"`
	Message          BuilderSubmitBlockRequestMessage `json:"message"`
	ExecutionPayload boostTypes.ExecutionPayload      `json:"execution_payload"`
}

func (r *RemoteRelay) SubmitBlock(msg *BuilderSubmitBlockRequest) error {
	code, err := server.SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodPost, r.endpoint+"/relay/v1/builder/blocks", msg, nil)
	if err != nil {
		return err
	}
	if code > 299 {
		return fmt.Errorf("non-ok response code %d from relay ", code)
	}

	if r.localRelay != nil {
		r.localRelay.SubmitBlock(msg)
	}

	return nil
}

func (r *RemoteRelay) getSlotValidatorMapFromRelay() (map[uint64]ValidatorData, error) {
	var dst GetValidatorRelayResponse
	code, err := server.SendHTTPRequest(context.TODO(), *http.DefaultClient, http.MethodGet, r.endpoint+"/relay/v1/builder/validators", nil, &dst)
	if err != nil {
		return nil, err
	}

	if code > 299 {
		return nil, fmt.Errorf("non-ok response code %d from relay", code)
	}

	res := make(map[uint64]ValidatorData)
	for _, data := range dst {
		slot, err := strconv.ParseUint(data.Slot, 10, 64)
		if err != nil {
			log.Error("Ill-formatted slot from relay", "data", data)
			continue
		}
		gasLimit, err := strconv.ParseUint(data.Entry.Message.GasLimit, 10, 64)
		if err != nil {
			log.Error("Ill-formatted gas_limit from relay", "data", data)
			continue
		}
		timestamp, err := strconv.ParseUint(data.Entry.Message.Timestamp, 10, 64)
		if err != nil {
			log.Error("Ill-formatted timestamp from relay", "data", data)
			continue
		}
		feeRecipientBytes, err := hexutil.Decode(data.Entry.Message.FeeRecipient)
		if err != nil {
			log.Error("Ill-formatted fee_recipient from relay", "data", data)
			continue
		}
		var feeRecipient boostTypes.Address
		feeRecipient.FromSlice(feeRecipientBytes[:])

		pubkeyHex := PubkeyHex(strings.ToLower(data.Entry.Message.Pubkey))

		res[slot] = ValidatorData{
			Pubkey:       pubkeyHex,
			FeeRecipient: feeRecipient,
			GasLimit:     gasLimit,
			Timestamp:    timestamp,
		}
	}

	return res, nil
}
