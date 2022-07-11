package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
	boostTypes "github.com/flashbots/go-boost-utils/types"
)

type testRelay struct {
	validator ValidatorData
}

func (r *testRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	return r.validator, nil
}
func (r *testRelay) GetValidatorsStats() string {
	return ""
}
func (r *testRelay) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
}

type LocalRelay struct {
	beaconClient IBeaconClient

	builderSigningDomain boostTypes.Domain

	validatorsLock sync.RWMutex
	validators     map[PubkeyHex]ValidatorData
}

func NewLocalRelay(beaconClient IBeaconClient, builderSigningDomain boostTypes.Domain) *LocalRelay {
	return &LocalRelay{
		beaconClient:         beaconClient,
		builderSigningDomain: builderSigningDomain,
		validators:           make(map[PubkeyHex]ValidatorData),
	}
}

func (r *LocalRelay) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	payload := []boostTypes.SignedValidatorRegistration{}
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		log.Error("could not decode payload", "err", err)
		respondError(w, http.StatusBadRequest, "invalid payload")
		return
	}

	for _, registerRequest := range payload {
		if len(registerRequest.Message.Pubkey) != 48 {
			respondError(w, http.StatusBadRequest, "invalid pubkey")
			return
		}

		if len(registerRequest.Signature) != 96 {
			respondError(w, http.StatusBadRequest, "invalid signature")
			return
		}

		ok, err := boostTypes.VerifySignature(registerRequest.Message, r.builderSigningDomain, registerRequest.Message.Pubkey[:], registerRequest.Signature[:])
		if !ok || err != nil {
			log.Error("error verifying signature", "err", err)
			respondError(w, http.StatusBadRequest, "invalid signature")
			return
		}

		// Do not check timestamp before signature, as it would leak validator data
		if registerRequest.Message.Timestamp > uint64(time.Now().Add(10*time.Second).Unix()) {
			respondError(w, http.StatusBadRequest, "invalid payload")
			return
		}
	}

	for _, registerRequest := range payload {
		pubkeyHex := PubkeyHex(registerRequest.Message.Pubkey.String())
		if !r.beaconClient.isValidator(pubkeyHex) {
			respondError(w, http.StatusBadRequest, "not a validator")
			return
		}
	}

	r.validatorsLock.Lock()
	defer r.validatorsLock.Unlock()

	for _, registerRequest := range payload {
		pubkeyHex := PubkeyHex(registerRequest.Message.Pubkey.String())
		if previousValidatorData, ok := r.validators[pubkeyHex]; ok {
			if registerRequest.Message.Timestamp < previousValidatorData.Timestamp {
				respondError(w, http.StatusBadRequest, "invalid timestamp")
				return
			}

			if registerRequest.Message.Timestamp == previousValidatorData.Timestamp && (registerRequest.Message.FeeRecipient != previousValidatorData.FeeRecipient || registerRequest.Message.GasLimit != previousValidatorData.GasLimit) {
				respondError(w, http.StatusBadRequest, "invalid timestamp")
				return
			}
		}
	}

	for _, registerRequest := range payload {
		pubkeyHex := PubkeyHex(strings.ToLower(registerRequest.Message.Pubkey.String()))
		r.validators[pubkeyHex] = ValidatorData{
			Pubkey:       pubkeyHex,
			FeeRecipient: registerRequest.Message.FeeRecipient,
			GasLimit:     registerRequest.Message.GasLimit,
			Timestamp:    registerRequest.Message.Timestamp,
		}

		log.Info("registered validator", "pubkey", pubkeyHex, "data", r.validators[pubkeyHex])
	}

	w.WriteHeader(http.StatusOK)
}

func (r *LocalRelay) GetValidatorForSlot(nextSlot uint64) (ValidatorData, error) {
	pubkeyHex, err := r.beaconClient.getProposerForNextSlot(nextSlot)
	if err != nil {
		return ValidatorData{}, err
	}

	r.validatorsLock.RLock()
	if vd, ok := r.validators[pubkeyHex]; ok {
		r.validatorsLock.RUnlock()
		return vd, nil
	}
	r.validatorsLock.RUnlock()
	log.Info("no local entry for validator", "validator", pubkeyHex)
	return ValidatorData{}, errors.New("missing validator")
}

func (r *LocalRelay) GetValidatorsStats() string {
	r.validatorsLock.RLock()
	noValidators := len(r.validators)
	r.validatorsLock.RUnlock()
	return fmt.Sprint(noValidators) + " validators registered"
}

type RemoteRelay struct {
	endpoint string
	client   http.Client

	localRelay *LocalRelay

	validatorsLock       sync.RWMutex
	validatorSyncOngoing bool
	lastRequestedSlot    uint64
	validatorSlotMap     map[uint64]ValidatorData
}

func NewRemoteRelay(endpoint string, localRelay *LocalRelay) (*RemoteRelay, error) {
	r := &RemoteRelay{
		endpoint:             endpoint,
		client:               http.Client{Timeout: time.Second},
		localRelay:           localRelay,
		validatorSyncOngoing: false,
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

	if r.lastRequestedSlot == 0 || nextSlot > 12+r.lastRequestedSlot {
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

	r.validatorsLock.RLock()
	vd, found := r.validatorSlotMap[nextSlot]
	r.validatorsLock.RUnlock()
	if found {
		return vd, nil
	}

	return ValidatorData{}, errors.New("validator not found")
}

func (r *RemoteRelay) getSlotValidatorMapFromRelay() (map[uint64]ValidatorData, error) {
	req, err := http.NewRequest("GET", r.endpoint+"/relay/v1/builder/validators", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("client refused", "url", r.endpoint, "err", err)
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("could not read response body", "url", r.endpoint, "err", err)
		return nil, err
	}

	if resp.StatusCode >= 300 {
		return nil, errors.New(string(bodyBytes))
	}

	var dst GetValidatorRelayResponse
	err = json.Unmarshal(bodyBytes, &dst)
	if err != nil {
		log.Error("could not unmarshal response", "url", r.endpoint, "resp", string(bodyBytes), "dst", dst, "err", err)
		return nil, err
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

func (r *RemoteRelay) GetValidatorsStats() string {
	if r.localRelay != nil {
		return r.localRelay.GetValidatorsStats()
	}

	r.validatorsLock.RLock()
	nValidators := len(r.validatorSlotMap)
	r.validatorsLock.RUnlock()

	return fmt.Sprint(nValidators) + " registered for current and next epochs"
}

func (r *RemoteRelay) handleRegisterValidator(w http.ResponseWriter, req *http.Request) {
	if r.localRelay != nil {
		r.localRelay.handleRegisterValidator(w, req)
		return
	}

	http.Error(w, "invalid request", 400)
}
