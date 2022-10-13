package builder

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/log"
)

type testBeaconClient struct {
	validator *ValidatorPrivateData
	slot      uint64
}

func (b *testBeaconClient) isValidator(pubkey PubkeyHex) bool {
	return true
}
func (b *testBeaconClient) getProposerForSlot(requestedSlot uint64) (PubkeyHex, error) {
	return PubkeyHex(hexutil.Encode(b.validator.Pk)), nil
}

type BeaconClient struct {
	endpoint string

	mu              sync.Mutex
	currentEpoch    uint64
	slotProposerMap map[uint64]PubkeyHex
}

func NewBeaconClient(endpoint string) *BeaconClient {
	return &BeaconClient{
		endpoint:        endpoint,
		slotProposerMap: make(map[uint64]PubkeyHex),
	}
}

func (b *BeaconClient) isValidator(pubkey PubkeyHex) bool {
	return true
}

func (b *BeaconClient) getProposerForSlot(requestedSlot uint64) (PubkeyHex, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	requestedEpoch := requestedSlot / 32
	if requestedEpoch != b.currentEpoch {
		slotProposerMap, err := fetchEpochProposersMap(b.endpoint, requestedEpoch)
		if err != nil {
			return PubkeyHex(""), err
		}

		b.currentEpoch = requestedEpoch
		b.slotProposerMap = slotProposerMap
	}

	nextSlotProposer, found := b.slotProposerMap[requestedSlot]
	if !found {
		return PubkeyHex(""), errors.New("no validator for requested slot")
	}

	return nextSlotProposer, nil
}

func fetchEpochProposersMap(endpoint string, epoch uint64) (map[uint64]PubkeyHex, error) {
	proposerDutiesResponse := &struct {
		Data []struct {
			PubkeyHex string `json:"pubkey"`
			Slot      string `json:"slot"`
		} `json:"data"`
	}{}

	err := fetchBeacon(fmt.Sprintf("%s/eth/v1/validator/duties/proposer/%d", endpoint, epoch), proposerDutiesResponse)
	if err != nil {
		return nil, err
	}

	proposersMap := make(map[uint64]PubkeyHex)
	for _, proposerDuty := range proposerDutiesResponse.Data {
		slot, err := strconv.Atoi(proposerDuty.Slot)
		if err != nil {
			log.Error("could not parse slot", "Slot", proposerDuty.Slot, "err", err)
			continue
		}
		proposersMap[uint64(slot)] = PubkeyHex(proposerDuty.PubkeyHex)
	}
	return proposersMap, nil
}

func fetchBeacon(url string, dst any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Error("invalid request", "url", url, "err", err)
		return err
	}
	req.Header.Set("accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Error("client refused", "url", url, "err", err)
		return err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error("could not read response body", "url", url, "err", err)
		return err
	}

	if resp.StatusCode >= 300 {
		ec := &struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}{}
		if err = json.Unmarshal(bodyBytes, ec); err != nil {
			log.Error("Couldn't unmarshal error from beacon node", "url", url, "body", string(bodyBytes))
			return errors.New("could not unmarshal error response from beacon node")
		}
		return errors.New(ec.Message)
	}

	err = json.Unmarshal(bodyBytes, dst)
	if err != nil {
		log.Error("could not unmarshal response", "url", url, "resp", string(bodyBytes), "dst", dst, "err", err)
		return err
	}

	log.Info("fetched", "url", url, "res", dst)
	return nil
}
