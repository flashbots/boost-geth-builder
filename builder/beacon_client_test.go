package builder

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
)

type mockBeaconNode struct {
	srv *httptest.Server

	proposerDuties map[int][]byte
	forkResp       map[int][]byte
	headersCode    int
	headersResp    []byte
}

func newMockBeaconNode() *mockBeaconNode {
	r := mux.NewRouter()
	srv := httptest.NewServer(r)

	mbn := &mockBeaconNode{
		srv: srv,

		proposerDuties: make(map[int][]byte),
		forkResp:       make(map[int][]byte),
		headersCode:    200,
		headersResp:    []byte{},
	}

	r.HandleFunc("/eth/v1/validator/duties/proposer/{epoch}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		epochStr, ok := vars["epoch"]
		if !ok {
			http.Error(w, `{ "code": 400, "message": "invalid epoch" }`, 400)
			return
		}
		epoch, err := strconv.Atoi(epochStr)
		if err != nil {
			http.Error(w, `{ "code": 400, "message": "epoch not a number" }`, 400)
			return
		}

		resp, found := mbn.proposerDuties[epoch]
		if !found {
			http.Error(w, `{ "code": 400, "message": "epoch not found" }`, 400)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
	})

	r.HandleFunc("/eth/v1/beacon/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(mbn.headersCode)
		w.Write(mbn.headersResp)
	})

	return mbn
}

func TestFetchBeacon(t *testing.T) {
	mbn := newMockBeaconNode()
	defer mbn.srv.Close()

	mbn.headersCode = 200
	mbn.headersResp = []byte(`{ "data": [ { "header": { "message": { "slot": "10", "proposer_index": "1" } } } ] }`)

	// Green path
	headersResp := struct {
		Data []struct {
			Header struct {
				Message struct {
					Slot string `json:"slot"`
				} `json:"message"`
			} `json:"header"`
		} `json:"data"`
	}{}
	err := fetchBeacon(mbn.srv.URL+"/eth/v1/beacon/headers", &headersResp)
	require.NoError(t, err)
	require.Equal(t, "10", headersResp.Data[0].Header.Message.Slot)

	// Wrong dst
	wrongForkResp := struct {
		Data []struct {
			Slot string `json:"slot"`
		}
	}{}
	err = fetchBeacon(mbn.srv.URL+"/eth/v1/beacon/headers", &wrongForkResp)
	require.NoError(t, err)
	require.Equal(t, wrongForkResp.Data[0].Slot, "")

	mbn.headersCode = 400
	mbn.headersResp = []byte(`{ "code": 400, "message": "Invalid call" }`)
	err = fetchBeacon(mbn.srv.URL+"/eth/v1/beacon/headers", &headersResp)
	require.EqualError(t, err, "Invalid call")
}

func TestFetchEpochProposersMap(t *testing.T) {
	mbn := newMockBeaconNode()
	defer mbn.srv.Close()

	mbn.proposerDuties[10] = []byte(`{
  "dependent_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
  "execution_optimistic": false,
  "data": [
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
      "validator_index": "1",
      "slot": "1"
    },
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b",
      "validator_index": "2",
      "slot": "2"
    }
  ]
}`)

	proposersMap, err := fetchEpochProposersMap(mbn.srv.URL, 10)
	require.NoError(t, err)
	require.Equal(t, 2, len(proposersMap))
	require.Equal(t, PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"), proposersMap[1])
	require.Equal(t, PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b"), proposersMap[2])
}

func TestGetProposerForSlot(t *testing.T) {
	mbn := newMockBeaconNode()
	defer mbn.srv.Close()

	mbn.headersResp = []byte(`{ "data": [ { "header": { "message": { "slot": "31", "proposer_index": "1" } } } ] }`)

	mbn.proposerDuties[1] = []byte(`{
  "dependent_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
  "execution_optimistic": false,
  "data": [
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a",
      "validator_index": "1",
      "slot": "31"
    },
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b",
      "validator_index": "2",
      "slot": "32"
    },
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74c",
      "validator_index": "3",
      "slot": "33"
    }
  ]
}`)

	bc := NewBeaconClient(mbn.srv.URL)
	pubkeyHex, err := bc.getProposerForSlot(32)
	require.NoError(t, err)
	require.Equal(t, PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74b"), pubkeyHex)

	_, err = bc.getProposerForSlot(31)
	require.EqualError(t, err, "epoch not found")

	pubkeyHex, err = bc.getProposerForSlot(33)

	require.NoError(t, err)
	require.Equal(t, PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74c"), pubkeyHex)

	mbn.headersCode = 404
	mbn.headersResp = []byte(`{ "code": 404, "message": "State not found" }`)

	// Check that client does not fetch new proposers if epoch did not change
	mbn.headersCode = 200
	mbn.headersResp = []byte(`{ "data": [ { "header": { "message": { "slot": "31", "proposer_index": "1" } } } ] }`)
	mbn.proposerDuties[1] = []byte(`{
  "data": [
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74d",
      "validator_index": "4",
      "slot": "32"
    }
  ]
}`)

	mbn.headersResp = []byte(`{ "data": [ { "header": { "message": { "slot": "63", "proposer_index": "1" } } } ] }`)
	mbn.proposerDuties[2] = []byte(`{
  "data": [
    {
      "pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74d",
      "validator_index": "4",
      "slot": "64"
    }
  ]
}`)

	pubkeyHex, err = bc.getProposerForSlot(64)
	require.NoError(t, err)
	require.Equal(t, PubkeyHex("0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74d"), pubkeyHex)

	// Check proposers map error is routed out
	mbn.headersResp = []byte(`{ "data": [ { "header": { "message": { "slot": "65", "proposer_index": "1" } } } ] }`)
	_, err = bc.getProposerForSlot(65)
	require.EqualError(t, err, "no validator for requested slot")
}
