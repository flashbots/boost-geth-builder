[geth readme](README.original.md)

# Builder API

Builder API implementing [builder spec](https://github.com/ethereum/builder-specs), making geth into a standalone block builder. 

Run on your favorite network.

Requires `builder_payloadAttributes` update to be sent for block building, run [our Prysm fork](https://github.com/flashbots/prysm)

Test with [mev-boost](https://github.com/flashbots/mev-boost) and [mev-boost test cli](https://github.com/flashbots/mev-boost/tree/main/cmd/test-cli).

Provides summary page at the listening address' root (http://localhost:28545 by default).

## How it works

* Builder polls relay for the proposer registrations for the next epoch

Builder has two hooks into geth:
* On forkchoice update, changing the payload attributes feeRecipient to the one registered for next slot's validator
* On new sealed block, consuming the block as the next slot's proposed payload and submits it to the relay

Local relay is enabled by `--local_relay` and overwrites remote relay data. This is only meant for the testnets!  

To connect to a remote relay use `--builder.remote_relay_endpoint`.  

## Limitations

* Blocks are only built on a specialized call `builder_payloadAttributes`, see [our Prysm fork](https://github.com/flashbots/prysm)
* Does not accept external blocks
* Does not have payload cache, only the latest block is available

## Usage

Configure geth for your network, it will become the block builder.

Builder API options:
```
$ geth --help
    --builder                      (default: false)
          Enable the builder
   
    --builder.beacon_endpoint value (default: "http://127.0.0.1:5052")
          Beacon endpoint to connect to for beacon chain data [$BUILDER_BEACON_ENDPOINT]
   
    --builder.bellatrix_fork_version value (default: "0x02000000")
          Bellatrix fork version. For goerli use 0x02001020
          [$BUILDER_BELLATRIX_FORK_VERSION]
   
    --builder.genesis_fork_version value (default: "0x00000000")
          Gensis fork version. For goerli use 0x00001020 [$BUILDER_GENESIS_FORK_VERSION]
   
    --builder.genesis_validators_root value (default: "0x0000000000000000000000000000000000000000000000000000000000000000")
          Genesis validators root of the network. For goerli use
          0x043db0d9a83813551ee2f33450d23797757d430911a9320530ad8a0eabc43efb
          [$BUILDER_GENESIS_VALIDATORS_ROOT]
   
    --builder.listen_addr value    (default: ":28545")
          Listening address for builder endpoint [$BUILDER_LISTEN_ADDR]
   
    --builder.local_relay          (default: false)
          Enable the local relay
   
    --builder.relay_secret_key value (default: "0x2fc12ae741f29701f8e30f5de6350766c020cb80768a0ff01e6838ffd2431e11")
          Builder local relay API key used for signing headers [$BUILDER_RELAY_SECRET_KEY]
   
    --builder.remote_relay_endpoint value
          Relay endpoint to connect to for validator registration data, if not provided
          will expose validator registration locally [$BUILDER_REMOTE_RELAY_ENDPOINT]
   
    --builder.secret_key value     (default: "0x2fc12ae741f29701f8e30f5de6350766c020cb80768a0ff01e6838ffd2431e11")
          Builder key used for signing blocks [$BUILDER_SECRET_KEY]
   
    --builder.validator_checks     (default: false)
          Enable the validator checks
```
