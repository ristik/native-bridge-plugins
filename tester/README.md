# Bridge tester

A small command-line tool for one person's round trip through the native bridge of a public **test** network. You use your own keys and
only the operator's public endpoints: lock test ether in the vault, mint the bridged token, transfer it, burn it, redeem it and claim
the ether back.

> **Fake value, no guarantees.** Everything here is test ether on a test network.
> - The network is reset without notice, and a reset loses every lock, token and credit.
> - Nothing carries over between networks or releases, and nothing is compatible with a later one.
> - A token exists only in its wallet file. Lose the file and the token is gone; the locked test ether stays in the vault.
> - The keys sit unencrypted in the wallet directory.
> - Nothing here is audited. Never put a key that holds real value into it.

## Running it

The tester ships in the bridge driver image (bft-core `deploy/testnet/bridge`), or runs from a checkout of this repository after `npm ci`:

```
npx tsx tester/bridge-tester.ts <command> [--wallet DIR] [options]
```

The wallet is a directory: `--wallet`, or `BRIDGE_TESTER_WALLET`, and `./bridge-wallet` by default.

| command | what it does |
| --- | --- |
| `init --config tester-config.json [--eth-key-file F]` | a new wallet: a fresh EVM key (or yours, from the file) and a copy of the configuration. Fund the printed address from the faucet. |
| `lock --amount 0.5` | locks the amount (ether, or `Nwei`) in the vault for a new token, owned by a fresh Unicity key of the wallet. At most 2^64 − 1 wei, about 18.4 ETH, per lock. |
| `mint` | fetches the lock's proof from the lock-proof endpoint and mints the token on the aggregator. Fetch it soon: the endpoint serves a lock only within its proof window (about 64 blocks on the testnet package). |
| `transfer [--count n]` | `n` certified transfers, each to a fresh key of the wallet. |
| `burn [--recipient 0x..]` | burns the token for its return to an EVM address, this wallet's by default. |
| `redeem` | builds the return proof and sends the redemption, which credits the burn's recipient. The aggregator consolidates the history under one seal, so a long history still makes a one-anchor proof. |
| `claim [--to 0x..]` | withdraws the wallet's whole vault credit to an address, its own by default. |
| `status` | the wallet's tokens, its balance and credit, and the vault's view of each lock (locked, redeemed). |

Every command except `init`, `status` and `claim` takes `--token <nonce>`, the newest token by default. A step out of order is refused,
and the error names the next step.

## The configuration

The operator publishes `tester-config.json` together with the four files it names. A tester never needs anything private.

```json
{
  "ethUrl": "https://rpc.example",
  "redeemEthUrl": "https://rpc-large.example",
  "aggUrl": "https://aggregator.example",
  "lockProofUrl": "https://lockproof.example",
  "chainId": 3,
  "vault": "0x...",
  "files": { "trustBundle": "trust-base.bundle.cbor", "trustEntryId": "trust-base.genesis.entryid", "evmPdr": "evm-pdr.cbor", "deployment": "bridge-deployment.json" }
}
```

`redeemEthUrl` is optional. A redemption carries the whole return proof, about 8 to 13 KB of bytes and so 16 to 26 KB as hex. A gateway
with a smaller request-body limit refuses it; the testnet package's public gateway takes 16 KiB. With `redeemEthUrl` set, redemptions go
there and every other call goes to `ethUrl`.

## What it checks

- Before minting, it checks that the vault's record of the lock is the one the plug-in derives from the wallet's key and amount.
- Each token file is re-parsed after every step.
- The plug-in verifies the return proof against the operator's trust base before the redemption is sent.
- The redemption is first run as an `eth_call`, and is sent only once the vault accepts it.

## Tests

`npx tsx --test tester/*.test.ts` runs the offline tests: the vault ABI against `cast`, amounts, the configuration, the token-file append
and the step order. The live round trip is a stage of the bft-core testnet package rehearsal (`deploy/testnet/bridge/rehearse_bridge.py`).
