# Wallet guide transcript: public testnet `tn-public-20261128`

Run on 2026-11-26 (UTC) from the guide ([`nb2-wallet-guide.md`](nb2-wallet-guide.md), "Try it: the reference wallet"). Setup:

- A clean clone of `ristik/native-bridge-plugins` at `f0e037a9c5df73b027d11cb3b1b1da55b5af7971`, the commit `bridge.sources` of the published
  `nb2-release.json` names, then `npm ci` (Node 24; the guide asks for 22 or later).
- `nb2-release.json`, `trust-base.bundle.cbor` and `trust-base.genesis.entryid` downloaded from `https://pos.staging.unicity.network/release/`.
  The manifest's SHA-256 was `a69fefdaaa162de43135f70e8913c03332838c34e39c398cdb1fd3f044cb8b91`, as `SHA256SUMS` lists.
- Public URLs only: gateway `https://pos.staging.unicity.network/rpc`, aggregator `https://pos.staging.unicity.network/aggregator`.
- A fresh wallet. The test EVM address received 5 UCT from the operator funder account, because the public faucet needs a human CAPTCHA.

Long hex values are shortened with `..` as in the guide; transaction hashes are complete.

```console
$ nb2-wallet init --release release/nb2-release.json --rpc https://pos.staging.unicity.network/rpc
wallet ./w for the production vault 0x9836fc75a44d490d506c847245863f2812b94532 on chain 316695515
installation check passed: chain ID, config() = the pinned Γ, the vault's runtime code hash
fund this EVM address with UCT for deposits and gas: 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b

$ nb2-wallet address
EVM address 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b: 5 UCT
Unicity owner key 0x0333c8d1cf6c858b1b29cd8b425d087ff5e07860191fdee77e461b0607f26ee7c5

$ nb2-wallet deposit coin 0.1
planned deposit intent 0 of 0.1 UCT as coin; the intent high-water mark is backed up
deposit 5 in block 242 (tx 0xbdfba050fd503068502b4c37bc0ebbccc01b251fbd72fc9fb49f11cc74284a88)
next: mint coin

$ nb2-wallet mint coin
  the deposit proof: CompanionUnknown, retrying
error: <html> ... 404 Not Found ... nginx/1.24.0 (Ubuntu) ... </html>
```

The first `mint` failed because `init` was run without `--aggregator`: the wallet defaulted to `<rpc>/aggregator`, which is
`/rpc/aggregator` and does not exist on the public route (the aggregator is `/aggregator`). This was a guide gap, and the guide now says to
pass `--aggregator`. The run continued by correcting `aggregator` in the wallet's `config.json`, which is what `init --aggregator` writes.

```console
$ nb2-wallet mint coin
minted coin: 0.1 UCT from deposit 5, token 0x6c7254e004d3c5b3.., J 2147 bytes

$ nb2-wallet split coin keep=0.06 back=0.04
split coin into keep (0.06 UCT) + back (0.04 UCT)

$ nb2-wallet status
vault 0x9836fc75a44d490d506c847245863f2812b94532: segment 0, 5 deposits, 0.13 UCT outstanding
coin: deposit intent 0 of 100000000000000000: minted (deposit 5, block 242)

$ nb2-wallet plan-return back
refused: CapacityPreflight: nb2: CapacityPreflight: explicit payer limits are required

$ nb2-wallet burn back
refused: CapacityPreflight: nb2: CapacityPreflight: explicit payer limits are required
```

The production vault needs a payer policy. This was the second guide gap; the guide now gives the policy file (`payer.json`) and its values.

```console
$ nb2-wallet plan-return back --return-policy payer.json
the preflight passes: back (0.04 UCT) to 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b at index a = 0, vault at segment 0
  ordinary gas limit 17506048 of 24000000; room for 1374 historical proofs, 1310 beyond the reserve
nothing is burned. Run burn back to return it: the preflight runs again on fresh state first

$ nb2-wallet burn back --return-policy payer.json --backup back.private.json
the preflight passes again at index a = 0
burned back for 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b: 0.04 UCT, redemption ID 0x9bd87e6bcedd1344.., 7770 evidence bytes
next: redeem back

$ nb2-wallet redeem back --return-policy payer.json
waiting for certification of 0x0bc2bea23d6e9a6a43ad6fd81fa9682e23d2d0040b748aa9281aad56415ca6cf; repeat this command

$ nb2-wallet redeem back --return-policy payer.json
waiting for certification of 0x0bc2bea23d6e9a6a43ad6fd81fa9682e23d2d0040b748aa9281aad56415ca6cf; repeat this command

$ nb2-wallet redeem back --return-policy payer.json
paid 0.04 UCT to 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b in block 294, tx 0x0bc2bea23d6e9a6a43ad6fd81fa9682e23d2d0040b748aa9281aad56415ca6cf

$ nb2-wallet status
vault 0x9836fc75a44d490d506c847245863f2812b94532: segment 0, 5 deposits, 0.09 UCT outstanding
coin: deposit intent 0 of 100000000000000000: minted (deposit 5, block 242)
back: return 0x157f0ca3da53fdfd of 40000000000000000 to 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b (a = 0): paid

$ nb2-wallet tokens
keep: 0.06 UCT

$ nb2-wallet address
EVM address 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b: 4.939998400362 UCT
Unicity owner key 0x0333c8d1cf6c858b1b29cd8b425d087ff5e07860191fdee77e461b0607f26ee7c5
```

Summary: deposit 0.1 UCT (block 242), mint, split 0.06 + 0.04, burn the 0.04 part, and the vault paid it back in block 294. The
vault's outstanding balance fell from 0.13 to 0.09 UCT, and the wallet ended at 4.94 UCT of EVM balance (5 - 0.1 + 0.04, less gas) plus a
0.06 UCT Unicity token.
