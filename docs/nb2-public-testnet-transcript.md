# Wallet guide transcript: public testnet `tn-public-20261128`

> Historical record for generation `tn-public-20261128`. Use the current release manifest for live deployment values.

Run on 2026-11-26 (UTC) by following the guide ([`nb2-wallet-guide.md`](nb2-wallet-guide.md), "Try it: the reference wallet") literally:

- A clean clone of `ristik/native-bridge-plugins` at PR #92 at `399ecb74ca2db63ce81e2509e1cef8456d1e70f5` (the final head differs only in this transcript and the report; it has the origin-derived aggregator
  default), then `npm ci` (Node 24; the guide asks for 22 or later). A fresh wallet directory.
- The three release files downloaded from `https://pos.staging.unicity.network/release/` with the guide's commands. The manifest's SHA-256 is
  `a69fefdaaa162de43135f70e8913c03332838c34e39c398cdb1fd3f044cb8b91`, as `SHA256SUMS` lists.
- Public URLs only: gateway `https://pos.staging.unicity.network/rpc`; the aggregator came from the default (`<origin>/aggregator`).
- The EVM key is a scratch key funded with 5 UCT by the operator funder account, because the public faucet needs a human CAPTCHA. It was passed
  with `--key-env NB2_KEY` so that this fresh wallet reuses the funded address; `payer.json` is the guide's policy file.
- No step needed a deviation. An earlier run at the commit that generation's manifest pinned needed `--aggregator` because its default was `<rpc>/aggregator`.

Long hex values are shortened with `..` as in the guide; transaction hashes are complete.

```console
$ nb2-wallet init --release $REL/nb2-release.json --rpc https://pos.staging.unicity.network/rpc --key-env NB2_KEY
wallet ./w2 for the production vault 0x9836fc75a44d490d506c847245863f2812b94532 on chain 316695515
installation check passed: chain ID, config() = the pinned Γ, the vault's runtime code hash
fund this EVM address with UCT for deposits and gas: 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b

$ nb2-wallet address
EVM address 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b: 4.939998400362 UCT
Unicity owner key 0x0333c8d1cf6c858b1b29cd8b425d087ff5e07860191fdee77e461b0607f26ee7c5

$ nb2-wallet deposit coin 0.1
planned deposit intent 0 of 0.1 UCT as coin; the intent high-water mark is backed up
deposit 6 in block 315 (tx 0x46e11046e26a0c88bf046dd2124d89e9bf45ce731d2d59de05684e04108e7412)
next: mint coin

$ nb2-wallet mint coin
  the deposit proof: CompanionUnknown, retrying
minted coin: 0.1 UCT from deposit 6, token 0x0f2aef6ca962d253.., J 2233 bytes

$ nb2-wallet split coin keep=0.06 back=0.04
split coin into keep (0.06 UCT) + back (0.04 UCT)

$ nb2-wallet plan-return back --return-policy payer.json
the preflight passes: back (0.04 UCT) to 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b at index a = 0, vault at segment 0
  ordinary gas limit 17506048 of 24000000; room for 1374 historical proofs, 1310 beyond the reserve
nothing is burned. Run burn back to return it: the preflight runs again on fresh state first

$ nb2-wallet burn back --return-policy payer.json --backup back.private.json
the preflight passes again at index a = 0
burned back for 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b: 0.04 UCT, redemption ID 0x84d189825757e269.., 7824 evidence bytes
next: redeem back

$ nb2-wallet redeem back --return-policy payer.json
waiting for certification of 0x3404fb68aef0875a0a54d65edb2f6f80100e9ba0f180a3cc87eb2bfe636a873d; repeat this command

$ nb2-wallet redeem back --return-policy payer.json
paid 0.04 UCT to 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b in block 321, tx 0x3404fb68aef0875a0a54d65edb2f6f80100e9ba0f180a3cc87eb2bfe636a873d

$ nb2-wallet status
vault 0x9836fc75a44d490d506c847245863f2812b94532: segment 0, 6 deposits, 0.15 UCT outstanding
coin: deposit intent 0 of 100000000000000000: minted (deposit 6, block 315)
back: return 0x5c1f818d8c5b4e9c of 40000000000000000 to 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b (a = 0): paid

$ nb2-wallet tokens
keep: 0.06 UCT

$ nb2-wallet address
EVM address 0x77f9052a33d6c04fdc453c62da67fb4e4a25038b: 4.87999680012 UCT
Unicity owner key 0x0333c8d1cf6c858b1b29cd8b425d087ff5e07860191fdee77e461b0607f26ee7c5
```

Summary: deposit 0.1 UCT (deposit 6, block 315, tx `0x46e11046e26a0c88bf046dd2124d89e9bf45ce731d2d59de05684e04108e7412`), mint, split 0.06 + 0.04, burn the 0.04 part, and the vault paid it in block 321 (tx `0x3404fb68aef0875a0a54d65edb2f6f80100e9ba0f180a3cc87eb2bfe636a873d`). The EVM balance went from 4.93999840 to 4.87999680 UCT: the 0.1 deposit less the 0.04 return, plus gas.
