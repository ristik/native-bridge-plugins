# Tester trust helper

`trust.ts` keeps a wallet's trust-base history current: it loads the held release bundle, appends newer entries through the SDK's
trust-base fetch (`refreshAll`) and persists the result atomically. The bft-core testnet driver (`deploy/testnet/bridge/nb2/driver.ts`)
uses it. The protocol 7 bridge tester (lock, mint, claim) was removed with that bridge (bft-core#1106).

```
npx tsx --test tester/trust.test.ts
```
