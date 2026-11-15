# Native bridge v2 wallet journal, format version 1

The TypeScript plug-in (`packages/native-bridge-plugin`, `src/nb2/journal.ts`, NB2-07 bft-core#1103) writes this format, and the
Rust plug-in (NB2-08, bft-core#1104) must read and write it unchanged. With a common format, a wallet can move between the two
implementations. This document is the format's definition: when the code and this document disagree, the code is wrong.

The journal holds the only state that cannot be rebuilt from public data:

- the deposit secret's intent counter;
- each deposit's evidence and token;
- each split;
- each certified burn.

Everything else is a cache: segment logs, gap trees, proofs, fee estimates. A wallet that loses the cache and keeps the journal still
redeems.

## Store

The store is a key-value store of UTF-8 JSON documents, one record per key. Records are written whole.

Every write is a compare-and-swap (`putIf(key, expected, value)`), against the exact text the writer last read or wrote. It must be
durable before it returns. The plug-in reads every record back, and does not take the step the record enables until the read-back
matches. A writer that loses the compare-and-swap stops with `JournalConflict`, so two processes sharing one store never both advance
a record. Within one process, calls on the same record are serialized.

| Key | Record |
|---|---|
| `nb2/v1/<D>/intents` | the intent counter |
| `nb2/v1/<D>/deposit/<i>` | the deposit of intent `i` (decimal) |
| `nb2/v1/<D>/split/<id>` | one split; `<id>` is the split ID in hex without `0x` |
| `nb2/v1/<D>/return/<id>` | one return; `<id>` is the return ID in hex without `0x` |

`<D>` is the deployment domain `D = H_U(Γ)`, in lowercase hex without `0x`. A record whose `domain` differs from its key's is refused.

## Encodings

- Byte strings: `0x` followed by lowercase hex.
- Integers: decimal strings with no leading zeros (`"0"` is zero). Amounts, nonces and indices exceed 2^53, so they are never JSON
  numbers.
- `format` is `"unicity-nb2-journal"` and `version` is the number `1`. A reader refuses any other format, version or `kind`.
- Unknown fields: a version 1 reader keeps them on rewrite and does not interpret them. A field this document marks optional may be
  absent.

Every record carries `format`, `version`, `kind` and `domain`. The tables below list the remaining fields.

## `intents`

| Field | Type | Meaning |
|---|---|---|
| `kind` | `"intents"` | |
| `keyScheme` | string | the wallet-versioned derivation of `k_w` from the seed; the plug-in's default is `nb2-hmac-sha256-v1`: `k_w = HMAC-SHA256(key = seed, "unicity-nb2/wallet-bridge-key/v1")` |
| `next` | dec | the next unused intent `i`; the high-water mark is `next - 1` |

The counter is written before the deposit record of the intent it allocates. A crash therefore wastes an intent but never reuses one.
This record is what the wallet backs up with the seed (spec section 5.1). To recover from the seed alone, scan intents `0 .. next-1`
and match each `rho` against the certified `Deposited` events (`recoverDeposits`). A look-ahead past the mark does not replace it.

## `deposit`

| Field | Type | Meaning |
|---|---|---|
| `kind` | `"deposit"` | |
| `keyScheme` | string | as in `intents` |
| `intent` | dec | `i` |
| `amount` | dec | the value to deposit, in wei |
| `ownerKey` | hex | the first owner's compressed secp256k1 key (33 bytes) |
| `firstOwner` | hex | `tag(39032, [1, b(0x01), b(key33)])`, 42 bytes |
| `rho` | hex | `H_E(DEPOSIT_SECRET \|\| D \|\| r)` with `r = HMAC-SHA256(k_w, C(b("UNICITY_NB2_DEPOSIT_INTENT"), b(D), i))` |
| `status` | string | `planned`, `submitted`, `deposited`, `proven` or `minted` |
| `backedUp` | bool | the high-water mark covering `i` has been handed to the backup |
| `sends` | array | every signed deposit transaction, in order (see below) |
| `depositTx` | hex, optional | the transaction that executed the deposit |
| `blockNumber` | dec, optional | its block |
| `depositNumber` | dec, optional | the vault's `n` |
| `receiptProof` | hex, optional | the `DepositProof` container |
| `reason` | hex, optional | `J = tag(39051, [1, b(D), n, b(r), DepositProof])` |
| `token` | hex, optional | the certified minted token |
| `secret` | hex, optional | `r` itself, only when the wallet backs up secrets instead of the high-water mark |
| `plannedBlock` | dec, optional | the head block at planning; before the first send, the vault's `Deposited` events from here on are searched for this `rho` |
| `seenDeposits` | array, optional | every `Deposited` event carrying this `rho`, as `{tx, depositNumber, blockNumber, amount, token?}`; the first is the record's own; each further one (a reused secret, or two devices) is a separate root token, minted with `mintExtraDeposit` |

The status moves only forwards:

| Status | Entered when |
|---|---|
| `planned` | the record and the advanced counter are durable (`backedUp` may still be false) |
| `submitted` | a signed transaction has been added to `sends`; this happens before it is broadcast |
| `deposited` | a successful receipt has a `Deposited` log with this `rho` |
| `proven` | J is verified offline and stored |
| `minted` | the certified token is verified offline and stored |

The plug-in sends no value for a record that is not `planned` or `submitted`, is not backed up (unless the deployment opts out), or
whose `rho` does not derive from this wallet's `k_w`.

## `split`

| Field | Type | Meaning |
|---|---|---|
| `kind` | `"split"` | |
| `splitId` | hex | 32 bytes; by default `H_U(C(b("UNICITY_NB2_WALLET_SPLIT"), b(source)))` |
| `source` | hex | the held token being split |
| `outputs` | array of `{ownerKey, amount, salt, token}` | each child's owner key (33 bytes), amount (dec), mint salt (32 bytes) and certified token (hex or `null`) |
| `mask` | hex | the state mask of the manifest burn |
| `status` | string | `planned`, `burn-requested`, `burned` or `minted` |
| `burnTx` | hex, optional | the exact manifest burn transfer |
| `burnRequest` | hex, optional | its certification data (CD), written before the first submission |
| `burned` | hex, optional | the certified burned parent |

The plan (`source`, `outputs` with salts, `mask`) fixes the manifest and every child mint. A resumed split rebuilds the same bytes.

## `return`

| Field | Type | Meaning |
|---|---|---|
| `kind` | `"return"` | |
| `returnId` | hex | `H_U(source)` |
| `source` | hex | the held part before its burn |
| `amount` | dec | its whole amount |
| `recipient` | hex | the EVM recipient (20 bytes) |
| `a` | dec | the signed minimum segment index |
| `startHead` | hex | `H_a`: `headAfter` of the seal receipt that gave `a`, or `H_0` when `a = 0` |
| `fromBlock` | dec | the block of that seal receipt, or the deployment block; history and `Paid` logs are read from here |
| `sealReceipt` | hex, optional | the verified seal receipt (`DepositProof` container); absent when `a = 0` |
| `status` | string | `planned`, `burn-requested`, `burned`, `submitted` or `paid` |
| `burnTx` | hex, optional | the exact return burn transfer, data `R` |
| `burnRequest` | hex, optional | its CD, written before certification |
| `burned` | hex, optional | the certified burned part: the redeem evidence is `C(1, burned)` |
| `eta` | hex, optional | the redemption ID, from the offline verdict |
| `sends` | array | every signed redeem transaction |
| `payer` | hex, optional | the EVM account that pays the redeem's gas; `burn` re-checks its funds |
| `firstSendBlock` | dec, optional | the head block at the first broadcast |
| `paid` | `{txHash, blockNumber}`, optional | the transaction that emitted `Paid(eta)` |

Once a record holds `burnTx`, its burn never changes. Neither does `a`, so a refreshed witness only rebuilds the history. A record in
`burn-requested` resubmits exactly `burnRequest`.

## Send records

The `sends` arrays of deposits and returns hold objects of this shape:

| Field | Type | Meaning |
|---|---|---|
| `hash` | hex | `keccak256(raw)` |
| `raw` | hex | the signed EIP-1559 transaction |
| `nonce` | dec | its account nonce |
| `gas` | dec | its gas limit |
| `at` | dec | wall-clock milliseconds when it was signed (informational) |
| `nonceUsedAt` | dec, optional | the head block when a mined transaction of the account was first seen past this nonce without this send's success receipt |

A send is journaled before it is broadcast. The plug-in signs it through an `EvmSigner`, decodes the signed bytes, and refuses them unless they
are exactly the requested transaction (chain ID, nonce, fees, gas, target, value, data) from the signer's own address. The journaled
nonce comes from the signed bytes.

Before signing a new transaction, the plug-in checks the record's earlier sends, in this order:

1. It reads the account's **mined** (`latest`) nonce, then the receipt of every send. A successful receipt is the answer whenever it is
   seen, and nothing new is signed.
2. If the mined nonce has not reached the newest send's nonce, that send is still alive. The same raw bytes are broadcast again, and the
   step reports pending.
3. If a mined transaction has used the nonce and no successful receipt is visible, the send is not yet dead. The plug-in records
   `nonceUsedAt` and reports pending.
4. Only when the head has advanced `deadAfterBlocks` (6 by default) beyond `nonceUsedAt`, and every receipt has been read again without
   a success, is the send dead. Then a new transaction may be signed.

The order covers a send mined between two reads, and backends of a load-balanced gateway that sit at different heights.

## Example

```json
{"format":"unicity-nb2-journal","version":1,"domain":"0x5c…","kind":"deposit","keyScheme":"nb2-hmac-sha256-v1","intent":"0",
 "amount":"100","ownerKey":"0x02…","firstOwner":"0xd9987883014101582102…","rho":"0x9a…","status":"submitted","backedUp":true,
 "sends":[{"hash":"0x4f…","raw":"0x02f8…","nonce":"0","gas":"147516","at":"1763200000000"}],"plannedBlock":"1204"}
```
