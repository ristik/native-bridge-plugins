/**
 * Rewrites tests/nb2-gas/gas-vectors.json: the redeem gas bound (src/nb2/gas.ts, estimate-nb2-1179) on real evidence, its features and terms,
 * which the TypeScript (test/nb2/gas.test.ts) and the Rust plug-in (crates/native-bridge-sdk-ext/tests/nb2_gas.rs) must both reproduce.
 *
 *   npx tsx scripts/gen-nb2-gas-vectors.ts NAME=EVIDENCE.cbor[=LABGAS] ...
 *
 * LABGAS is the evidence's measured gas in the forge lab (the deployed verifier bytecode with constant stubs for the two natives); the
 * suites check that the estimate's execution, memory and SHA-256 terms at redemption are at or above it.
 *
 * Each evidence file (a burned part from the bft-core#1179 measurement lane, or one with its UCs replaced by synthetic ones: shard tree
 * siblings, non-ASCII node IDs, 16 or 17 signatures, 24 KiB seals, a non-text signature key) gives five cases: at redemption (the evidence
 * itself; P 0 and 17 at K = 4, P 17 at K = 64) and at the preflight (the part before its burn, the burn pending at the decoder bounds, the
 * evidence length the preflight charges, 64 + 3 proofs, K = 4 and 64). A vector whose bound is null (fail closed) records null.
 */
import { readFileSync, writeFileSync } from 'node:fs';

import { toHex } from '../src/bytes.js';
import { lineageOf } from '../src/nb2/bridge.js';
import { burnPairBound } from '../src/nb2/bridge.js';
import { redeemFeatures, redeemGasTerms, type RedeemShape } from '../src/nb2/gas.js';
import { encodeToken, type Token } from '../src/nb2/token.js';
import { decodeEvidence, evidenceOf } from '../src/nb2/verify.js';

const OUT = new URL('../../../tests/nb2-gas/gas-vectors.json', import.meta.url);
const json = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x)));

const vectors: unknown[] = [];
for (const arg of process.argv.slice(2)) {
  const [name, file, lab] = arg.split('=');
  const evidence = new Uint8Array(readFileSync(file));
  const part = decodeEvidence(evidence);
  const pre: Token = { ...part, transfers: part.transfers.slice(0, -1), proofs: part.proofs.slice(0, -1), transfersRaw: part.transfersRaw.slice(0, -1) };
  const preBytes = evidenceOf(encodeToken(pre)).length + burnPairBound(104);
  const cases: { pending: number; proofs: bigint; K: bigint; evidenceBytes: number; lineage: Token[] }[] = [
    { pending: 0, proofs: 0n, K: 4n, evidenceBytes: evidence.length, lineage: lineageOf(part) },
    { pending: 0, proofs: 17n, K: 4n, evidenceBytes: evidence.length, lineage: lineageOf(part) },
    { pending: 0, proofs: 17n, K: 64n, evidenceBytes: evidence.length, lineage: lineageOf(part) },
    { pending: 1, proofs: 67n, K: 4n, evidenceBytes: preBytes, lineage: lineageOf(pre) },
    { pending: 1, proofs: 67n, K: 64n, evidenceBytes: preBytes, lineage: lineageOf(pre) },
  ];
  vectors.push({
    name,
    ...(lab === undefined ? {} : { labGas: lab }),
    evidence: toHex(evidence),
    cases: cases.map((c) => {
      const s: RedeemShape = { evidenceBytes: c.evidenceBytes, lineage: c.lineage, pendingTransactions: c.pending, proofs: c.proofs, K: c.K };
      return { input: c.pending === 1 ? 'preflight' : 'redemption', pendingTransactions: c.pending, proofs: c.proofs, K: c.K, evidenceBytes: c.evidenceBytes,
        features: redeemFeatures(s), terms: redeemGasTerms(s) };
    }),
  });
}
writeFileSync(OUT, JSON.stringify(json({ model: 'estimate-nb2-1179', generator: 'packages/native-bridge-plugin/scripts/gen-nb2-gas-vectors.ts', vectors }), null, 1) + '\n');
console.log(`${vectors.length} vectors written to ${OUT.pathname}`);
