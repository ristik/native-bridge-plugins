/**
 * Rewrites tests/nb2-gas/gas-vectors.json: the redeem gas bound (src/nb2/gas.ts, bound-nb2-1179) on real evidence, its features and terms,
 * which the TypeScript (test/nb2/gas.test.ts) and the Rust plug-in (crates/native-bridge-sdk-ext/tests/nb2_gas.rs) must both reproduce.
 *
 *   npx tsx scripts/gen-nb2-gas-vectors.ts NAME=EVIDENCE.cbor ...
 *
 * Each evidence file (a burned part from the bft-core#1179 measurement lane, K = 4) gives two cases: at redemption (the evidence itself, P
 * gap proofs for P in 0 and 17) and at the preflight (the part before its burn, the burn pending at the decoder bounds, the evidence length the
 * preflight charges and 64 + 3 proofs).
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
  const [name, file] = arg.split('=');
  const evidence = new Uint8Array(readFileSync(file));
  const part = decodeEvidence(evidence);
  const pre: Token = { ...part, transfers: part.transfers.slice(0, -1), proofs: part.proofs.slice(0, -1), transfersRaw: part.transfersRaw.slice(0, -1) };
  const preBytes = evidenceOf(encodeToken(pre)).length + burnPairBound(104);
  const cases: { pending: number; proofs: bigint; evidenceBytes: number; lineage: Token[] }[] = [
    { pending: 0, proofs: 0n, evidenceBytes: evidence.length, lineage: lineageOf(part) },
    { pending: 0, proofs: 17n, evidenceBytes: evidence.length, lineage: lineageOf(part) },
    { pending: 1, proofs: 67n, evidenceBytes: preBytes, lineage: lineageOf(pre) },
  ];
  vectors.push({
    name,
    evidence: toHex(evidence),
    cases: cases.map((c) => {
      const s: RedeemShape = { evidenceBytes: c.evidenceBytes, lineage: c.lineage, pendingTransactions: c.pending, proofs: c.proofs, K: 4n };
      return { input: c.pending === 1 ? 'preflight' : 'redemption', pendingTransactions: c.pending, proofs: c.proofs, K: 4n, evidenceBytes: c.evidenceBytes,
        features: redeemFeatures(s), terms: redeemGasTerms(s) };
    }),
  });
}
writeFileSync(OUT, JSON.stringify(json({ model: 'bound-nb2-1179', generator: 'packages/native-bridge-plugin/scripts/gen-nb2-gas-vectors.ts', vectors }), null, 1) + '\n');
console.log(`${vectors.length} vectors written to ${OUT.pathname}`);
