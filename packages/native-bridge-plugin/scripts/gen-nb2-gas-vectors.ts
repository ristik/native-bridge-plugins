/** Inspect the historical model's terms on flat evidence. These terms do not qualify a protocol 10 deployment. */
import { readFileSync } from 'node:fs';

import { toHex } from '../src/bytes.js';
import { lineageOf } from '../src/nb2/bridge.js';
import { burnPairBound } from '../src/nb2/bridge.js';
import { redeemFeatures, redeemGasTerms, type RedeemShape } from '../src/nb2/gas.js';
import { encodeToken, type Token, type LineageLevel } from '../src/nb2/token.js';
import { decodeEvidence, evidenceOf } from '../src/nb2/verify.js';

const json = (v: unknown): unknown => JSON.parse(JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x)));

const vectors: unknown[] = [];
for (const arg of process.argv.slice(2)) {
  const [name, file, lab] = arg.split('=');
  const evidence = new Uint8Array(readFileSync(file));
  const part = decodeEvidence(evidence);
  const pre: Token = { ...part, transfers: part.transfers.slice(0, -1), proofs: part.proofs.slice(0, -1), transfersRaw: part.transfersRaw.slice(0, -1) };
  const preBytes = evidenceOf(encodeToken(pre)).length + burnPairBound(104);
  const cases: { pending: number; proofs: bigint; K: bigint; evidenceBytes: number; lineage: LineageLevel[] }[] = [
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
console.log(JSON.stringify(json({ model: 'estimate-nb2-1179', vectors }), null, 1));
