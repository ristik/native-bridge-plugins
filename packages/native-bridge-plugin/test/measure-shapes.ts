/**
 * Measures the resources of a return at a given history length (docs/admitted-shapes.md, "Resource limits"); not a test, run by hand:
 *   npx tsx test/measure-shapes.ts 800,850,900          every leaf under its own certificate (the original proofs, never refreshed)
 *   ONE_SEAL=1 npx tsx test/measure-shapes.ts 900,1700  every leaf under one certificate (a consolidated or freshly fetched bundle)
 * Prints one JSON line per length: token bytes (the admission bound is 2 MiB), envelope bytes (the direct bound is 2 MiB) and the plug-in's gas
 * estimate (the bound is the block capacity). The fixture tree holds the token's leaves only, so its paths are shorter than a live aggregator's.
 */
import { buildReturnProof } from '../src/proof.js';
import { buildToken, burnStep, makeWorld, spec, txStep } from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_100_000n;
const w = await makeWorld();
for (const n of (process.argv[2] ?? '50,200').split(',').map(Number)) {
  const steps = Array.from({ length: n + 1 }, (_, i) => (i === n ? burnStep(T0 + 20n + BigInt(n)) : txStep((i % 200) + 2, 7, T0 + 10n + BigInt(i))));
  const out = await buildToken(w, spec(1), steps, T0, UC_TS, process.env.ONE_SEAL ? {} : { ucRound: (i) => 100n + BigInt(i) });
  const r = await buildReturnProof(w.bridge, out.token);
  console.log(JSON.stringify({ transfers: n, leaves: n + 2, tokenBytes: out.bytes.length, envelopeBytes: r.encoded.length, anchors: r.envelope.anchors.length, gas: r.gate.total }));
}
