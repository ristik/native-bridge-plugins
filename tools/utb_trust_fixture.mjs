#!/usr/bin/env node
// Installs every trust input the corpus and the shared dev fixture carry with the pinned SDK
// (TrustBaseHistory.fromBundle: complete, contiguous, witnessed link by link, genesis = pin), and
// checks that config/trust-base.bundle.cbor and .genesis.entryid are the fixture set's "pinned" entry.
//   node tools/utb_trust_fixture.mjs [--corpus DIR]
//   node tools/utb_trust_fixture.mjs --bundle FILE --pin HEX      (one installation; exit 1 if refused)
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { TrustBaseHistory } from '@unicitylabs/state-transition-sdk/lib/api/bft/trustbase/TrustBaseHistory.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const hex = (s) => new Uint8Array(Buffer.from(s, 'hex'));
const install = (bundle, pin) => TrustBaseHistory.fromBundle(bundle, pin);
const arg = (name) => {
  const i = process.argv.indexOf(name);
  return i < 0 ? undefined : process.argv[i + 1];
};

if (arg('--bundle')) {
  const history = await install(new Uint8Array(readFileSync(arg('--bundle'))), hex(arg('--pin')));
  console.log(`installed: epochs ${history.genesisEpoch}..${history.tipEpoch}`);
} else {
  const corpus = arg('--corpus') ?? path.join(root, 'protocol/vectors');
  const fixtures = JSON.parse(readFileSync(path.join(corpus, 'config/fixtures.json'), 'utf8'));
  const names = Object.keys(fixtures.trustBases).sort();
  assert.ok(names.includes('pinned'), 'the fixture set has no pinned trust input');
  for (const name of names) {
    const { bundle, pin } = fixtures.trustBases[name];
    await install(hex(bundle), hex(pin));
  }
  const bundle = readFileSync(path.join(corpus, 'config/trust-base.bundle.cbor'));
  const pin = readFileSync(path.join(corpus, 'config/trust-base.genesis.entryid'), 'utf8');
  assert.equal(bundle.toString('hex'), fixtures.trustBases.pinned.bundle, 'config/trust-base.bundle.cbor is not the pinned bundle');
  assert.equal(pin, `${fixtures.trustBases.pinned.pin}\n`, 'config/trust-base.genesis.entryid is not the pinned EntryID');
  const dev = path.join(root, 'tests/interop/utb-dev');
  const shared = await install(
    new Uint8Array(readFileSync(path.join(dev, 'bft-trustbase.dev.bundle.cbor'))),
    hex(readFileSync(path.join(dev, 'bft-trustbase.dev.genesis.entryid'), 'utf8').trim()),
  );
  console.log(`${names.length} corpus trust inputs install with the SDK; shared dev fixture epochs ${shared.genesisEpoch}..${shared.tipEpoch}`);
}
