#!/usr/bin/env node
// Exact SDK-emitted JSON fixture; this tool neither installs nor authenticates a base.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';

const root = new URL('../', import.meta.url);
const document = new URL('protocol/vectors/config/sdk-root-trust-base.json', root);
const provenance = new URL('protocol/vectors/config/sdk-root-trust-base.provenance.json', root);
// The committee of bft-core's bridgeprofile oracle (seed root-1, network 3, epoch 1, one
// unit-weight validator): the corpus generator emits this same document; the SDK output
// below is the authority for its bytes.
const source = {
  version: '1', networkId: 3, epoch: '1', epochStartRound: '0',
  rootNodes: [{ nodeId: '16Uiu2HAmLkhEor7y4dw92gqx7chepA9XKNpDUvxWXu4xEghY2eEX', sigKey: '037853a1c7855a1876b4aa46fc3f0b381e21eb4314f37dbddb9f6df2ef42dbaa9c', stake: '1' }],
  quorumThreshold: '1', stateHash: '', changeRecordHash: null,
  previousEntryHash: null, signatures: { '16Uiu2HAmLkhEor7y4dw92gqx7chepA9XKNpDUvxWXu4xEghY2eEX': 'ba3545188fe09554216f410ad6e67ca67f473f121cacc4adffb62449976b03b41d0aba34767af8f1ca47e31bd7c95c96c11a22740b6dfb73f1fa38491a92717401' },
};
const bytes = Buffer.from(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()), 'utf8');
const sha256 = createHash('sha256').update(bytes).digest('hex');
const metadata = {
  fixture: 'synthetic-fixed-base-not-authenticated', sdkVersion: '3.0.1',
  sdkCommit: 'f5f0737306901215860aa920a6ab570b699efba8',
  serialization: 'UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()))',
  byteLength: bytes.length, sha256,
};
const corpus = process.argv.indexOf('--corpus');
if (corpus > 0) {
  // Every trust-base document of a corpus must be byte-identical to the SDK's own emission.
  const fixtures = JSON.parse(readFileSync(new URL(`${process.argv[corpus + 1]}/config/fixtures.json`, `file://${process.cwd()}/`), 'utf8'));
  const names = Object.keys(fixtures.trustBases);
  assert.ok(names.length > 0, 'corpus has no trust-base documents');
  for (const name of names) {
    const raw = Buffer.from(fixtures.trustBases[name], 'hex');
    const emitted = Buffer.from(JSON.stringify(RootTrustBase.fromJSON(JSON.parse(raw.toString('utf8'))).toJSON()), 'utf8');
    assert.deepEqual(raw, emitted, `corpus trust base ${name} is not the SDK's emission`);
  }
  assert.deepEqual(Buffer.from(fixtures.trustBases.pinned, 'hex'), bytes, 'corpus pinned base is not the published fixture');
  console.log(`${names.length} corpus trust documents match the SDK 3.0.1 emission`);
} else if (process.argv.includes('--write')) {
  writeFileSync(document, bytes);
  writeFileSync(provenance, JSON.stringify(metadata, null, 2) + '\n');
} else {
  assert.deepEqual(readFileSync(document), bytes, 'SDK trust-document bytes changed');
  assert.deepEqual(JSON.parse(readFileSync(provenance, 'utf8')), metadata, 'SDK trust-document provenance changed');
}
console.log(`SDK 3.0.1 trust document: ${bytes.length} bytes, SHA256 ${sha256} (${fileURLToPath(document)})`);
