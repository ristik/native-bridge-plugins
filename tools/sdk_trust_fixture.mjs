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
const source = {
  version: '1', networkId: 1, epoch: '7', epochStartRound: '100',
  rootNodes: [{ nodeId: 'fixture-a', sigKey: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', stake: '1' }],
  quorumThreshold: '1', stateHash: '11'.repeat(32), changeRecordHash: null,
  previousEntryHash: null, signatures: {},
};
const bytes = Buffer.from(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()), 'utf8');
const sha256 = createHash('sha256').update(bytes).digest('hex');
const metadata = {
  fixture: 'synthetic-fixed-base-not-authenticated', sdkVersion: '3.0.1',
  sdkCommit: 'f5f0737306901215860aa920a6ab570b699efba8',
  serialization: 'UTF8(JSON.stringify(RootTrustBase.fromJSON(source).toJSON()))',
  byteLength: bytes.length, sha256,
};
if (process.argv.includes('--write')) {
  writeFileSync(document, bytes);
  writeFileSync(provenance, JSON.stringify(metadata, null, 2) + '\n');
} else {
  assert.deepEqual(readFileSync(document), bytes, 'SDK trust-document bytes changed');
  assert.deepEqual(JSON.parse(readFileSync(provenance, 'utf8')), metadata, 'SDK trust-document provenance changed');
}
console.log(`SDK 3.0.1 trust document: ${bytes.length} bytes, SHA256 ${sha256} (${fileURLToPath(document)})`);
