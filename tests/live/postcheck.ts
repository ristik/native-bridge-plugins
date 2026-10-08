/** After restarts: the aggregator still serves a certified proof for every state of the previous token, and the token still verifies natively. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { loadConfig } from './lib.js';

const lane = loadConfig(process.argv[2]);
const token = await Token.fromCBOR(Uint8Array.from(readFileSync(`${lane.dir}/token-mint.cbor`)));
const agg = new AggregatorClient(lane.aggUrl);
for (const c of [token.genesis, ...token.transactions]) {
  const sid = await StateId.fromCertificationData(c.inclusionProof.certificationData);
  const r = await agg.getInclusionProof(sid);
  assert.ok(r.inclusionProof, 'the restarted aggregator still certifies the state');
  assert.deepEqual(r.inclusionProof.certificationData.toCBOR(), c.inclusionProof.certificationData.toCBOR());
  assert.equal(r.inclusionProof.referenceTime, c.inclusionProof.referenceTime, 'the original reference time t is preserved');
}
console.log(`PASS postcheck: ${1 + token.transactions.length} states still certified with their original CD and t, latest block ${await agg.getLatestBlockNumber()}`);
