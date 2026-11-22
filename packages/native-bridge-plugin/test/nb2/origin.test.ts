import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { toHex } from '../../src/bytes.js';
import { NativeBridgeV2, refreshNb2Origin, type Nb2OriginCheckpoint } from '../../src/nb2/index.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { evmAccount, key, makeRoot, makeConfig, roundAtLeast, roundNow, setup } from './world.js';

const blockHash = (hex: string) => '0x' + hex.repeat(64);

test('checkpoint refresh rejects rollback, wrong binding and malformed or conflicting fields', async () => {
  const root = await makeRoot();
  const cfg = makeConfig(root);
  const held: Nb2OriginCheckpoint = { blockHash: blockHash('1'), blockNumber: 12, usableEpoch: 2n, rootRound: 500n };
  const trust = root.trust.withAuthenticatedOrigin(held);
  const binding = { network: cfg.network, generation: 'public-a', genesisHash: '0x' + toHex(cfg.executionGenesis), releaseSha256: 'a'.repeat(64) };
  const candidate = { schema: 'unicity-nb2-origin', version: 1, ...binding,
    blockHash: blockHash('2'), blockNumber: 13, usableEpoch: '2', rootRound: '550' };
  const apply = (changes: Record<string, unknown>) => refreshNb2Origin(trust, binding, held, { ...candidate, ...changes });
  assert.deepEqual(apply({}).checkpoint, { blockHash: blockHash('2'), blockNumber: 13, usableEpoch: 2n, rootRound: 550n });
  assert.deepEqual(apply({ blockHash: held.blockHash, blockNumber: held.blockNumber, rootRound: '500' }).checkpoint, held);
  for (const changed of [
    { blockNumber: 11 }, { usableEpoch: '1' }, { rootRound: '499' },
  ]) assert.throws(() => apply(changed), /rolls back/);
  for (const changed of [
    { network: 320 }, { generation: 'public-b' }, { genesisHash: blockHash('f') }, { releaseSha256: 'b'.repeat(64) },
  ]) assert.throws(() => apply(changed), /different release or network/);
  for (const changed of [
    { blockHash: blockHash('0') }, { blockHash: blockHash('g') }, { blockNumber: 12.5 },
    { usableEpoch: 2 }, { rootRound: '0550' }, { rootRound: '18446744073709551616' },
  ]) assert.throws(() => apply(changed), /invalid/);
  for (const changed of [
    { blockNumber: held.blockNumber }, { blockHash: held.blockHash },
    { blockNumber: held.blockNumber, blockHash: held.blockHash, usableEpoch: '3' },
  ]) assert.throws(() => apply(changed), /conflicts/);
  const ahead = trust.withAuthenticatedOrigin({ usableEpoch: 2n, rootRound: 600n });
  assert.throws(() => refreshNb2Origin(ahead, binding, held, candidate), /rolls back/);
});

test('the existing refresh hook verifies a deposit hundreds of rounds beyond an unchanged release', async () => {
  const w = await setup();
  let held: Nb2OriginCheckpoint = { blockHash: blockHash('1'), blockNumber: 120, usableEpoch: 1n, rootRound: roundNow() };
  let trust = w.root.trust.withAuthenticatedOrigin(held);
  const original = JSON.stringify({ trust: { origin: { ...held, usableEpoch: String(held.usableEpoch), rootRound: String(held.rootRound) } } });
  const releaseSha256 = createHash('sha256').update(original).digest('hex');
  const binding = { network: w.cfg.network, generation: 'public-a', genesisHash: '0x' + toHex(w.cfg.executionGenesis), releaseSha256 };
  const reply = { schema: 'unicity-nb2-origin', version: 1, ...binding, blockHash: blockHash('2'), blockNumber: 121,
    usableEpoch: '1', rootRound: String(held.rootRound + 200n) };
  roundAtLeast(held.rootRound + 500n);
  const owner = localOwner(key('checkpoint owner'));
  const payer = evmAccount(w.chain, 'checkpoint payer');
  let refreshes = 0;
  const bridge = await NativeBridgeV2.open({
    ...w.options('checkpoint'), trust, refreshTrust: async () => {
      refreshes++;
      ({ trust, checkpoint: held } = refreshNb2Origin(trust, binding, held, reply));
      return trust;
    },
  });
  const plan = await bridge.planDeposit(40n, owner.publicKey);
  await bridge.submitDeposit(plan, payer);
  await assert.rejects(bridge.collectDepositProof(plan.intent), /seal exceeds the authenticated B1 origin/);
  assert.equal(refreshes, 1, 'a monotonic checkpoint can still be behind the deposit seal');

  reply.blockHash = blockHash('3');
  reply.blockNumber = 122;
  reply.rootRound = String(roundNow());
  const proof = await bridge.collectDepositProof(plan.intent);
  assert.ok(proof.reason.length);
  assert.equal(refreshes, 2);
  assert.equal(held.rootRound, roundNow());
  assert.equal(createHash('sha256').update(original).digest('hex'), releaseSha256);
});
