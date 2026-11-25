import assert from 'node:assert/strict';
import { test } from 'node:test';
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicitySeal } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicitySeal.js';
import { fromHex, toHex } from '../../src/bytes.js';
import { IMPORTED_TIP_PROFILE_HASH, NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { decodeReceiptBacking } from '../../src/nb2/deposit.js';
import type { JsonRpc } from '../../src/nb2/rpc.js';
import { localOwner } from '../../src/nb2/tokenops.js';
import { decodeUc, verifyEvmUc } from '../../src/nb2/trust.js';
import { successor, withSeal } from './certification-fixtures.js';
import { evmAccount, key, roundAtLeast, roundNow, setup, type Root } from './world.js';

async function reseal(raw: Uint8Array, root: Root, round: bigint, epoch: bigint): Promise<Uint8Array> {
  const uc = decodeUc(raw);
  const old = uc.unicitySeal;
  const seal = await UnicitySeal.create(old.networkId, round, epoch, old.timestamp, old.previousHash, old.hash, new Map(root.signers));
  return new UnicityCertificate(uc.inputRecord, uc.technicalRecordHash, uc.shardConfigurationHash, uc.shardTreeCertificate,
    uc.unicityTreeCertificate, seal).toCBOR();
}

test('D4 Mint uses the ancestor child’s in-term witness and waits for the frozen parent’s successor child', async () => {
  const w = await setup(fromHex(IMPORTED_TIP_PROFILE_HASH)!);
  const opts = w.options('D4 mint');
  const owner = localOwner(key('D4 owner'));
  const payer = evmAccount(w.chain, 'D4 payer');
  let substituted: Uint8Array | undefined;
  let omitRootInput = false;
  let next: Awaited<ReturnType<typeof successor>> | undefined;
  let serveSuccessor = false;
  const rpc: JsonRpc = { async call<T>(method: string, params: unknown[]): Promise<T> {
    const result = await w.chain.call<T>(method, params);
    if (method === 'unicity_getSealCompanionV1' && (substituted || omitRootInput)) {
      const c = (result as { companion: { rootInput?: string; witnesses: string[] } }).companion;
      if (substituted) c.witnesses[0] = '0x' + toHex(substituted);
      if (omitRootInput) delete c.rootInput;
    }
    return result;
  } };
  const bridge = await NativeBridgeV2.open({ ...opts, rpc, requireImportedTipProfile: true,
    refreshTrust: async () => serveSuccessor ? next?.trust : undefined,
    aggregator: { async certify(request) {
      const proof = await w.agg.certify(request);
      return serveSuccessor ? withSeal(proof, next!, undefined, next!.signers.length, 2n) : proof;
    } },
  });
  const deposit = async () => {
    const { intent } = await bridge.planDeposit(8n, owner.publicKey);
    const receipt = await bridge.submitDeposit(intent, payer);
    return { intent, original: w.chain.blocks[Number(receipt.blockNumber)].uc! };
  };

  const ancestor = await deposit();
  const frozen = await deposit();
  // No child can be certified between Prepare and the successor acknowledgement.
  w.chain.blocks.pop();
  const start = roundNow() + 50n;
  next = await successor(w.root, start);

  substituted = await reseal(ancestor.original, w.root, start + 10n, 1n);
  // The suffix is a valid quorum over the same IR while the wallet still has an open predecessor tip.
  await verifyEvmUc(w.root.trust, substituted, w.cfg);
  await assert.rejects(bridge.collectDepositProof(ancestor.intent), { reason: 'CompanionProvider' });
  assert.equal((await bridge.journal.deposit(ancestor.intent))?.reason, undefined);
  substituted = undefined;
  omitRootInput = true;
  await assert.rejects(bridge.collectDepositProof(ancestor.intent), { reason: 'CompanionUnknown' });
  omitRootInput = false;
  const ancestorProof = await bridge.collectDepositProof(ancestor.intent);
  assert.deepEqual(decodeReceiptBacking(ancestorProof.reason).proof.uc, ancestor.original);
  const ancestorToken = await bridge.mint(ancestor.intent);

  await assert.rejects(bridge.collectDepositProof(frozen.intent), { reason: 'CompanionUnknown' });
  assert.equal((await bridge.journal.deposit(frozen.intent))?.reason, undefined);
  roundAtLeast(start);
  const recertification = await reseal(frozen.original, next, start, 2n);
  await w.chain.mine([], recertification);
  substituted = await reseal(frozen.original, w.root, start + 10n, 1n);
  await assert.rejects(bridge.collectDepositProof(frozen.intent), { reason: 'CompanionProvider' });
  substituted = undefined;
  await assert.rejects(bridge.collectDepositProof(frozen.intent), { rule: 'NoEntryForEpoch' });
  assert.equal((await bridge.journal.deposit(frozen.intent))?.reason, undefined);
  serveSuccessor = true;
  const frozenProof = await bridge.collectDepositProof(frozen.intent);
  assert.deepEqual(decodeReceiptBacking(frozenProof.reason).proof.uc, recertification);
  const frozenToken = await bridge.mint(frozen.intent);
  const reopened = await NativeBridgeV2.open({ ...opts, trust: next.trust });
  assert.equal((await reopened.verifyToken(ancestorToken)).amount, 8n);
  assert.equal((await reopened.verifyToken(frozenToken)).amount, 8n);
});
