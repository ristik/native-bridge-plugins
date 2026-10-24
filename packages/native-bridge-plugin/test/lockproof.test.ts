import assert from 'node:assert/strict';
import { test } from 'node:test';

import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';

import type { NativeReason } from '../src/errors.js';
import { encodeJustification, parseJustification } from '../src/lockproof.js';
import { accountTrieKey, keccak256 } from '../src/profile.js';
import { decode } from '../src/rlp.js';
import { C } from './cbor.js';
import { rejects } from './util.js';
import {
  CHAIN_ID, EVM_PARTITION, VAULT, ZERO20, buildToken, encodeParts, headerRlp, lockParts, makeUc, makeWorld, pdrBytes, sha, signer, spec, type LockParts,
  nextEpoch, type MintSpec, type World,
} from './world.js';
import { NativeBridge } from '../src/verifier.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;

async function mutated(f: (w: World, p: LockParts, s: MintSpec) => Promise<void> | void, specMut?: (s: MintSpec) => void, world?: World): Promise<unknown> {
  const w = world ?? (await makeWorld());
  const s = spec(1);
  specMut?.(s);
  const parts = await lockParts(w, s);
  await f(w, parts, s);
  const out = await buildToken(w, s, [], T0, UC_TS, {}, parts);
  return w.bridge.verifyNativeToken(out.token, 'receipt');
}

const flip = (b: Uint8Array, i: number): Uint8Array => {
  const c = b.slice();
  c[Math.min(i, c.length - 1)] ^= 1;
  return c;
};

const resignUc = (w: World, p: LockParts, mod: Partial<LockParts['ucSpec']>): Promise<UnicityCertificate> => makeUc(w.evm, { ...p.ucSpec, ...mod });

test('baseline lock proof verifies', async () => {
  await mutated(() => undefined);
});

test('cfg and trustBaseId must match the installed deployment and trust base', async () => {
  await rejects(mutated((_, p) => void (p.cfg = flip(p.cfg, 0))), 'ErrLockProofCfg');
  await rejects(mutated((_, p) => void (p.trustBaseId = flip(p.trustBaseId, 0))), 'ErrLockProofTrust');
});

test('quorum: one short is rejected, three of four is enough, a stranger fails the seal (B1)', async () => {
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { signers: 2 }))), 'ErrQuorumNotMet');
  await mutated(async (w, p) => void (p.uc = await resignUc(w, p, { signers: 3 })));
  // B1: every signature must be a valid one of a committee member; an unknown signer fails the seal even beside a full quorum
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { extra: [['intruder', signer(200)]] }))), 'ErrQuorumNotMet');
  // Two genuine plus two known members signing with the wrong keys: no quorum.
  await rejects(
    mutated(async (w, p) => void (p.uc = await resignUc(w, p, { signers: 2, extra: [[w.evm.signers[2][0], signer(201)], [w.evm.signers[3][0], signer(202)]] }))),
    'ErrQuorumNotMet',
  );
});

test('certificate checks: false root, wrong network, an epoch not held yet, an epoch before the genesis', async () => {
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { sealHash: new Uint8Array(32).fill(1) }))), 'ErrSealRoot');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { network: 4 }))), 'ErrSealNetwork');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 9n }))), 'ErrNoEntryForEpoch');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 1n }))), 'ErrSealEpoch');
});

test('an epoch change: retryable until the history holds the new epoch, then verified under its own committee and interval', async () => {
  const w = await makeWorld();
  // the root committee changes at round 1000 (epoch 3, a new committee witnessed by epoch 2's)
  const next = await nextEpoch(w.evm, 1000n, 4, 30);
  const sealedIn3 = { ...w, evm: next };
  // the bridge still holds only epoch 2: the lock certificate of epoch 3 is retryable, never invalid
  await rejects(mutated(async (_, p) => void (p.uc = await resignUc(sealedIn3, p, { rootEpoch: 3n, round: 1500n })), undefined, w), 'ErrNoEntryForEpoch');
  // the wallet appended epoch 3: the same kind of certificate verifies
  const held: World = { ...sealedIn3, bridge: new NativeBridge(w.bridge.registry, next.trust) };
  await mutated(async (ww, p) => void (p.uc = await resignUc(ww, p, { rootEpoch: 3n, round: 1500n })), undefined, held);
  // ... under epoch 3's committee only, within its interval
  await rejects(mutated(async (ww, p) => void (p.uc = await resignUc(ww, p, { rootEpoch: 3n, round: 500n })), undefined, held), 'ErrSealEpoch');
  await rejects(mutated(async (ww, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 3n, round: 1500n })), undefined, held), 'ErrQuorumNotMet');
  // epoch 2 has ended at round 1000: an epoch-2 seal at round 1500 is outside its interval
  await rejects(mutated(async (ww, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 2n, round: 1500n })), undefined, held), 'ErrSealEpoch');
});

test('EVM partition, shard and configuration pins', async () => {
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { partition: EVM_PARTITION + 1 }))), 'ErrEvmPartition');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { shard: { bytes: Uint8Array.of(0x40), siblings: [new Uint8Array(32)] } }))), 'ErrEvmShard');
  await rejects(mutated((_, p) => void (p.pdr = flip(p.pdr, 3))), 'ErrEvmConfigHash');
  // A self-consistent certificate over a PDR changing a non-membership setting.
  await rejects(
    mutated(async (w, p) => {
      p.pdr = pdrBytes(5n, 1n);
      p.uc = await resignUc(w, p, { conf: sha(p.pdr) });
    }),
    'ErrEvmConfigPin',
  );
  // A later shard epoch committing to its own PDR keeps the pin.
  await mutated(async (w, p) => {
    p.pdr = pdrBytes(6n, 0n);
    p.uc = await resignUc(w, p, { conf: sha(p.pdr), epochIr: 6n });
  });
  // Certified shard epoch must be the PDR's epoch.
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { epochIr: 9n }))), 'ErrEvmConfigPin');
  // Non-canonical PDR (long-form integer head), committed by the certificate.
  await rejects(
    mutated(async (w, p) => {
      p.pdr = Uint8Array.of(p.pdr[0], 0x18, 0x01, ...p.pdr.slice(2));
      p.uc = await resignUc(w, p, { conf: sha(p.pdr) });
    }),
    'ErrEvmConfigPin',
  );
});

test('header bindings', async () => {
  await rejects(mutated((_, p) => void (p.header = flip(p.header, 40))), 'ErrHeaderHash');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { stateHash: new Uint8Array(32).fill(0x5a) }))), 'ErrHeaderRoot');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { blockHash: new Uint8Array(32).fill(0x5b) }))), 'ErrHeaderHash');
  // a changed state with no block hash is not a native input record: refused by the certificate check, before any header binding
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { blockHash: null }))), 'ErrCertStructure');
  // A well-formed 21-field header under a deployment pinned to 20 fields.
  await rejects(
    mutated(async (w, p) => {
      const root = decode(p.header);
      const stateRoot = (root as { items: { data: Uint8Array }[] }).items[3].data;
      p.header = headerRlp(stateRoot, 1234n, 21);
      p.uc = await resignUc(w, p, { blockHash: keccak256(p.header) });
    }),
    'ErrHeaderProfile',
  );
});

test('account and storage proofs: mutated, extra, missing, empty nodes', async () => {
  await rejects(mutated((_, p) => void (p.accountNodes[0] = flip(p.accountNodes[0], 10))), 'ErrAccountProof');
  await rejects(mutated((_, p) => void p.accountNodes.push(p.accountNodes[0])), 'ErrAccountProof');
  await rejects(mutated((_, p) => void p.accountNodes.pop()), 'ErrAccountProof');
  await rejects(mutated((_, p) => void (p.accountNodes = [])), 'ErrLockProofShape');
  await rejects(mutated(() => undefined, (s) => void (s.evm.vaultCodeHash = new Uint8Array(32).fill(0x77))), 'ErrAccountCode');
  await rejects(mutated((_, p) => void (p.storageNodes[0] = flip(p.storageNodes[0], 12))), 'ErrStorageProof');
  await rejects(mutated((_, p) => void p.storageNodes.push(p.storageNodes[0])), 'ErrStorageProof');
  await rejects(mutated(() => undefined, (s) => void (s.evm.nonce = 99n)), 'ErrStorageProof');
  await rejects(mutated(() => undefined, (s) => void (s.evm.stored = new Uint8Array(32).fill(0x42))), 'ErrLockDigest');
  await rejects(mutated(() => undefined, (s) => void (s.evm.stored = new Uint8Array(32))), 'ErrStorageValue');
});

test('a digest with leading zero bytes round trips through the stored word', async () => {
  const w = await makeWorld();
  const { digestOf } = await import('./world.js');
  for (let n = 1n; n < 3000n; n++) {
    const s = spec(1);
    s.nonce = n;
    s.evm.nonce = n;
    if (digestOf(w, s).digest[0] === 0) {
      await w.bridge.verifyNativeToken((await buildToken(w, s, [], T0, UC_TS)).token, 'receipt');
      return;
    }
  }
  assert.fail('no leading-zero digest found');
});

test('certificates outside the SDK-decodable subset are unsupported', async () => {
  await rejects(mutated((_, p) => void (p.ucRaw = Uint8Array.of(0xd9, 0x03, 0xe9, 0x80))), 'ErrUnsupportedCertificateEncoding');
  await rejects(mutated((_, p) => void (p.ucRaw = Uint8Array.of(...p.uc.toCBOR(), 0))), 'ErrUnsupportedCertificateEncoding');
});

// ---- bounds ------------------------------------------------------------------------------------

async function parse(f: (p: LockParts) => void): Promise<void> {
  const w = await makeWorld();
  const p = await lockParts(w, spec(1));
  f(p);
  parseJustification(encodeJustification(CHAIN_ID, VAULT, ZERO20, 1n, encodeParts(p)));
}

const parseRejects = (f: (p: LockParts) => void, reason: NativeReason = 'ErrLockProofTooLarge'): Promise<void> => rejects(parse(f), reason);

test('node count, node size and combined bytes boundaries', async () => {
  const node = (n: number): Uint8Array => new Uint8Array(n).fill(1);
  await parse((p) => void (p.accountNodes = Array(65).fill(Uint8Array.of(0xc0))));
  await parseRejects((p) => void (p.accountNodes = Array(66).fill(Uint8Array.of(0xc0))));
  await parse((p) => void (p.storageNodes = Array(65).fill(Uint8Array.of(0xc0))));
  await parseRejects((p) => void (p.storageNodes = Array(66).fill(Uint8Array.of(0xc0))));
  await parse((p) => void (p.accountNodes = [node(1024)]));
  await parseRejects((p) => void (p.accountNodes = [node(1025)]));
  await parseRejects((p) => void (p.storageNodes = [new Uint8Array()]), 'ErrLockProofShape');
  await parse((p) => {
    p.accountNodes = Array(12).fill(node(1024));
    p.storageNodes = Array(12).fill(node(1024));
  });
  await parseRejects((p) => {
    p.accountNodes = Array(12).fill(node(1024));
    p.storageNodes = [...Array(12).fill(node(1024)), node(1)];
  });
});

test('certificate, header and PDR boundaries', async () => {
  await parse((p) => void (p.ucRaw = new Uint8Array(16384).fill(1)));
  await parseRejects((p) => void (p.ucRaw = new Uint8Array(16385).fill(1)));
  await parse((p) => void (p.header = new Uint8Array(2048).fill(1)));
  await parseRejects((p) => void (p.header = new Uint8Array(2049).fill(1)));
  await parse((p) => void (p.pdr = new Uint8Array(16384).fill(1)));
  await parseRejects((p) => void (p.pdr = new Uint8Array(16385).fill(1)));
  await parseRejects((p) => void (p.header = new Uint8Array()), 'ErrLockProofShape');
});

test('over-bound evidence never triggers online fallback; justification is bounded first', async () => {
  const w = await makeWorld();
  const s = spec(1);
  const p = await lockParts(w, s);
  p.accountNodes = Array(66).fill(Uint8Array.of(0xc0));
  await rejects(w.bridge.verifyNativeToken((await buildToken(w, s, [], T0, UC_TS, {}, p)).token, 'receipt'), 'ErrProofTooLarge');
  assert.throws(() => parseJustification(new Uint8Array(64 * 1024 + 1)), /ErrJustificationTooLarge/);
});

// The cfg and trustBaseId slots are the proof's own shape (bft-core decodeLockProof): a 31-byte value is ErrLockProofShape, not the
// scanner's generic error.
test('proof cfg and trustBaseId of the wrong width are the proof\'s shape', async () => {
  await parseRejects((p) => void (p.cfg = new Uint8Array(31).fill(7)), 'ErrLockProofShape');
  await parseRejects((p) => void (p.trustBaseId = new Uint8Array(31).fill(7)), 'ErrLockProofShape');
});

test('proof arity and version are exact', async () => {
  const w = await makeWorld();
  const p = await lockParts(w, spec(1));
  const good = encodeParts(p);
  const k = C.encodeArray(...[1, 2, 3, 4, 5, 6, 7].map((n) => C.encodeUnsignedInteger(n)));
  assert.throws(() => parseJustification(encodeJustification(CHAIN_ID, VAULT, ZERO20, 1n, k)), /ErrLockProofShape/);
  const v2 = good.slice();
  v2[1] = 0x02;
  assert.throws(() => parseJustification(encodeJustification(CHAIN_ID, VAULT, ZERO20, 1n, v2)), /ErrLockProofShape/);
  void accountTrieKey;
});

test('a weighted committee after a rotation: the heavy member alone certifies the lock, the two light members do not', async () => {
  const w = await makeWorld();
  // epoch 3 from round 1000, weights 98, 1, 1 in member order: W = 100, threshold 67
  const next = await nextEpoch(w.evm, 1000n, 3, 50, [98, 1, 1]);
  const held: World = { ...w, evm: next, bridge: new NativeBridge(w.bridge.registry, next.trust) };
  await mutated(async (ww, p) => void (p.uc = await resignUc(ww, p, { rootEpoch: 3n, round: 1500n, signers: 1 })), undefined, held);
  await rejects(
    mutated(async (ww, p) => void (p.uc = await resignUc(ww, p, { rootEpoch: 3n, round: 1500n, signers: 0, extra: next.signers.slice(1) })), undefined, held),
    'ErrQuorumNotMet',
  );
});

test('a historical committee: a lock sealed in epoch 2 still verifies after the history holds epoch 3, inside epoch 2\'s closed interval', async () => {
  const w = await makeWorld();
  const next = await nextEpoch(w.evm, 1000n, 4, 30);
  const held: World = { ...w, evm: next, bridge: new NativeBridge(w.bridge.registry, next.trust) };
  // epoch 2's committee sealed round 500, before epoch 3 started: verified under epoch 2's own committee, at any later time
  await mutated(async (_, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 2n, round: 500n })), undefined, held);
  // the last round of epoch 2 is 999; round 1000 is epoch 3's
  await mutated(async (_, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 2n, round: 999n })), undefined, held);
  await rejects(mutated(async (_, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 2n, round: 1000n })), undefined, held), 'ErrSealEpoch');
});

test('several faults get the oracle verdict: the seal epoch first, then the configuration, then the certificate', async () => {
  const w = await makeWorld();
  const next = await nextEpoch(w.evm, 1000n, 4, 30);
  // an epoch the history does not hold and a false root: retryable, never the root failure
  await rejects(
    mutated(async (_, p) => void (p.uc = await resignUc({ ...w, evm: next }, p, { rootEpoch: 3n, round: 1500n, sealHash: new Uint8Array(32).fill(1) })), undefined, w),
    'ErrNoEntryForEpoch',
  );
  // an epoch the history does not hold and a configuration that is not the certificate's: the epoch decides (the lock path's own selection)
  await rejects(
    mutated(async (_, p) => {
      p.uc = await resignUc({ ...w, evm: next }, p, { rootEpoch: 3n, round: 1500n });
      p.pdr = flip(p.pdr, 3);
    }, undefined, w),
    'ErrNoEntryForEpoch',
  );
  // a configuration that is not the certificate's and a short quorum: the configuration first
  await rejects(
    mutated(async (ww, p) => {
      p.uc = await resignUc(ww, p, { signers: 2 });
      p.pdr = flip(p.pdr, 3);
    }),
    'ErrEvmConfigHash',
  );
});
