import assert from 'node:assert/strict';
import { test } from 'node:test';

import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';

import { encodeJustification, parseJustification } from '../src/lockproof.js';
import { accountTrieKey, keccak256 } from '../src/profile.js';
import { decode } from '../src/rlp.js';
import { C } from './cbor.js';
import { rejects } from './util.js';
import {
  CHAIN_ID, VAULT, ZERO20, buildToken, encodeParts, headerRlp, lockParts, makeUc, makeWorld, pdrBytes, sha, signer, spec, type LockParts,
  type MintSpec, type World,
} from './world.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;

async function mutated(f: (w: World, p: LockParts, s: MintSpec) => Promise<void> | void, specMut?: (s: MintSpec) => void, w = makeWorld()): Promise<unknown> {
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

test('quorum: one short is rejected, three of four is enough, strangers add nothing', async () => {
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { signers: 2 }))), 'ErrQuorumNotMet');
  await mutated(async (w, p) => void (p.uc = await resignUc(w, p, { signers: 3 })));
  await mutated(async (w, p) => void (p.uc = await resignUc(w, p, { extra: [['intruder', signer(200)]] })));
  // Two genuine plus two known members signing with the wrong keys: no quorum.
  await rejects(
    mutated(async (w, p) => void (p.uc = await resignUc(w, p, { signers: 2, extra: [[w.evm.signers[2][0], signer(201)], [w.evm.signers[3][0], signer(202)]] }))),
    'ErrQuorumNotMet',
  );
});

test('certificate guards: false root, wrong network, wrong epoch, round before start', async () => {
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { sealHash: new Uint8Array(32).fill(1) }))), 'ErrSealRoot');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { network: 4 }))), 'ErrSealNetwork');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { rootEpoch: 9n }))), 'ErrEpochMismatch');
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { round: 0n }))), 'ErrRoundBeforeEpochStart');
});

test('EVM partition, shard and configuration pins', async () => {
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { partition: 8 }))), 'ErrEvmPartition');
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
  await rejects(mutated(async (w, p) => void (p.uc = await resignUc(w, p, { blockHash: null }))), 'ErrHeaderHash');
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
  await rejects(mutated((_, p) => void (p.accountNodes = [])), 'ErrAccountProof');
  await rejects(mutated(() => undefined, (s) => void (s.evm.vaultCodeHash = new Uint8Array(32).fill(0x77))), 'ErrAccountCode');
  await rejects(mutated((_, p) => void (p.storageNodes[0] = flip(p.storageNodes[0], 12))), 'ErrStorageProof');
  await rejects(mutated((_, p) => void p.storageNodes.push(p.storageNodes[0])), 'ErrStorageProof');
  await rejects(mutated(() => undefined, (s) => void (s.evm.nonce = 99n)), 'ErrStorageProof');
  await rejects(mutated(() => undefined, (s) => void (s.evm.stored = new Uint8Array(32).fill(0x42))), 'ErrLockDigest');
  await rejects(mutated(() => undefined, (s) => void (s.evm.stored = new Uint8Array(32))), 'ErrStorageValue');
});

test('a digest with leading zero bytes round trips through the stored word', async () => {
  const w = makeWorld();
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
  const w = makeWorld();
  const p = await lockParts(w, spec(1));
  f(p);
  parseJustification(encodeJustification(CHAIN_ID, VAULT, ZERO20, 1n, encodeParts(p)));
}

const parseRejects = (f: (p: LockParts) => void): Promise<void> => rejects(parse(f), 'ErrProofTooLarge');

test('node count, node size and combined bytes boundaries', async () => {
  const node = (n: number): Uint8Array => new Uint8Array(n).fill(1);
  await parse((p) => void (p.accountNodes = Array(65).fill(Uint8Array.of(0xc0))));
  await parseRejects((p) => void (p.accountNodes = Array(66).fill(Uint8Array.of(0xc0))));
  await parse((p) => void (p.storageNodes = Array(65).fill(Uint8Array.of(0xc0))));
  await parseRejects((p) => void (p.storageNodes = Array(66).fill(Uint8Array.of(0xc0))));
  await parse((p) => void (p.accountNodes = [node(1024)]));
  await parseRejects((p) => void (p.accountNodes = [node(1025)]));
  await parseRejects((p) => void (p.storageNodes = [new Uint8Array()]));
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
  await parseRejects((p) => void (p.header = new Uint8Array()));
});

test('over-bound evidence never triggers online fallback; justification is bounded first', async () => {
  const w = makeWorld();
  const s = spec(1);
  const p = await lockParts(w, s);
  p.accountNodes = Array(66).fill(Uint8Array.of(0xc0));
  await rejects(w.bridge.verifyNativeToken((await buildToken(w, s, [], T0, UC_TS, {}, p)).token, 'receipt'), 'ErrProofTooLarge');
  assert.throws(() => parseJustification(new Uint8Array(64 * 1024 + 1)), /ErrInputTooLarge/);
});

test('proof arity and version are exact', async () => {
  const w = makeWorld();
  const p = await lockParts(w, spec(1));
  const good = encodeParts(p);
  const k = C.encodeArray(...[1, 2, 3, 4, 5, 6, 7].map((n) => C.encodeUnsignedInteger(n)));
  assert.throws(() => parseJustification(encodeJustification(CHAIN_ID, VAULT, ZERO20, 1n, k)), /ErrShape/);
  const v2 = good.slice();
  v2[1] = 0x02;
  assert.throws(() => parseJustification(encodeJustification(CHAIN_ID, VAULT, ZERO20, 1n, v2)), /ErrVersion/);
  void accountTrieKey;
});

test('DEFERRED: rotation, weighted and historical-committee scenarios are unsupported', { skip: 'common SDK trust-base work (bft-core#421)' }, () => undefined);
