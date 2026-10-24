/**
 * The corpus ops the oracle alone used to replay (bft-core #438 "independent JS/Rust conformance"): config (cfg-decode, identifiers, value-data,
 * trust-input), history prepareLock, lock (lock-backing, mpt), unlock and wire token-project. Each op is the oracle's definition (bft-core
 * `bridgeprofile.Replay`), run on the plug-in's own code; every case of the op is replayed and counted. The `kernel` op (the 0x0104 ABI output) has
 * no plug-in counterpart: the plug-ins never call the kernel, whose relation the kernel mirror in `corpus.test.ts` replays.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';

import { fromHex, toHex } from '../src/bytes.js';
import { makeDeployment } from '../src/deployment.js';
import { NativeError } from '../src/errors.js';
import { checkMintData, decodeHistory, predBytes, prepareLock, projectToken } from '../src/history.js';
import { configHashOfPdr, parseJustificationFor, verifyLockProof } from '../src/lockproof.js';
import { verifyProof } from '../src/mpt.js';
import {
  H, cfgBytes, cfgHash, decodeCfg, decodePolicy, deriveAsset, deriveSalt, deriveTokenId, deriveType, identityDomain, lockDigest, lockRecord, valueEnvelope,
} from '../src/profile.js';
import { validateCfg } from '../src/deployment.js';
import { TrustInput } from '../src/trust.js';
import { preflightToken } from '../src/resources.js';
import { parseKey, verifyUnlock } from '../src/unlock.js';

const VECTORS = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'protocol', 'vectors');
const load = (rel: string): any => JSON.parse(readFileSync(path.join(VECTORS, rel), 'utf8'));
const fixtures = load('config/fixtures.json');

interface Case {
  id: string;
  op: string;
  cfg?: string;
  input: string;
  aux?: Record<string, string>;
  expected: { status: 'ok' | 'error'; family?: string; reason?: string; values?: Record<string, string>; result?: Record<string, unknown> };
}
type Got = { status: 'ok'; values?: Record<string, string>; result?: Record<string, unknown> } | { status: 'error'; family: string; reason: string };

const casesOf = (family: string, op: string): Case[] => (load(`${family}/cases.json`).cases as Case[]).filter((c) => c.op === op);
const hex = (b: Uint8Array): string => toHex(b);
const bytes = (h: string): Uint8Array => fromHex(h)!;
/** A decimal amount as the minimal big-endian bytes the profile encodes (no leading zero byte). */
const amountOf = (dec: string): Uint8Array => {
  let v = BigInt(dec);
  const out: number[] = [];
  while (v > 0n) {
    out.unshift(Number(v & 0xffn));
    v >>= 8n;
  }
  return Uint8Array.from(out);
};

/**
 * Where the plug-ins name a refusal differently from the oracle, per op: the oracle's reason and the plug-in reasons it may appear as. The verdict
 * never differs (a refusal stays a refusal); only these names do, and only as listed. lock-backing: the plug-in's lock-proof names (one-to-one, finer
 * for the PDR and the header); mpt and token-project: the plug-in's coarser names (one MPT failure, one unsupported-certificate refusal).
 */
type Aliases = Record<string, string[]>;
const LOCK_BACKING_NAMES: Aliases = {
  ErrCertScan: ['ErrUnsupportedCertificateEncoding', 'ErrProofTooLarge'],
  ErrLockAccount: ['ErrAccountProof'],
  ErrLockCodeHash: ['ErrAccountCode'],
  ErrLockHeader: ['ErrHeaderHash', 'ErrHeaderRoot'],
  ErrLockPDR: ['ErrEvmConfigHash', 'ErrEvmConfigPin'],
  ErrLockStorage: ['ErrStorageProof'],
  ErrLockUC: ['ErrQuorumNotMet', 'ErrSealRoot'],
  ErrTrustBaseDigest: ['ErrLockProofTrust'],
};
const MPT_NAMES: Aliases = Object.fromEntries(['ErrMPTAbsent', 'ErrMPTExtraneous', 'ErrMPTNode', 'ErrMPTPath'].map((r) => [r, ['ErrMptMalformed']]));
const TOKEN_NAMES: Aliases = {
  ...Object.fromEntries(['ErrCertSigLength', 'ErrInputTooLarge', 'ErrLength', 'ErrShape', 'ErrTag', 'ErrVersion'].map((r) => [r, ['ErrUnsupportedCertificateEncoding']])),
  ErrCertScan: ['ErrUnsupportedCertificateEncoding', 'ErrNonCanonical'],
};

/**
 * Replay every case of an op: a success must be a success with the corpus's values or result (when it gives them); an error must be an error with the
 * corpus's family and reason, or a listed alias of that reason. `skip` names the cases with no plug-in counterpart, each with why.
 */
async function replayAll(family: string, op: string, count: number, run: (c: Case) => Promise<Got> | Got, aliases: Aliases = {}, skip: Record<string, string> = {}): Promise<void> {
  const cases = casesOf(family, op);
  assert.equal(cases.length, count, `${family}/${op}: the corpus case count`);
  const mismatches: string[] = [];
  for (const id of Object.keys(skip)) assert.ok(cases.some((c) => c.id === id), `${id}: a skipped case exists`);
  for (const c of cases.filter((x) => !(x.id in skip))) {
    let got: Got;
    try {
      got = await run(c);
    } catch (e) {
      got = e instanceof NativeError ? { status: 'error', family: e.family, reason: e.reason } : { status: 'error', family: 'thrown', reason: String(e).slice(0, 80) };
    }
    const want = c.expected.status === 'ok'
      ? { status: 'ok', ...(c.expected.values ? { values: c.expected.values } : {}), ...(c.expected.result ? { result: c.expected.result } : {}) }
      : { status: 'error', family: c.expected.family, reason: c.expected.reason };
    const have = got.status === 'ok' ? { status: 'ok', ...(c.expected.values ? { values: got.values } : {}), ...(c.expected.result ? { result: got.result } : {}) } : got;
    const aliased = want.status === 'error' && have.status === 'error' && (aliases[want.reason as string] ?? []).includes((have as { reason: string }).reason);
    try {
      if (!aliased) assert.deepEqual(have, want);
    } catch {
      mismatches.push(`${c.id}: oracle ${JSON.stringify(want).slice(0, 120)} plug-in ${JSON.stringify(have).slice(0, 120)}`);
    }
  }
  assert.deepEqual(mismatches, [], `${family}/${op}: ${mismatches.length} of ${cases.length} cases differ from the oracle`);
}

test('config/cfg-decode: decoded, canonical, hashed, and whether its identities are derived', async () => {
  await replayAll('config', 'cfg-decode', 12, (c) => {
    const input = bytes(c.input);
    const cfg = decodeCfg(input);
    if (hex(cfgBytes(cfg)) !== hex(input)) throw new NativeError('ErrNonCanonical');
    let derived = 'true';
    try {
      validateCfg(cfg);
    } catch {
      derived = 'false';
    }
    return { status: 'ok', values: { cfgHash: hex(cfgHash(cfg)), ty: hex(cfg.ty), aid: hex(cfg.aid), identitiesDerived: derived } };
  });
});

test('config/identifiers: the identity domain D, the token type and the asset of (network, root genesis, execution genesis, chain)', async () => {
  await replayAll('config', 'identifiers', 7, (c) => {
    const [nw, rg, eg, ch] = c.input.split(':');
    const n = Number(nw);
    const args = [n, bytes(rg), bytes(eg), BigInt(ch)] as const;
    return { status: 'ok', values: { D: identityDomain(...args), ty: hex(deriveType(...args)), aid: hex(deriveAsset(...args)) } };
  });
});

test('config/value-data: the value envelope of (asset, amount)', async () => {
  await replayAll('config', 'value-data', 4, (c) => {
    const [aid, amount] = c.input.split(':');
    return { status: 'ok', values: { data: hex(valueEnvelope(bytes(aid), amountOf(amount))) } };
  });
});

test('config/trust-input: a release bundle installed under a pin', async () => {
  await replayAll('config', 'trust-input', 5, async (c) => {
    await TrustInput.fromBundle(bytes(c.input), bytes(c.aux!.pin));
    return { status: 'ok' };
  });
});

const devDeployment = (vaultCodeHash: Uint8Array, evmConfigHash: Uint8Array) =>
  makeDeployment(decodeCfg(bytes(fixtures.fixtures.dev.cfg)), vaultCodeHash, evmConfigHash, { fields: 20 }, decodePolicy(bytes(fixtures.fixtures.dev.policyBody)));

test('history/prepareLock: the lock request\'s outcome for (cfg, nonce, amount, first predicate)', async () => {
  const dep = devDeployment(bytes(fixtures.pins.dev.vaultCodeHash), new Uint8Array(32));
  await replayAll('history', 'prepareLock', 5, (c) => {
    assert.equal(c.cfg, 'dev', c.id);
    const o = prepareLock(dep, BigInt(c.aux!.n), amountOf(c.aux!.amount), bytes(c.input));
    return {
      status: 'ok',
      result: {
        cfg: hex(o.cfg), nonce: String(o.nonce), amount: hex(o.amount), tokenId: hex(o.tokenId), salt: hex(o.salt), firstPredicateHash: hex(o.firstPredicateHash),
        lockDigest: hex(o.lockDigest), releaseTo: hex(o.releaseTo), nullifier: hex(o.nullifier), leaves: o.leaves,
      },
    };
  });
});

test('lock/lock-backing: the mint\'s lock justification verified offline against a trust base and a deployment pin', async () => {
  const cfg = decodeCfg(bytes(fixtures.fixtures.dev.cfg));
  const ch = cfgHash(cfg);
  await replayAll('lock', 'lock-backing', 66, async (c) => {
    assert.equal(c.cfg, 'dev', c.id);
    const h = decodeHistory(bytes(c.input));
    const tb = fixtures.trustBases[c.aux!.trustBase];
    if (!tb) throw new NativeError('ErrTrustBaseDigest');
    const trust = await TrustInput.fromBundle(bytes(tb.bundle), bytes(tb.pin));
    const pin = fixtures.pins[c.aux!.pin];
    const dep = devDeployment(bytes(pin.vaultCodeHash), configHashOfPdr(bytes(pin.genesisPDR)));
    const j = parseJustificationFor(cfg, ch, h.mint.justification as Uint8Array);
    const amount = checkMintData(dep, h.mint.data);
    const salt = deriveSalt(ch, j.nonce);
    if (hex(h.mint.salt) !== hex(salt)) throw new NativeError('ErrMintSalt');
    const id = deriveTokenId(salt, cfg.network);
    const digest = lockDigest(ch, j.nonce, lockRecord(cfg.zeroAddress, cfg.ty, cfg.aid, amount, id, H(predBytes(h.mint.recipient))));
    await verifyLockProof(dep, trust, j, digest);
    return { status: 'ok' };
  }, LOCK_BACKING_NAMES, { 'backing-no-pin': 'a plug-in deployment always carries its pin (makeDeployment requires the vault code hash and EVM configuration)' });
});

test('lock/mpt: the account and storage proof verifier', async () => {
  await replayAll('lock', 'mpt', 7, (c) => {
    const nodes = (c.aux!.nodes ?? '').split(',').filter((n) => n !== '').map(bytes);
    return { status: 'ok', values: { value: hex(verifyProof(bytes(c.aux!.root), bytes(c.aux!.key), nodes)) } };
  }, MPT_NAMES);
});

test('unlock/unlock: the strict signature unlock of (source hash, transaction hash) under a key', async () => {
  await replayAll('unlock', 'unlock', 17, async (c) => {
    const input = bytes(c.input);
    if (input.length < 64) throw new NativeError('ErrUnlockLength');
    await verifyUnlock(parseKey(bytes(c.aux!.key)), input.slice(0, 32), input.slice(32, 64), input.slice(64));
    return { status: 'ok' };
  });
});

test('wire/token-project: the compact history of an SDK token', async () => {
  // A refused case goes through the plug-in's own token intake (NativeBridge.verifyNativeTokenBytes: the bounded native scan, then the SDK decode,
  // re-encoding equal). The accepted cases carry a synthetic certificate inside the mint's lock proof, which the intake scans (and refuses) and the
  // oracle's projection never reads, so their projection is compared through the SDK decode alone.
  await replayAll('wire', 'token-project', 36, async (c) => {
    const input = bytes(c.input);
    if (c.expected.status !== 'ok') preflightToken(input);
    let token: Token;
    try {
      token = await Token.fromCBOR(input);
    } catch {
      throw new NativeError('ErrSdkDecode');
    }
    if (hex(token.toCBOR()) !== hex(input)) throw new NativeError('ErrNonCanonical');
    return { status: 'ok', values: { projection: hex(projectToken(token)) } };
  }, TOKEN_NAMES);
});
