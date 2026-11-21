/** Preflight refusals before the irreversible burn, the recipient rule, the index rule, and the SDK's view of the plug-in's bytes. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';

import { eq } from '../../src/bytes.js';
import { NativeBridgeV2 } from '../../src/nb2/bridge.js';
import { HE } from '../../src/nb2/crypto.js';
import { Nb2Error, WalletError } from '../../src/nb2/errors.js';
import { decodeToken, encodeProof, signaturePredicate } from '../../src/nb2/token.js';
import { localOwner, mintRequest } from '../../src/nb2/tokenops.js';
import { evmAccount, key, setup, FakeChain, VAULT } from './world.js';
import type { GasModel } from '../../src/nb2/gas.js';
import { ProvisionalGasModel } from '../../src/nb2/gas.js';

const outcome = async (p: Promise<unknown>): Promise<string> => {
  try {
    await p;
    return 'ok';
  } catch (e) {
    return e instanceof Nb2Error ? e.rule : e instanceof WalletError ? e.reason : String(e);
  }
};

async function minted(overrides: Record<string, unknown> = {}, pins: Record<string, unknown> = {}) {
  const s = await setup();
  const payer = evmAccount(s.chain, 'p');
  const owner = localOwner(key('o'));
  const o = s.options('w');
  const w = await NativeBridgeV2.open({ ...o, ...overrides, pins: { ...o.pins, ...pins } });
  const p = await w.planDeposit(3n, owner.publicKey);
  await w.submitDeposit(p, payer);
  await w.collectDepositProof(p.intent);
  return { ...s, w, payer, owner, token: await w.mint(p.intent) };
}

const r = HE(key('recipient')).slice(12);

test('preflight: an oversized token, unfundable gas and an unboundable gas cost refuse before the burn', async () => {
  const small = await minted({}, { maxEncodedTxBytes: 40_000n });
  assert.equal(await outcome(small.w.planReturn(small.token, r, small.payer.address)), 'CapacityPreflight');
  const tight = await minted({}, { userGasLimit: 1_000_000n });
  assert.equal(await outcome(tight.w.planReturn(tight.token, r, tight.payer.address)), 'CapacityPreflight');
  const blind: GasModel = { name: 'blind', redeemGasLimit: () => null, depositGasLimit: () => 200_000n };
  const unbounded = await minted({ gas: blind });
  assert.equal(await outcome(unbounded.w.planReturn(unbounded.token, r, unbounded.payer.address)), 'CapacityPreflight');
  const ok = await minted();
  const poor = evmAccount(ok.chain, 'poor');
  ok.chain.balances.set(Buffer.from(poor.address).toString('hex'), 1000n);
  assert.equal(await outcome(ok.w.planReturn(ok.token, r, poor.address)), 'InsufficientFunds');
  // nothing was burned or journaled as burned
  assert.equal((await ok.w.journal.returns()).length, 0);
  const plan = await ok.w.planReturn(ok.token, r, ok.payer.address);
  assert.ok(plan.gasLimit > 500_000n && plan.gasLimit < 60_000_000n);
  // the bound stays above NB2-05's mint + burn token (748,672) plus the worst vault call and the reserve
  assert.ok(plan.gasLimit >= 748_672n + 487_339n + 500_000n, `gas limit ${plan.gasLimit}`);
  assert.equal(ok.w.gas.name, 'estimate-nb2-1179');
  assert.ok(new ProvisionalGasModel().name.length > 0);
});

test('the default gas estimate is refused for a verifier it is not calibrated for: the stand-in verifier code is not Γ\'s', async () => {
  const s = await minted();
  const bridge = await NativeBridgeV2.open({ ...s.options('default gas'), gas: undefined });
  assert.equal(bridge.gas.name, 'estimate-nb2-1179');
  assert.equal(await outcome(bridge.planReturn(s.token, r, s.payer.address)), 'BadDeployment');
  // the world's own tests supply the model as a wallet supplies its own (world.ts WORLD_GAS): no build check, the bound as computed
});

test('recipient rule: zero and vault refused, a contract warned', async () => {
  const s = await minted();
  assert.equal(await outcome(s.w.planReturn(s.token, new Uint8Array(20), s.payer.address)), 'RecipientRefused');
  assert.equal(await outcome(s.w.planReturn(s.token, VAULT, s.payer.address)), 'RecipientRefused');
  s.chain.code.set(Buffer.from(r).toString('hex'), Uint8Array.of(0x60, 0x00));
  assert.equal((await s.w.planReturn(s.token, r, s.payer.address)).warnings.length, 1);
});

test('index rule: a plain state() read is not evidence outside stateReadOnly; an implausible jump is refused', async () => {
  const s = await minted();
  assert.equal(await outcome(s.w.planReturn(s.token, r, s.payer.address, { useStateRead: true })), 'StateReadNotAdmitted');
  const t = await minted({}, { stateReadOnly: true, maxJump: 0n });
  // a provider claims segment 5 while the wallet verified 0
  const real = t.chain.call.bind(t.chain);
  t.chain.call = async <T>(m: string, p: any[]): Promise<T> => {
    const out = await real<any>(m, p);
    if (m === 'eth_call' && p[0].data === '0xc19d93fb') return (`${(out as string).slice(0, 66)}${'00'.repeat(31)}05${(out as string).slice(130)}`) as T;
    return out;
  };
  assert.equal(await outcome(t.w.planReturn(t.token, r, t.payer.address, { useStateRead: true, verifiedIndex: 0n })), 'ImplausibleIndex');
  // a provider that hides every seal only anchors the burn lower (a = 0), never higher
  const u = await minted();
  u.chain.faults.hideAllSeals = true;
  assert.equal((await u.w.planReturn(u.token, r, u.payer.address)).a, 0n);
});

test('SDK parity: the plug-in mint is the SDK mint, and the SDK decodes its inclusion proof', async () => {
  const s = await minted();
  const t = decodeToken(s.token);
  const sdkMint = await MintTransaction.create(NetworkId.fromId(t.mint.network), SignaturePredicate.create(s.owner.publicKey), {
    salt: TokenSalt.fromBytes(t.mint.salt), tokenType: new TokenType(t.mint.type), justification: t.mint.justification, data: t.mint.data, expiresAt: null,
  });
  assert.ok(eq(sdkMint.toCBOR(), t.mintRaw));
  const ours = mintRequest({ ...t.mint, recipient: signaturePredicate(s.owner.publicKey) });
  assert.ok(eq((await CertificationData.fromMintTransaction(sdkMint)).toCBOR(), ours.cd));
  const proof = encodeProof(t.mintProof);
  assert.ok(eq(InclusionProof.fromCBOR(proof).toCBOR(), proof));
});

test('unlock recovery IDs 2 and 3 are refused (astra delta ruling): such a lineage is not returnable', async () => {
  const { verifyUnlock, signUnlock } = await import('../../src/nb2/crypto.js');
  const { secp256k1 } = await import('@noble/curves/secp256k1.js');
  const k = key('u');
  const src = HE(key('s'));
  const tx = HE(key('t'));
  const sig = signUnlock(k, src, tx);
  verifyUnlock(secp256k1.getPublicKey(k, true), src, tx, sig);
  for (const id of [2, 3]) {
    const bad = sig.slice();
    bad[64] = id;
    assert.throws(() => verifyUnlock(secp256k1.getPublicKey(k, true), src, tx, bad), (e) => e instanceof Nb2Error && e.rule === 'UnlockRecovery');
  }
});

test('deposit estimates the pinned protocol 10 deployment and checks its gas limit before signing', async () => {
  const s = await setup();
  const code = Buffer.from('verifier code');
  const chain = await FakeChain.create(s.root, { ...s.cfg, verifierCodeHash: HE(code) });
  const payer = evmAccount(chain, 'estimate payer');
  const owner = localOwner(key('estimate owner'));
  chain.code.set(Buffer.from(s.cfg.verifier).toString('hex'), code);
  const pins = { ...s.pins, gamma: chain.gamma };
  const options = s.options('estimated deposit');
  const bridge = await NativeBridgeV2.open({ ...options, pins, rpc: chain, gas: undefined });
  const plan = await bridge.planDeposit(3n, owner.publicKey);
  await bridge.submitDeposit(plan, payer);
  assert.equal((await bridge.journal.depositForUpdate(plan.intent))!.sends[0].gas, '144000');
  assert.ok(chain.calls.includes('eth_estimateGas'));

  const limited = await NativeBridgeV2.open({ ...s.options('limited deposit'), gas: undefined, rpc: chain, pins: { ...pins, userGasLimit: 143_999n } });
  const denied = await limited.planDeposit(3n, owner.publicKey);
  assert.equal(await outcome(limited.submitDeposit(denied, payer)), 'CapacityExceeded');
  assert.equal((await limited.journal.depositForUpdate(denied.intent))!.sends.length, 0);
});
