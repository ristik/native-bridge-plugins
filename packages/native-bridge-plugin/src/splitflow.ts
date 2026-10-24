/**
 * Splitting a held bridged token (protocol 6, `protocol/interop.md` "Split lineage"): the SDK's burn-and-mint `TokenSplit`, journaled so
 * that every step survives a crash.
 *
 * The split is deterministic once its plan is fixed: the source token, each output's recipient, amount and salt, and the burn's state
 * mask. `planSplit` checks and prices it and has no side effect; the host journals the plan BEFORE anything is submitted. `runSplit`
 * then rebuilds the same manifest burn and the same child mints from the plan on every call, journals the burn's certification data
 * before submitting it (so a resubmission after a crash is the identical request, never a second burn), journals the certified burned
 * source, then each certified child. A step is never acknowledged before its certified blob is in the journal, and a call on a journaled
 * record continues where the last one stopped. The plug-in submits nothing itself: certification and signing are the host's.
 */
import type { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import type { IUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/IUnlockScript.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { SplitMintJustification } from '@unicitylabs/state-transition-sdk/lib/payment/SplitMintJustification.js';
import { SplitTokenRequest } from '@unicitylabs/state-transition-sdk/lib/payment/SplitTokenRequest.js';
import { TokenSplit, type ISplit } from '@unicitylabs/state-transition-sdk/lib/payment/TokenSplit.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { CertifiedTransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedTransferTransaction.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import type { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';

import { eq, toHex } from './bytes.js';
import { fail } from './errors.js';
import { type Gate } from './gas.js';
import { SPLIT_EDGE_BASE, SPLIT_PER_BYTE, SPLIT_PER_STEP } from './lineage.js';
import { MAX_SUM_PROOF_STEPS } from './limits.js';
import { BURN_HISTORY_BYTES, checkBurnProjection } from './proof.js';
import { cfgBytes, policyBytes } from './profile.js';
import { preflightToken } from './resources.js';
import { scanCounted } from './scan.js';
import { WalletValue } from './splitpart.js';
import { uintOf, type NativeBridgePlugin } from './wallet.js';

/** One output of a split: its first owner (an encoded predicate, tag 39032), its whole amount and its mint salt (32 bytes). */
export interface SplitOutput {
  recipient: Uint8Array;
  amount: bigint;
  salt: Uint8Array;
}

/** A split as the host journals it. Everything after the plan is a certified result, appended in order. */
export interface SplitRecord {
  splitId: string;
  /** The held token being split (exact bytes). */
  source: Uint8Array;
  outputs: SplitOutput[];
  /** The burn's state mask: with the outputs it fixes the manifest burn. */
  burnStateMask: Uint8Array;
  /** The manifest burn's certification data, journaled before its first submission. */
  burnRequest?: Uint8Array;
  /** The certified burned source token. */
  burned?: Uint8Array;
  /** Each output's certified token, in output order (null until minted). */
  children: (Uint8Array | null)[];
}

export interface SplitJournal {
  put(record: SplitRecord): Promise<void>;
  get(splitId: string): Promise<SplitRecord | null>;
}

export class MemorySplitJournal implements SplitJournal {
  private readonly records = new Map<string, SplitRecord>();
  public put(r: SplitRecord): Promise<void> {
    this.records.set(r.splitId, structuredClone(r));
    return Promise.resolve();
  }
  public get(id: string): Promise<SplitRecord | null> {
    const r = this.records.get(id);
    return Promise.resolve(r ? structuredClone(r) : null);
  }
}

/** The host's side of a split: the holder's signature on the burn, and certification by the aggregator. */
export interface SplitHost {
  journal: SplitJournal;
  /** The holder's unlock script for the manifest burn of the source. */
  unlock(burn: TransferTransaction): Promise<IUnlockScript>;
  /** Submit one certification request and return its inclusion proof. Submitting the same request again must be harmless. */
  certify(request: CertificationData, what: string): Promise<InclusionProof>;
}

/** What `planSplit` returns: the record to journal before `runSplit`, and each output's best-case redemption estimate. */
export interface SplitPlan {
  record: SplitRecord;
  estimates: Gate[];
}

/**
 * Check and price a split before anything is burned. The held token must verify as a receipt (a whole token or a part); the outputs must
 * be at least two, each positive, summing to exactly the held amount, with distinct 32-byte salts. Each output's redemption is priced
 * from the lineage it will have (the held lineage, the manifest burn, the output's mint and its own return burn) and the walk's charge of
 * the new edge: the full estimate interop.md asks for before the manifest burn ("Split lineage": the whole lineage and the walk, not the
 * output's own leaves only), computed before the burn exists and therefore a lower bound, as `preflightBurn`'s is for a whole token. An
 * output that could never be redeemed under the resource policy (`ErrInputTooLarge`) refuses the whole split. The estimate is never a gas
 * ceiling (owner section 36).
 */
export async function planSplit(
  plugin: NativeBridgePlugin, splitId: string, tokenBytes: Uint8Array, outputs: SplitOutput[], burnStateMask: Uint8Array = StateMask.generate().bytes,
): Promise<SplitPlan> {
  preflightToken(tokenBytes);
  const held = await plugin.bridge.verifyNativeToken(await Token.fromCBOR(tokenBytes), 'receipt');
  const amount = uintOf(held.lineage?.partAmount ?? held.outcome.amount);
  if (outputs.length < 2) fail('ErrSplitProofCount', 'a split has at least two outputs');
  const salts = new Set<string>();
  let sum = 0n;
  for (const o of outputs) {
    if (o.amount <= 0n) fail('ErrSplitSum', 'every output amount is positive');
    if (o.salt.length !== 32) fail('ErrSplitProofShape', 'an output salt is 32 bytes');
    salts.add(toHex(o.salt));
    EncodedPredicate.fromCBOR(o.recipient);
    sum += o.amount;
  }
  if (salts.size !== outputs.length) fail('ErrSplitProofShape', 'output salts are distinct');
  if (sum !== amount) fail('ErrSplitSum', `the outputs sum to ${sum}, the held token holds ${amount}`);
  StateMask.fromBytes(burnStateMask);
  const dep = plugin.bridge.registry.deployments[held.deployment];
  // the child's mint embeds the burned source: about the held bytes plus the burn and its proof; its own history adds its burn
  const nested = tokenBytes.length + BURN_HISTORY_BYTES;
  const history = nested + 2 * BURN_HISTORY_BYTES;
  const leaves = held.outcome.leaves.length + 3; // the held lineage, its manifest burn, the output's mint and its return burn
  const steps = Math.min(MAX_SUM_PROOF_STEPS, Math.ceil(Math.log2(outputs.length)));
  const items = scanCounted(tokenBytes, Number.MAX_SAFE_INTEGER, true).tokens; // the embedded token is scanned as a native item (its certificates carry maps)
  const walk = (held.lineage?.splitGas ?? 0) + SPLIT_PER_BYTE * (history - 2 * BURN_HISTORY_BYTES) + SPLIT_PER_BYTE * nested + 20 * items + SPLIT_EDGE_BASE + SPLIT_PER_STEP * steps;
  const estimates = outputs.map(() => {
    const gate = checkBurnProjection(cfgBytes(dep.cfg).length, policyBytes(dep.policy).length, leaves, history, 1);
    return { ...gate, native: gate.native + walk, total: gate.total + walk };
  });
  const record: SplitRecord = {
    splitId, source: tokenBytes, outputs: outputs.map((o) => ({ ...o })), burnStateMask, children: outputs.map(() => null),
  };
  return { record, estimates };
}

/** The SDK split of the plan: the same manifest burn and child templates on every call. */
async function rebuild(record: SplitRecord, source: Token, aid: Uint8Array): Promise<ISplit> {
  const requests = record.outputs.map((o) => SplitTokenRequest.create(
    EncodedPredicate.fromCBOR(o.recipient), WalletValue.of(aid, amountBytes(o.amount)), TokenSalt.fromBytes(o.salt)));
  return TokenSplit.split(source, WalletValue.decode, requests, { burnStateMask: StateMask.fromBytes(record.burnStateMask) });
}

/** The SDK's own checks of one certified step (its proof, certificate and predicate), as a profile failure. */
async function sdkStep<T>(what: string, f: () => Promise<T>): Promise<T> {
  try {
    return await f();
  } catch (e) {
    return fail('ErrSdkVerification', `${what}: ${String((e as Error)?.message ?? e).slice(0, 160)}`);
  }
}

const amountBytes = (v: bigint): Uint8Array => {
  const out: number[] = [];
  for (let x = v; x > 0n; x >>= 8n) out.unshift(Number(x & 0xffn));
  return Uint8Array.from(out);
};

/**
 * Run (or resume) a planned split: the manifest burn of the source, then each output's mint, every certified result journaled before the
 * next step. Each minted output is verified as a receipt of the source's deployment (the issuance policy fails closed) before it is
 * journaled. Returns the certified output tokens in output order.
 */
export async function runSplit(plugin: NativeBridgePlugin, record: SplitRecord, host: SplitHost): Promise<Uint8Array[]> {
  const source = await Token.fromCBOR(record.source);
  const held = await plugin.bridge.verifyNativeToken(source, 'receipt');
  const aid = plugin.bridge.registry.deployments[held.deployment].cfg.aid;
  const split = await rebuild(record, source, aid);
  const ctx = await plugin.bridge.context();
  let r = { ...record, children: [...record.children] };
  if (r.burned === undefined) {
    let request: CertificationData;
    if (r.burnRequest === undefined) {
      request = await CertificationData.fromTransaction(split.burn.transaction, await host.unlock(split.burn.transaction));
      r = { ...r, burnRequest: request.toCBOR() };
      await host.journal.put(r);
    } else {
      request = CertificationData.fromCBOR(r.burnRequest);
      // the journaled request must be this plan's burn: a different transaction is another split, never resubmitted under this one
      if (!eq((await split.burn.transaction.calculateTransactionHash()).data, request.transactionHash.data)) fail('ErrBurnReason', 'the journaled burn is not this plan\'s');
    }
    const proof = await host.certify(request, 'the split burn');
    // the host's answer is verified before it is journaled: the proof is for this request, and the SDK accepts the burned source (its
    // proof under the installed trust, the holder's unlock), so a bad proof never reaches the journal or a child's mint
    if (!eq(proof.certificationData.toCBOR(), request.toCBOR())) fail('ErrCDMismatch', 'the burn proof is not for the journaled request');
    const certified = await sdkStep('the split burn', () =>
      CertifiedTransferTransaction.fromTransaction(ctx.trustBase, ctx.predicateVerifier, ctx.unicityCertificateVerifier, split.burn.transaction, proof));
    const burned = (await sdkStep('the burned source', () => source.transfer(certified, ctx))).toCBOR();
    preflightToken(burned);
    r = { ...r, burned };
    await host.journal.put(r);
  }
  const burnedToken = await Token.fromCBOR(r.burned!);
  for (let j = 0; j < split.tokens.length; j++) {
    if (r.children[j] !== null) continue;
    const o = split.tokens[j];
    // the committed mint data is the frozen payment data's exact bytes (the output commitment binds them)
    const mint = await MintTransaction.create(NetworkId.fromId(o.networkId.id), o.recipient, {
      data: await o.paymentData.encode(), expiresAt: null, justification: SplitMintJustification.create(burnedToken, o.proofs).toCBOR(), salt: o.salt, tokenType: o.tokenType,
    });
    const request = await CertificationData.fromMintTransaction(mint);
    const proof = await host.certify(request, `split output ${j + 1}/${split.tokens.length}`);
    if (!eq(proof.certificationData.toCBOR(), request.toCBOR())) fail('ErrCDMismatch', `the proof of split output ${j + 1} is not for its mint`);
    const genesis = await sdkStep(`split output ${j + 1}`, () =>
      CertifiedMintTransaction.fromTransaction(ctx.trustBase, ctx.predicateVerifier, ctx.unicityCertificateVerifier, mint, proof));
    const child = (await sdkStep(`split output ${j + 1}`, () => Token.mint(genesis, ctx))).toCBOR();
    preflightToken(child);
    await plugin.bridge.verifyNativeToken(await Token.fromCBOR(child), 'receipt');
    r.children[j] = child;
    await host.journal.put(r);
  }
  return r.children as Uint8Array[];
}
