/**
 * An in-process model of the vault (sections 5.2, 9, 10.4, 11.1; bft-core `nb2ref/vault.go`): the packed accounting word, the
 * position-tag recent buffers, rotation and sealing, deposit and redeem in the frozen check order. It is not the contract. The plug-in
 * uses it as the vault of its offline simulator (`test/nb2`), and the shared vault vectors check that it behaves as the reference. The
 * verifier is outside the model: a redeem carries the verifier's raw return data or its revert.
 */
import { eq, toHex } from '../bytes.js';
import { ASSET_UCT, MAX_DEPOSIT, MAX_SEGMENT, construct, domainOf, log2, type Config, type Environment, type Params } from './config.js';
import { parseKey } from './crypto.js';
import { FIRST_OWNER_BYTES, FIRST_OWNER_PREFIX } from './deposit.js';
import { Nb2Error, fail } from './errors.js';
import { GapTree, bucketOf, cmp, foldHistory, gapProofLen, genesisHead, nextHead } from './segment.js';

export type VaultEvent =
  | { name: 'Deposited'; n: bigint; amount: bigint; rho: Uint8Array; firstOwner: Uint8Array }
  | { name: 'Paid'; eta: Uint8Array; recipient: Uint8Array; amount: bigint }
  | { name: 'SegmentSealed'; segment: bigint; before: Uint8Array; after: Uint8Array; ids: Uint8Array[] };

export type RecipientBehaviour = 'accepts' | 'reverts' | 'reenters-redeem' | 'reenters-deposit';

/** The mock verifier's answer: a revert with that data, or its return data. */
export type VerifierAnswer = { revert: Uint8Array } | { ret: Uint8Array };

const SHIFT = { n: 200n, c: 152n, m: 144n, q: 0n } as const;
const WIDTH = { n: 56n, c: 48n, m: 8n, q: 144n } as const;
const mask = (w: bigint): bigint => (1n << w) - 1n;
const getF = (a: bigint, f: keyof typeof SHIFT): bigint => (a >> SHIFT[f]) & mask(WIDTH[f]);
function putF(a: bigint, f: keyof typeof SHIFT, v: bigint): bigint {
  if (v < 0n || v > mask(WIDTH[f])) throw new Error(`nb2: accounting field ${f} overflow`);
  return (a & ~(mask(WIDTH[f]) << SHIFT[f])) | (v << SHIFT[f]);
}

/** A vault error with arguments (the vectors' `args`). */
const argsErr = (rule: Nb2Error['rule'], ...args: (bigint | number | string | Uint8Array)[]): Nb2Error =>
  new Nb2Error(rule, undefined, args.map((x) => (x instanceof Uint8Array ? `0x${toHex(x)}` : String(x))));

export interface RedeemOutcome { inner: Nb2Error | null }

export class VaultModel {
  public readonly d: Uint8Array;
  public A = 0n;
  public T: [bigint[], bigint[]];
  public S: [Uint8Array[], Uint8Array[]];
  public head: Uint8Array;
  public prev: Uint8Array = new Uint8Array(32);
  public events: VaultEvent[] = [];
  private entered = false;

  public constructor(public readonly gamma: Uint8Array, env: Environment, p: Params, public readonly cfg: Config = construct(gamma, env, p)) {
    this.d = domainOf(gamma);
    const w = tagWords(cfg.K, cfg.B);
    const K = Number(cfg.K);
    this.T = [Array(w).fill(0n), Array(w).fill(0n)];
    this.S = [Array.from({ length: K }, () => new Uint8Array(32)), Array.from({ length: K }, () => new Uint8Array(32))];
    this.head = genesisHead(this.d, cfg.K);
  }

  public get n(): bigint { return getF(this.A, 'n'); }
  public get c(): bigint { return getF(this.A, 'c'); }
  public get m(): bigint { return getF(this.A, 'm'); }
  public get q(): bigint { return getF(this.A, 'q'); }

  private tagAt(p: number, i: number): number {
    const lb = BigInt(log2(this.cfg.B));
    const t = 256n / lb;
    return Number((this.T[p][Number(BigInt(i) / t)] >> (lb * (BigInt(i) % t))) & mask(lb));
  }

  private setTag(p: number, i: number, tag: number): void {
    const lb = BigInt(log2(this.cfg.B));
    const t = 256n / lb;
    const w = Number(BigInt(i) / t);
    const sh = lb * (BigInt(i) % t);
    this.T[p][w] = (this.T[p][w] & ~(mask(lb) << sh)) | (BigInt(tag) << sh);
  }

  /** The live identifiers of the current and previous buffer, in arrival order. */
  public liveIds(): { current: Uint8Array[]; previous: Uint8Array[] } {
    const p = Number(this.c % 2n);
    return { current: this.S[p].slice(0, Number(this.m)), previous: this.c > 0n ? this.S[1 - p].slice() : [] };
  }

  /** The state() view. */
  public state(): { deposits: bigint; segment: bigint; population: bigint; outstanding: bigint; head: Uint8Array; previousHead: Uint8Array } {
    return { deposits: this.n, segment: this.c, population: this.m, outstanding: this.q, head: this.head, previousHead: this.c === 0n ? new Uint8Array(32) : this.prev };
  }

  public deposit(value: bigint, firstOwner: Uint8Array, rho: Uint8Array): void {
    if (this.entered) fail('Reentrancy');
    if (value <= 0n) fail('ZeroValue');
    if (firstOwner.length !== FIRST_OWNER_BYTES || !eq(firstOwner.subarray(0, FIRST_OWNER_PREFIX.length), FIRST_OWNER_PREFIX)) fail('BadFirstOwner');
    try {
      parseKey(firstOwner.subarray(FIRST_OWNER_PREFIX.length));
    } catch {
      fail('BadFirstOwner');
    }
    if (value > this.cfg.Qmax - this.q) throw argsErr('LiabilityCap', this.q, value, this.cfg.Qmax);
    const n = this.n;
    if (n >= MAX_DEPOSIT) fail('DepositCounterExhausted');
    this.A = putF(putF(this.A, 'n', n + 1n), 'q', this.q + value);
    this.events.push({ name: 'Deposited', n: n + 1n, amount: value, rho: rho.slice(), firstOwner: firstOwner.slice() });
  }

  /** redeem(evidence, claimedEta, claimedStart, history) with the verifier's answer and the recipient's behaviour; a failure reverts all. */
  public redeem(eta: Uint8Array, a: bigint, history: Uint8Array, ver: VerifierAnswer, rcp: RecipientBehaviour = 'accepts'): RedeemOutcome {
    if (this.entered) fail('Reentrancy');
    const snap = this.snapshot();
    try {
      return this.redeemInner(eta, a, history, ver, rcp);
    } catch (e) {
      this.restore(snap);
      throw e;
    }
  }

  private redeemInner(eta: Uint8Array, a: bigint, history: Uint8Array, ver: VerifierAnswer, rcp: RecipientBehaviour): RedeemOutcome {
    const K = this.cfg.K;
    const pl = BigInt(gapProofLen(K));
    const l = BigInt(history.length);
    let P = 0n;
    if (l !== 0n) {
      if (l < 32n + pl || (l - 32n) % pl !== 0n) throw argsErr('BadHistoryLength', l);
      P = (l - 32n) / pl;
    }
    const c = this.c;
    if (a > c) throw argsErr('FutureIndex', a, c);
    const e = a + P;
    if (!(e === c || (c > 0n && e === c - 1n))) throw argsErr('StaleEndpoint', e, c);
    if (P > 0n) {
      const proofs: Uint8Array[] = [];
      for (let i = 0n; i < P; i++) proofs.push(history.subarray(Number(32n + i * pl), Number(32n + (i + 1n) * pl)));
      const x = foldHistory(this.d, K, eta, a, history.subarray(0, 32), proofs);
      if (!eq(x, e === c ? this.head : this.prev)) fail('ChainMismatch');
    }
    const p = Number(c % 2n);
    const b = bucketOf(eta, this.cfg.B);
    const scan: [number, number][] = [[p, Number(this.m)]];
    if (c > 0n && e === c - 1n) scan.push([1 - p, Number(K)]);
    for (const [buf, pop] of scan) {
      for (let i = 0; i < pop; i++) if (this.tagAt(buf, i) === b && eq(this.S[buf][i], eta)) throw argsErr('AlreadyPaid', eta);
    }
    // a revert longer than MAX_VERIFIER_REVERT is VerifierBadReturn: the vault never copies unbounded revert data
    if ('revert' in ver && ver.revert.length > MAX_VERIFIER_REVERT) fail('VerifierBadReturn');
    if ('revert' in ver) throw argsErr('VerifierRefused', ver.revert);
    const vd = decodeVerdictAbi(ver.ret);
    if (vd === null) fail('VerifierBadReturn');
    const q = this.q;
    if (!eq(vd!.domain, this.d)) fail('DomainMismatch');
    if (!eq(vd!.asset, ASSET_UCT)) fail('AssetMismatch');
    if (!eq(vd!.eta, eta) || vd!.minSegment !== a) fail('ClaimMismatch');
    if (vd!.recipient.every((x) => x === 0) || eq(vd!.recipient, this.cfg.vault)) fail('BadRecipient');
    if (vd!.amount === 0n) fail('ZeroAmount');
    if (vd!.amount > q) throw argsErr('LiabilityUnderflow', q, vd!.amount);
    let m = Number(this.m);
    this.S[p][m] = vd!.eta.slice();
    this.setTag(p, m, bucketOf(vd!.eta, this.cfg.B));
    m++;
    this.A = putF(this.A, 'q', q - vd!.amount);
    this.events.push({ name: 'Paid', eta: vd!.eta.slice(), recipient: vd!.recipient.slice(), amount: vd!.amount });
    if (BigInt(m) === K) this.seal(p);
    else this.A = putF(this.A, 'm', BigInt(m));
    const out: RedeemOutcome = { inner: null };
    this.entered = true;
    try {
      if (rcp === 'reverts') fail('PayoutFailed');
      if (rcp === 'reenters-redeem') out.inner = this.tryInner(() => this.redeem(eta, a, history, ver, 'accepts'));
      if (rcp === 'reenters-deposit') out.inner = this.tryInner(() => this.deposit(1n, new Uint8Array(), new Uint8Array(32)));
    } finally {
      this.entered = false;
    }
    return out;
  }

  private tryInner(f: () => unknown): Nb2Error | null {
    try {
      f();
      return null;
    } catch (e) {
      if (e instanceof Nb2Error) return e;
      throw e;
    }
  }

  private seal(p: number): void {
    const c = this.c;
    const K = Number(this.cfg.K);
    if (c >= MAX_SEGMENT) fail('SegmentCounterExhausted');
    const buckets: Uint8Array[][] = Array.from({ length: Number(this.cfg.B) }, () => []);
    for (let i = 0; i < K; i++) buckets[this.tagAt(p, i)].push(this.S[p][i]);
    const z: Uint8Array[] = [];
    buckets.forEach((bk, t) => {
      bk.sort(cmp);
      for (const x of bk) if (bucketOf(x, this.cfg.B) !== t) throw new Error('nb2: seal assertion failed');
      z.push(...bk);
    });
    const tree = GapTree.build(z);
    if (tree === null) throw new Error('nb2: seal assertion failed');
    const next = nextHead(this.d, c, this.head, tree.root);
    this.events.push({ name: 'SegmentSealed', segment: c, before: this.head, after: next, ids: z.map((x) => x.slice()) });
    this.prev = this.head;
    this.head = next;
    this.A = putF(putF(this.A, 'c', c + 1n), 'm', 0n);
  }

  private snapshot(): unknown {
    return { A: this.A, T: [this.T[0].slice(), this.T[1].slice()], S: [this.S[0].map((x) => x.slice()), this.S[1].map((x) => x.slice())], h: this.head, p: this.prev, ev: this.events.length };
  }

  private restore(s: unknown): void {
    const x = s as { A: bigint; T: [bigint[], bigint[]]; S: [Uint8Array[], Uint8Array[]]; h: Uint8Array; p: Uint8Array; ev: number };
    this.A = x.A;
    this.T = x.T;
    this.S = x.S;
    this.head = x.h;
    this.prev = x.p;
    this.events.length = x.ev;
    this.entered = false;
  }

  /** An independent copy of this vault's state (for simulating a call without effects). */
  public copy(): VaultModel {
    const v = new VaultModel(this.gamma, { address: this.cfg.vault, chainId: this.cfg.chainId, verifierCodeHash: this.cfg.verifierCodeHash }, { K: [this.cfg.K], B: [this.cfg.B] }, this.cfg);
    v.A = this.A;
    v.T = [this.T[0].slice(), this.T[1].slice()];
    v.S = [this.S[0].map((x) => x.slice()), this.S[1].map((x) => x.slice())];
    v.head = this.head.slice();
    v.prev = this.prev.slice();
    v.events = this.events.slice();
    return v;
  }

  /** The test harness's storage injection (states no sequence can reach). */
  public setState(n: bigint, c: bigint, m: bigint, q: bigint, head: Uint8Array, prev: Uint8Array, current: Uint8Array[], previous: Uint8Array[]): void {
    this.A = putF(putF(putF(putF(0n, 'n', n), 'c', c), 'm', m), 'q', q);
    this.head = head.slice();
    this.prev = prev.slice();
    const p = Number(c % 2n);
    current.forEach((x, i) => {
      this.S[p][i] = x.slice();
      this.setTag(p, i, bucketOf(x, this.cfg.B));
    });
    previous.forEach((x, i) => {
      this.S[1 - p][i] = x.slice();
      this.setTag(1 - p, i, bucketOf(x, this.cfg.B));
    });
  }
}

/** The longest verifier revert the vault relays as VerifierRefused(revertData). */
export const MAX_VERIFIER_REVERT = 1024;

/** words(K, B) = ceil(K / floor(256 / log2 B)). */
export function tagWords(K: bigint, B: bigint): number {
  const t = 256n / BigInt(log2(B));
  return Number((K + t - 1n) / t);
}

/** The verifier's return data: exactly 192 canonical bytes (uint64 and address words with zero high bytes). */
export function decodeVerdictAbi(b: Uint8Array): { domain: Uint8Array; eta: Uint8Array; minSegment: bigint; asset: Uint8Array; recipient: Uint8Array; amount: bigint } | null {
  if (b.length !== 192 || b.subarray(64, 88).some((x) => x !== 0) || b.subarray(128, 140).some((x) => x !== 0)) return null;
  const int = (x: Uint8Array): bigint => x.reduce((a, y) => (a << 8n) | BigInt(y), 0n);
  return {
    domain: b.slice(0, 32), eta: b.slice(32, 64), minSegment: int(b.subarray(64, 96)), asset: b.slice(96, 128), recipient: b.slice(140, 160), amount: int(b.subarray(160, 192)),
  };
}
