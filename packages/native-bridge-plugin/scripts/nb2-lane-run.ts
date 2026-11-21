import { randomBytes } from 'node:crypto';
import { existsSync, linkSync, lstatSync, mkdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fsyncDir, lockWallet, writeDurable } from '../../../wallet/core.js';
import { eq, fromHex, toHex } from '../src/bytes.js';
import { ascii, u64 } from '../src/nb2/cbor.js';
import { decodeConfig, domainOf, type Params } from '../src/nb2/config.js';
import { HU } from '../src/nb2/crypto.js';
import { burnPredicate, decodeToken, lineageOf, signaturePredicate } from '../src/nb2/token.js';
import {
  appendTransfer, certifyChecked, childMint, mintRequest, splitPlan, tokenOfChild, transferRequest,
  type Aggregator, type OwnerSigner,
} from '../src/nb2/tokenops.js';
import { Nb2Error } from '../src/nb2/errors.js';
import { burnIndex, verifySealReceipt } from '../src/nb2/rules.js';
import { bindTrust, SealAheadOfOrigin, type TrustInput } from '../src/nb2/trust.js';
import { encodeReturnData, verdictAbi, verifyCertifiedStep, verifyHeld, verifyReturn, verifySplit } from '../src/nb2/verify.js';

const workloads = {
  'transfers-600': { transfers: 600, splits: 0 },
  'one-split-600': { transfers: 600, splits: 1 },
  'depth-20': { transfers: 0, splits: 20 },
};
export type History = keyof typeof workloads;

interface Job {
  gamma: Uint8Array;
  params: Params;
  trust: TrustInput;
  /** Reload the operator-authenticated checkpoint and held UTB bundle. */
  refreshTrust?: () => Promise<TrustInput>;
  originPollMs?: number;
  root: Uint8Array;
  owner: OwnerSigner;
  aggregator: Aggregator;
  recipient: Uint8Array;
  startingSeal?: Uint8Array;
  output: string;
  history: History;
}

interface Pending {
  tx: string;
  cd: string;
  allocation?: string;
}

interface Journal {
  binding: string;
  seed: string;
  rootAmount: string;
  step: number;
  token: string;
  pending?: Pending;
}

function bytes(hex: string): Uint8Array {
  const decoded = fromHex(hex);
  if (decoded === null) throw new Error('invalid lane journal hex');
  return decoded;
}

function pendingAuthority(error: unknown): boolean {
  for (let e = error; e instanceof Nb2Error; e = e.inner) {
    if (e instanceof SealAheadOfOrigin || e.rule === 'NoEntryForEpoch') return true;
  }
  return false;
}

export async function runLaneWorkload(job: Job) {
  const { transfers, splits } = workloads[job.history];
  const count = transfers + 2 * splits + 1;
  const output = resolve(job.output);
  const dir = output + '.journal';
  if (!statSync(dirname(output)).isDirectory()) throw new Error('lane output requires an existing parent directory');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  lockWallet(dir);
  const file = join(dir, 'state.json');
  const reservation = join(dir, 'reservation');
  const cfg = decodeConfig(job.gamma, job.params);
  const domain = domainOf(job.gamma);
  if (job.recipient.length !== 20 || !job.recipient.some(Boolean) || eq(job.recipient, cfg.vault)) throw new Error('invalid return recipient');
  const save = (state: Journal): void => writeDurable(file, JSON.stringify(state));
  let trust = job.trust;
  bindTrust(trust, cfg);
  const verify = async <T>(check: (authority: TrustInput) => Promise<T>): Promise<T> => {
    const deadline = Date.now() + 120_000;
    for (;;) {
      try {
        return await check(trust);
      } catch (e) {
        if (!job.refreshTrust || !pendingAuthority(e) || Date.now() >= deadline) throw e;
        await new Promise<void>((resolve) => setTimeout(resolve, job.originPollMs ?? 1_000));
        const fresh = await job.refreshTrust();
        bindTrust(fresh, cfg);
        const tip = trust.history.tip!;
        const prefix = fresh.history.entryForEpoch(tip.epoch);
        if (prefix === null || !eq(await prefix.entryId(), await tip.entryId())
          || fresh.origin!.usableEpoch < trust.origin!.usableEpoch || fresh.origin!.rootRound < trust.origin!.rootRound) {
          throw new Error('lane authority refresh does not extend the held checkpoint and history');
        }
        trust = fresh;
      }
    }
  };

  const { startingSeal } = job;
  const seal = startingSeal === undefined ? null : await verify((t) => verifySealReceipt(cfg, domain, t, startingSeal));
  const { a: minIndex } = burnIndex(cfg, domain, seal);
  const binding = toHex(HU(domain, HU(job.root), job.owner.publicKey, job.recipient, u64(minIndex), ascii(job.history)));
  let state: Journal;
  if (existsSync(file)) {
    state = JSON.parse(readFileSync(file, 'utf8')) as Journal;
    if (state.binding !== binding) throw new Error('lane journal belongs to a different workload');
  } else {
    if (existsSync(output)) throw new Error(`lane output already exists: ${output}`);
    const root = decodeToken(job.root);
    const held = await verify((t) => verifyHeld(cfg, domain, t, root));
    if (root.ancestors.length !== 0 || root.transfers.length !== 0 || !eq(held.owner.params, job.owner.publicKey)) {
      throw new Error('workload requires a freshly minted root held by this owner');
    }
    if (held.amount <= BigInt(splits)) throw new Error('root amount is too small for the requested splits');
    state = { binding, seed: toHex(randomBytes(32)), rootAmount: String(held.amount), step: 0, token: toHex(job.root) };
    save(state);
  }

  // Create a fresh empty reservation when the destination is free. The old inode
  // may still hold bytes someone wrote through the destination before removing it.
  if (!existsSync(output)) {
    writeDurable(reservation, new Uint8Array());
    linkSync(reservation, output);
    fsyncDir(dirname(output));
  }
  const reserved = existsSync(reservation) ? statSync(reservation, { bigint: true }) : undefined;
  const checkOutput = () => {
    const current = lstatSync(output, { bigint: true });
    if (reserved && current.size === 0n && current.dev === reserved.dev && current.ino === reserved.ino) return true;
    if (current.isFile() && state.step === count && eq(readFileSync(output), bytes(state.token))) return false;
    throw new Error(`lane output already exists: ${output}`);
  };
  checkOutput();

  const owner = signaturePredicate(job.owner.publicKey);
  const seed = bytes(state.seed);
  const randomFor = (label: string, i: number) => HU(seed, ascii(label), u64(i));
  while (state.step < count) {
    const step = state.step;
    const token = bytes(state.token);
    const terminal = step === count - 1;
    const splitIndex = Math.floor((step - transfers) / 2);
    const splitMint = step >= transfers && !terminal && (step - transfers) % 2 === 1;
    const amount = BigInt(state.rootAmount) - BigInt(Math.max(0, splitIndex));
    if (!state.pending) {
      if (step < transfers || terminal) {
        const data = terminal ? encodeReturnData({ d: domain, asset: cfg.asset, recipient: job.recipient, amount, minIndex }) : null;
        const request = await transferRequest(token, job.owner, {
          recipient: data === null ? owner : burnPredicate(HU(data)), mask: randomFor('transfer', step), data, deadline: null,
        });
        state.pending = { tx: toHex(request.tx), cd: toHex(request.cd) };
      } else {
        const plan = splitPlan(decodeToken(token), [
          { ownerKey: job.owner.publicKey, amount: amount - 1n, salt: randomFor('child', splitIndex) },
          { ownerKey: job.owner.publicKey, amount: 1n, salt: randomFor('sibling', splitIndex) },
        ], cfg.ty, cfg.aid, randomFor('split', splitIndex));
        if (splitMint) {
          const split = await verify((t) => verifySplit(cfg, domain, t, decodeToken(token)));
          if (!eq(split.manifest, plan.tree.root)) throw new Error('certified split manifest differs from its journaled plan');
          const { mint, allocation } = childMint(split.link, plan.tree, plan.children[0]);
          const request = mintRequest(mint);
          state.pending = { tx: toHex(request.tx), cd: toHex(request.cd), allocation: toHex(allocation) };
        } else {
          const request = await transferRequest(token, job.owner, plan.burn);
          state.pending = { tx: toHex(request.tx), cd: toHex(request.cd) };
        }
      }
      save(state);
    }

    const tx = bytes(state.pending.tx);
    const proof = await certifyChecked(job.aggregator, bytes(state.pending.cd));
    const certified = state.pending.allocation === undefined
      ? appendTransfer(token, tx, proof)
      : tokenOfChild(token, bytes(state.pending.allocation), tx, proof);
    if (terminal) {
      await verify((t) => verifyReturn(job.gamma, certified, t, job.params));
    } else {
      const part = decodeToken(certified);
      if (step < transfers) await verify((t) => verifyCertifiedStep(cfg, t, tx, part.proofs.at(-1)!));
      else if (splitMint) await verify((t) => verifyHeld(cfg, domain, t, part));
      else await verify((t) => verifySplit(cfg, domain, t, part));
    }
    state.token = toHex(certified);
    state.step++;
    delete state.pending;
    save(state);
  }

  const evidence = bytes(state.token);
  const verdict = await verify((t) => verifyReturn(job.gamma, evidence, t, job.params));
  if (checkOutput()) writeDurable(output, evidence);
  const levels = lineageOf(decodeToken(evidence)).map((level) => ({
    mintBytes: level.mintRaw.length,
    transfers: level.transfersRaw.length,
    transferBytes: level.transfersRaw.reduce((n, tx) => n + tx.length, 0),
  }));
  return { history: job.history, evidenceBytes: evidence.length, levels, verdict: toHex(verdictAbi(verdict)) };
}
