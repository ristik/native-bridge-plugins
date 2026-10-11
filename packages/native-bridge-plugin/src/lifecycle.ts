/**
 * The wallet's path from a durable burn to claimed native funds, journalled at each step (`RedemptionEntry.status`):
 * `burned` -> `submitted` (a redeem was sent, every hash kept) -> `redeemed` (the vault credited the recipient) -> `settled` (the claim was
 * confirmed by its receipt and by the `claimable` balance falling by the claimed amount). Settlement is never inferred from the wallet burn
 * acknowledgement. The host supplies the transports; nothing here decides admission.
 */
import { NativeError, fail } from './errors.js';
import { redeemReturn, DEFAULT_REDEEM, type ChainReader, type RedeemPolicy, type RedeemResult, type RedeemTransport } from './freshness.js';
import { claimCalldata, type NativeBridgePayments, type NativeBridgePlugin, type ProofSource, type RedemptionEntry } from './wallet.js';

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function entryOf(payments: NativeBridgePayments, burnId: string): Promise<RedemptionEntry> {
  return (await payments.journal.get(burnId)) ?? fail('ErrMissingBacking', `no journal entry for burn ${burnId}`);
}

/**
 * Redeem a journalled burn. The journal is written before every send (`submitted`) and with every hash, so a restart resumes with the hashes
 * of earlier sends (`RedemptionUnconfirmed` leaves the entry `submitted`); on success, or when the vault already credited the nonce, the entry
 * becomes `redeemed`. An entry that is already `redeemed` or `settled` is not sent again.
 */
export async function redeemBurned(
  plugin: NativeBridgePlugin,
  payments: NativeBridgePayments,
  burnId: string,
  source: ProofSource,
  chain: ChainReader,
  transport: RedeemTransport,
  policy: RedeemPolicy = DEFAULT_REDEEM,
): Promise<RedeemResult> {
  const entry = await entryOf(payments, burnId);
  if (entry.status === 'redeemed' || entry.status === 'settled') return { status: 'already-redeemed', nullifier: entry.nullifier, sends: 0 };
  const put = (patch: Partial<RedemptionEntry>): Promise<void> => payments.journal.put({ ...entry, ...patch, redeemTxs: [...entry.redeemTxs] });
  const result = await redeemReturn(plugin, entry.burnedToken, source, chain, transport, policy, entry.redeemTxs, {
    beforeSend: () => put({ status: 'submitted' }),
    sent: async (h) => {
      if (h !== undefined && !entry.redeemTxs.includes(h)) entry.redeemTxs.push(h);
      await put({ status: 'submitted' });
    },
  });
  if (result.status === 'redeemed' && result.txHash !== undefined && !entry.redeemTxs.includes(result.txHash)) entry.redeemTxs.push(result.txHash);
  await put({ status: 'redeemed' });
  return result;
}

/** The vault's claim transport. `send` must submit from the credited recipient's account: only it can claim. */
export interface ClaimTransport {
  send(tx: { to: Uint8Array; data: Uint8Array }): Promise<string>;
  receipt(txHash: string): Promise<'success' | 'reverted' | undefined>;
  /** `claimable(recipient)`: the credited, unclaimed balance. */
  claimable(recipient: Uint8Array): Promise<bigint>;
}

export interface ClaimPolicy {
  receiptTimeoutMs: number;
  pollMs: number;
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
}
export const DEFAULT_CLAIM: ClaimPolicy = { receiptTimeoutMs: 30_000, pollMs: 250 };

/** A claim without a receipt yet. The hash is journalled: calling `claimCredited` again checks it before any new send. */
export class ClaimUnconfirmed extends NativeError {
  public constructor(public readonly txHash: string) {
    super('ErrProofUnavailable', `claim unconfirmed (${txHash}); check the transaction before any resend`);
  }
}

async function waitReceipt(t: ClaimTransport, hash: string, p: ClaimPolicy): Promise<'success' | 'reverted'> {
  const sleep = p.sleep ?? realSleep;
  const now = p.now ?? Date.now;
  const deadline = now() + p.receiptTimeoutMs;
  for (;;) {
    const r = await t.receipt(hash);
    if (r !== undefined) return r;
    if (now() >= deadline) throw new ClaimUnconfirmed(hash);
    await sleep(p.pollMs);
  }
}

/**
 * Claim a redeemed burn's own amount to `to` and settle its entry. The attempt is journalled BEFORE the send and the hash right after it; on the
 * fresh path the entry becomes `settled` only when the receipt is a success AND `claimable` fell by exactly the claimed amount. A hash already
 * journalled is checked first and settles on its receipt alone (a restart no longer has the balance before the claim: `claimableBefore` is then
 * absent). An attempt without a hash (a crash between the mark and the hash) is never repeated automatically: another claim could take the same
 * recipient's other credit. The host looks at the account's transactions and then calls `abandonAttempt`.
 */
export async function claimCredited(
  payments: NativeBridgePayments,
  burnId: string,
  to: Uint8Array,
  vault: Uint8Array,
  transport: ClaimTransport,
  policy: ClaimPolicy = DEFAULT_CLAIM,
): Promise<{ amount: bigint; txHash: string; claimableBefore?: bigint; claimableAfter: bigint }> {
  const entry = await entryOf(payments, burnId);
  if (entry.status === 'settled') throw new Error(`burn ${burnId} is already settled`);
  if (entry.status !== 'redeemed') throw new Error(`burn ${burnId} is ${entry.status}: redeem it before claiming`);
  if (entry.claimStarted && entry.claimTx === undefined) {
    throw new Error(`an earlier claim of burn ${burnId} was started and its hash was not recorded: check the recipient's transactions, then abandonAttempt`);
  }
  if (entry.claimTx !== undefined) {
    // an earlier claim was sent: its receipt decides, nothing is sent again while it may still be pending
    const r = await waitReceipt(transport, entry.claimTx, policy);
    if (r === 'success') {
      await payments.journal.put({ ...entry, status: 'settled' });
      return { amount: entry.amount, txHash: entry.claimTx, claimableAfter: await transport.claimable(entry.releaseTo) };
    }
    entry.claimTx = undefined; // reverted: claim again below
    entry.claimStarted = undefined;
  }
  const before = await transport.claimable(entry.releaseTo);
  if (before < entry.amount) throw new Error(`claimable ${before} is below the redeemed amount ${entry.amount}: nothing to claim (already claimed elsewhere?)`);
  const data = claimCalldata(entry.amount, to, vault);
  await payments.journal.put({ ...entry, claimStarted: true });
  const txHash = await transport.send({ to: vault, data });
  await payments.journal.put({ ...entry, claimStarted: true, claimTx: txHash });
  if ((await waitReceipt(transport, txHash, policy)) !== 'success') throw new Error(`the claim ${txHash} reverted`);
  const after = await transport.claimable(entry.releaseTo);
  if (after !== before - entry.amount) throw new Error(`claimable went ${before} -> ${after}, not down by the claimed ${entry.amount}; the entry stays redeemed with claim ${txHash} recorded`);
  await payments.journal.put({ ...entry, claimStarted: true, claimTx: txHash, status: 'settled' });
  return { amount: entry.amount, txHash, claimableBefore: before, claimableAfter: after };
}

/**
 * The host's decision that a send is dead: it has established (for example by the sender's nonce having been used by another transaction, or the
 * transaction having been replaced) that `redeemTx` never was or never will be mined, or that a claim attempt without a recorded hash did not go
 * out. Nothing is inferred by the plug-in: it only forgets the attempt so the entry can be retried. Wrongly abandoning a transaction that is still
 * pending can pay twice (a second claim) or send a redeem the vault will refuse, so this is for the host's own evidence only.
 */
export async function abandonAttempt(payments: NativeBridgePayments, burnId: string, what: { redeemTx: string } | { claim: true }): Promise<void> {
  const entry = await entryOf(payments, burnId);
  if ('redeemTx' in what) {
    if (!entry.redeemTxs.includes(what.redeemTx)) throw new Error(`burn ${burnId} has no redeem transaction ${what.redeemTx}`);
    await payments.journal.put({ ...entry, redeemTxs: entry.redeemTxs.filter((h) => h !== what.redeemTx) });
    return;
  }
  if (entry.status === 'settled') throw new Error(`burn ${burnId} is already settled`);
  await payments.journal.put({ ...entry, claimStarted: undefined, claimTx: undefined });
}
