/**
 * The verdict on a conflicting certification request, read only once the aggregator has had the chance to act on it. A read right after the
 * submission says nothing: the request may still be queued for the next block. So, after the submission, a sentinel (a fresh mint of a throwaway
 * key, submitted after the conflict) must be certified and the block height of the conflict's aggregator must be at least two past the one current
 * at the submission; only then the proof served for the state is read again and compared with the first read. Shared by the tester (`replays`) and
 * the live driver (`negatives`).
 */
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { hex, sleep } from './lib.js';

/** What was waited for, as recorded next to the verdict. */
export interface ConflictWait {
  readonly what: string;
  readonly submittedAtBlock: bigint;
  readonly sentinelStateId: string;
  readonly sentinelBlock: bigint;
  readonly settledAtBlock: bigint;
  readonly firstRead: { readonly blockNumber: bigint; readonly transactionHash: string };
  readonly reRead: { readonly blockNumber: bigint; readonly transactionHash: string; readonly sameProof: boolean };
}

async function poll<T>(what: string, timeoutMs: number, everyMs: number, f: () => Promise<T | undefined>): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(everyMs);
  }
}

/**
 * Submit `conflict` for `stateId` (whose certified proof already exists), then wait as the module comment says and return the proof served after
 * the wait, the submission's answer (recorded, not asserted: a server may queue it, refuse it, or fail the call) and what was waited for. Throws if
 * the state has no proof, or if the certified transaction differs between the read right after the submission and the read after the wait.
 *
 * @param clientOf the aggregator of a state (the conflict's and the sentinel's may differ on a sharded network)
 */
export async function servedAfterConflict(
  clientOf: (sid: StateId) => AggregatorClient,
  stateId: StateId,
  conflict: CertificationData,
  network: number,
  { timeoutMs = 180_000 }: { timeoutMs?: number } = {},
): Promise<{ submission: string; served: InclusionProof; waited: ConflictWait }> {
  const agg = clientOf(stateId);
  const submission = await agg.submitCertificationRequest(conflict).then((r) => String(r.status), (e: unknown) => `error: ${String(e).slice(0, 200)}`);
  const submittedAtBlock = await agg.getLatestBlockNumber();
  const read = async () => {
    const r = await agg.getInclusionProof(stateId);
    if (!r.inclusionProof) throw new Error('the aggregator serves no proof for the state');
    return { blockNumber: r.blockNumber, proof: r.inclusionProof };
  };
  const first = await read();

  const sentinelCd = await CertificationData.fromMintTransaction(await MintTransaction.create(NetworkId.fromId(network), SignaturePredicate.create(SigningService.generate().publicKey)));
  const sentinelSid = await StateId.fromCertificationData(sentinelCd);
  const sentinelAgg = clientOf(sentinelSid);
  await sentinelAgg.submitCertificationRequest(sentinelCd);
  const sentinelBlock = await poll('the sentinel submitted after the conflict to be certified', timeoutMs, 2000, async () => {
    const r = await sentinelAgg.getInclusionProof(sentinelSid);
    return r.inclusionProof ? r.blockNumber : undefined;
  });
  const settledAtBlock = await poll(`the aggregator to reach block ${submittedAtBlock + 2n}`, timeoutMs, 1000, async () => {
    const h = await agg.getLatestBlockNumber();
    return h >= submittedAtBlock + 2n ? h : undefined;
  });
  const after = await read();
  // the certificate may be a newer one on the re-read; the certified transaction must not change
  if (hex(after.proof.certificationData.toCBOR()) !== hex(first.proof.certificationData.toCBOR())) {
    throw new Error('the state\'s certified transaction changed after the conflicting submission');
  }
  return {
    submission,
    served: after.proof,
    waited: {
      what: 'a sentinel mint submitted after the conflict certified, and the aggregator\'s block height at least two past the one at the submission',
      submittedAtBlock, sentinelStateId: hex(sentinelSid.data), sentinelBlock, settledAtBlock,
      firstRead: { blockNumber: first.blockNumber, transactionHash: hex(first.proof.certificationData.transactionHash.data) },
      reRead: { blockNumber: after.blockNumber, transactionHash: hex(after.proof.certificationData.transactionHash.data), sameProof: hex(after.proof.toCBOR()) === hex(first.proof.toCBOR()) },
    },
  };
}
