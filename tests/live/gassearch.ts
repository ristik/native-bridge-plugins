/**
 * The least gas limit at which a call succeeds, by bisection on a predicate. `eth_estimateGas` is not it: reth stops its own search once the range
 * is under 1.5% of the upper bound and returns the upper bound. `succeeds(g)` must be monotone (true from some M upward). `lo` must fail and `hi`
 * must succeed; the result M has `succeeds(M)` and `!succeeds(M - 1)`.
 */
export async function minimalGas(lo: bigint, hi: bigint, succeeds: (gas: bigint) => Promise<boolean>): Promise<{ min: bigint; calls: number }> {
  let calls = 0;
  const probe = async (g: bigint): Promise<boolean> => { calls++; return succeeds(g); };
  if (!(lo < hi)) throw new Error(`gas search: lo ${lo} is not below hi ${hi}`);
  if (await probe(lo)) throw new Error(`gas search: the lower bound ${lo} already succeeds`);
  if (!(await probe(hi))) throw new Error(`gas search: the upper bound ${hi} does not succeed`);
  while (hi - lo > 1n) {
    const mid = lo + (hi - lo) / 2n;
    if (await probe(mid)) hi = mid; else lo = mid;
  }
  return { min: hi, calls };
}

export interface GasOneFacts {
  /** the low send (limit M-1) */
  lowStatus: string; lowAnchorsInWindowAtExecution: boolean; creditedLow: bigint;
  /** read-only, same calldata, clock override and pinned block: M succeeds and M-1 fails */
  mSucceeds: boolean; mMinusOneFails: boolean;
  /** the same token's refetched proofs at M + headroom */
  highStatus: string; creditedHigh: bigint; amount: bigint;
}
/**
 * The gas-1 row's claim: with every anchor inside the window at its execution block, the redemption fails below the minimum limit M and
 * succeeds at M plus headroom. A failing send does not have to consume its whole limit: under the 63/64 rule an inner (native or RSMT) call is the
 * starved frame, its caller reverts and the unused gas of the outer frame is returned, so `gasUsed < limit` is expected and is recorded, not asserted.
 */
export const gasOneHolds = (f: GasOneFacts): boolean =>
  f.lowStatus === '0x0' && f.lowAnchorsInWindowAtExecution && f.creditedLow === 0n && f.mSucceeds && f.mMinusOneFails && f.highStatus === '0x1' && f.creditedHigh === f.amount;
