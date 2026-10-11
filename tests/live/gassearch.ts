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
