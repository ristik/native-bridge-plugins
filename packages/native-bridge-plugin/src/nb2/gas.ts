/**
 * Size and gas bounds of a redemption (sections 12.4 and 12.5). The preflight needs a CONSERVATIVE bound of the complete redeem
 * transaction before the burn exists: its encoded size and its gas limit (expected cost plus `gasReserve`). Replay and settlement are
 * measured (#1098, unicity-pos-contracts#80); the token verifier is not measured yet (NB2-05, #1101). The verifier part is therefore a
 * named, replaceable component: {@link GasModel}. The default {@link ProvisionalGasModel} over-estimates by construction and fails
 * closed (returns null, which the preflight reports as `CapacityPreflight`) for anything it cannot bound. NB2-05's measured schedule
 * replaces it without an API change.
 */
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';

import { gapProofLen } from './segment.js';
import { redeemCalldataLength } from './abi.js';
import type { Token } from './token.js';

/** What the gas model sees of a prospective redemption. */
export interface RedeemShape {
  /** The evidence bytes (`C(1, Token)`), or an upper bound of their length when the burn does not exist yet. */
  evidenceBytes: number;
  /** The decoded token of the lineage walk, root first, when known (counts certificates, signatures and paths). */
  lineage: Token[];
  /** Transactions the evidence will hold that are not in `lineage` yet (the burn about to be made). */
  pendingTransactions: number;
  /** Historical gap proofs. */
  proofs: bigint;
  K: bigint;
}

/** A gas model: the gas limit of a redeem (expected cost plus gasReserve), or null when it cannot be bounded. */
export interface GasModel {
  readonly name: string;
  redeemGasLimit(s: RedeemShape): bigint | null;
  /** The gas limit of a deposit call. */
  depositGasLimit(): bigint;
}

/** Measured by #1098 (K = 64, B = 16, optimizer runs 200): replay and settlement only. */
export const MEASURED = {
  gasReserve: 500_000n,
  previousEndpoint: 78_083n, // the more expensive of the P = 0 endpoints
  perSegment: 5_950n,
  depositFirst: 48_758n,
} as const;

const TX_BASE = 21_000n;
const CALLDATA_NONZERO = 16n;

/**
 * Upper-bound guesses for the unmeasured verifier, from the B1 price schedule (bft-core `b1ref/limits.go`, profile 7) charged for
 * EVERY certificate occurrence as its own call, plus a per-byte charge for parsing and hashing the evidence in Solidity. Each term is
 * chosen above any plausible cost; it is not a measurement.
 */
export const PROVISIONAL = {
  perEvidenceByte: 128n, // CBOR scanning, SHA-256 and keccak over every byte, memory expansion
  perCertificate: 60_000n + 1_100n + 29_900n + 2_000n, // one B1 call per UC: base, common reads, one epoch, one claim
  perCertificateByte: 16n,
  perSignature: 7_200n,
  maxSignatures: 16, // the B1 bound per seal; a UC claiming more cannot be bounded here
  perPathStep: 250n,
  perTransaction: 3_000n + 2_000n + 256n * 250n, // ecrecover, the RSMT membership call, a full-depth path
  receiptProof: 200_000n, // the deposit's EVM UC is counted as a certificate; this covers header, trie and log checks
  /** A pending transaction's own certificate. */
  pendingCertificateBytes: 24_576,
} as const;

export class ProvisionalGasModel implements GasModel {
  public readonly name = 'provisional-nb2-07';

  public redeemGasLimit(s: RedeemShape): bigint | null {
    const p = PROVISIONAL;
    let verifier = p.receiptProof + p.perEvidenceByte * BigInt(s.evidenceBytes);
    let transactions = 0;
    for (const tok of s.lineage) {
      const proofs = [tok.mintProof, ...tok.proofs];
      transactions += proofs.length;
      for (const pr of proofs) {
        const sigs = countSignatures(pr.uc);
        if (sigs === null || sigs > p.maxSignatures) return null;
        verifier += p.perCertificate + p.perCertificateByte * BigInt(pr.uc.length) + p.perSignature * BigInt(sigs) + p.perPathStep * BigInt(pr.siblings.length + 32);
      }
    }
    // the root's EVM UC (inside J) and every pending transaction's future certificate, at the bounds
    const pending = BigInt(s.pendingTransactions);
    verifier += (pending + 1n) * (p.perCertificate + p.perCertificateByte * BigInt(p.pendingCertificateBytes) + p.perSignature * BigInt(p.maxSignatures) + p.perPathStep * 288n);
    verifier += BigInt(transactions + s.pendingTransactions) * p.perTransaction;
    const historyBytes = s.proofs === 0n ? 0 : 32 + Number(s.proofs) * gapProofLen(s.K);
    const calldata = CALLDATA_NONZERO * BigInt(redeemCalldataLength(s.evidenceBytes, historyBytes));
    const settlement = MEASURED.previousEndpoint + MEASURED.perSegment * s.proofs;
    return TX_BASE + calldata + settlement + verifier + MEASURED.gasReserve;
  }

  public depositGasLimit(): bigint {
    return 2n * MEASURED.depositFirst + 50_000n;
  }
}

/** The signature count of a UC's seal, from its full canonical decode; null (fail closed) when the UC does not decode. */
function countSignatures(uc: Uint8Array): number | null {
  try {
    const sigs = UnicityCertificate.fromCBOR(uc).unicitySeal.witnesses;
    return sigs === null ? 0 : sigs.size;
  } catch {
    return null;
  }
}

/** The byte-level count, kept only as a cross-check in tests. */
export function countSignaturesRaw(uc: Uint8Array): number | null {
  // a full decode is the trust layer's; a byte-level count of the signature map is enough for a bound: find the seal tag 39005
  // (d9 985d) and read its 8-array's last item
  for (let i = 0; i + 3 < uc.length; i++) {
    if (uc[i] === 0xd9 && uc[i + 1] === 0x98 && uc[i + 2] === 0x5d && uc[i + 3] === 0x88) {
      try {
        // skip seven items, then read the map head
        let pos = i + 4;
        for (let k = 0; k < 7; k++) pos = skipItem(uc, pos);
        const ib = uc[pos];
        if (ib === 0xf6) return 0;
        if (ib >> 5 !== 5) return null;
        const ai = ib & 0x1f;
        if (ai < 24) return ai;
        if (ai === 24) return uc[pos + 1];
        return null;
      } catch {
        return null;
      }
    }
  }
  return null;
}

function skipItem(b: Uint8Array, pos: number): number {
  if (pos >= b.length) throw new Error('short');
  const ib = b[pos++];
  const major = ib >> 5;
  const ai = ib & 0x1f;
  let arg = 0;
  if (ai < 24) arg = ai;
  else if (ai <= 27) {
    const n = 1 << (ai - 24);
    for (let k = 0; k < n; k++) arg = arg * 256 + b[pos + k];
    pos += n;
  } else throw new Error('indefinite');
  switch (major) {
    case 0: case 1: case 7: return pos;
    case 2: case 3: return pos + arg;
    case 4: for (let k = 0; k < arg; k++) pos = skipItem(b, pos); return pos;
    case 5: for (let k = 0; k < 2 * arg; k++) pos = skipItem(b, pos); return pos;
    case 6: return skipItem(b, pos);
    default: throw new Error('major');
  }
}

/**
 * The encoded size of a signed EIP-1559 redeem transaction around `calldata` bytes: the envelope, nine scalar fields at their widest,
 * the 20-byte target, an empty access list and a 65-byte signature, plus the RLP heads of the data string and the list.
 */
export const redeemTxFraming = (calldata: number): number => 1 + 9 + 9 * 9 + 21 + 1 + 3 * 33 + (calldata >= 56 ? 5 : 1) + 5;
