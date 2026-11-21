/**
 * Native bridge v2 (protocol 10) wallet plug-in: `@unicitylabs/native-bridge-plugin/nb2`. The high-level API is {@link NativeBridgeV2};
 * the pure verifier, the segment and gap-proof functions, the journal format and the RPC adapters are exported for wallets that compose
 * their own flow. The package root holds only the shared bytes, errors and trust input (the protocol 7 plug-in was removed, bft-core#1106).
 */
export * from './errors.js';
export * from './config.js';
export * from './bridge.js';
export * from './journal.js';
export * from './gas.js';
export * from './evm.js';
export * from './rpc.js';
export * from './tokenops.js';
export * from './aggregator.js';
export * from './abi.js';
export { verifyReturn, verifyHeld, verifyPart, verifySplit, decodeEvidence, evidenceOf, encodeReturnData, decodeReturnData, verdictAbi, burnTransitionId, redemptionId, rsmtMember, type Verdict, type Held, type ReturnData } from './verify.js';
export { verifySealReceipt, burnIndex, maxProofs, capacityPreflight, capacityExceeded, checkStateRead, checkCompanion, type SealReceipt, type Preflight } from './rules.js';
export { GapTree, gapRoot, foldHistory, genesisHead, nextHead, checkSegmentLog, buildHistory, encodeHistory, bucketOf, gapProofLen, type Segment } from './segment.js';
export {
  TOPIC, depositIntentSecret, rhoOf, depositSalt, firstOwnerOf, decodeReceiptBacking, encodeReceiptBacking, decodeDepositProof, encodeDepositProof,
  verifyDepositEvidence, verifyReceiptLog, type DepositProof, type ReceiptBacking,
} from './deposit.js';
export { decodeToken, encodeToken, type Token, type LineageLevel } from './token.js';
export { TrustInput, verifyEvmUc } from './trust.js';
export { VaultModel } from './vaultmodel.js';
export { parentLink, splitOutputCommitment, decodeSplitJustification, decodeSumProof, type SumStep } from './split.js';
