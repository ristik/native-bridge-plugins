/**
 * Return proof assembly and aggregator refresh.
 *
 * Refresh keeps the original `M/T` (including embedded J), CD and original `t` byte for byte and
 * replaces only the aggregator path and certificate, within the one fixed trust base. Fetching is
 * the host's concern: this module only consumes proofs.
 */
import type { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';

import { preflightToken } from './resources.js';
import { eq, toHex } from './bytes.js';
import { checkAnchors, checkPolicyBody, encodeEnvelope, planAnchors, type Anchor, type Envelope, type LeafProof } from './envelope.js';
import { computeGate, kernelRequestBytes, projectedGate, type Gate } from './gas.js';
import { fail } from './errors.js';
import { projectToken } from './history.js';
import { MAX_ENVELOPE_BYTES, MAX_LEAVES, MAX_SEMANTIC_BYTES, TX_GAS_BUDGET } from './limits.js';
import { parseJustification } from './lockproof.js';
import { H, arr, cfgBytes, policyBytes, shardId, shardRow, u } from './profile.js';
import type { NativeBridge, VerifiedToken } from './verifier.js';

const proofOf = (certified: { inclusionProof: InclusionProof }): InclusionProof => certified.inclusionProof;

/**
 * Replace every aggregator proof of `token` with the freshly fetched proof for the same leaf.
 * `fresh` is ordered like the history, genesis first.
 */
export async function refreshToken(token: Token, fresh: InclusionProof[]): Promise<Token> {
  const old = [proofOf(token.genesis), ...token.transactions.map(proofOf)];
  if (fresh.length !== old.length) fail('ErrRefreshMismatch');
  const certified = [token.genesis, ...token.transactions].map((c, i) => {
    if (!eq(old[i].certificationData.toCBOR(), fresh[i].certificationData.toCBOR()) || old[i].referenceTime !== fresh[i].referenceTime) {
      fail('ErrRefreshMismatch');
    }
    return arr(CborDeserializer.decodeArray(c.toCBOR(), 2)[0], fresh[i].toCBOR());
  });
  const bytes = C.encodeTag(39040, arr(u(2), certified[0], arr(...certified.slice(1))));
  preflightToken(bytes);
  return Token.fromCBOR(bytes);
}

/**
 * Assemble the return envelope from a token whose every aggregator proof carries its own (path, UC)
 * pair. The token is verified in full as a return first.
 *
 * The anchor table is the profile's: one anchor per distinct complete UC (byte-identical UCs are one
 * anchor), in first-use leaf order, each claim derived from its UC and the pinned policy row of its
 * shard. Nothing here re-queries to make certificates converge: the pairs are used as fetched, and an
 * envelope that needs more anchors than the profile bound, or does not fit the shared gas gate, is
 * `ErrPolicyAnchors` or `ErrGasBudget` (BudgetExceeded), never truncated or split.
 */
export async function buildReturnProof(bridge: NativeBridge, token: Token): Promise<{ envelope: Envelope; encoded: Uint8Array; verified: VerifiedToken; gate: Gate }> {
  const verified = await bridge.verifyNativeToken(token, 'return');
  const dep = bridge.registry.deployments[verified.deployment];
  const history = projectToken(token);
  const proofs = [proofOf(token.genesis), ...token.transactions.map(proofOf)];
  const anchors: Anchor[] = [];
  const anchorOf = new Map<string, number>();
  const leafProofs: LeafProof[] = proofs.map((p, i) => {
    const ucBytes = p.unicityCertificate.toCBOR();
    const key = toHex(ucBytes);
    let idx = anchorOf.get(key);
    if (idx === undefined) {
      const row = shardRow(dep.policy, verified.outcome.leaves[i].sid);
      const ir = p.unicityCertificate.inputRecord;
      const irBytes = ir.toCBOR();
      idx = anchors.length;
      anchorOf.set(key, idx);
      anchors.push({
        partition: dep.policy.partition,
        shard: shardId(dep.policy, row),
        shardConfHash: dep.policy.shardConfs[row],
        expectedStateRoot: ir.hash,
        expectedIRHash: H(irBytes),
        uc: ucBytes,
        inputRecord: irBytes,
      });
    }
    const enc = p.inclusionCertificate.encode();
    const siblings: Uint8Array[] = [];
    for (let o = 32; o < enc.length; o += 32) siblings.push(enc.slice(o, o + 32));
    return { anchorIndex: idx, bitmap: enc.slice(0, 32), siblings };
  });
  const envelope: Envelope = { policyBody: policyBytes(dep.policy), history, anchors, leafProofs };
  const encoded = encodeEnvelope(envelope);
  if (encoded.length > MAX_ENVELOPE_BYTES) fail('ErrInputTooLarge');
  // The composing verifier's own checks must pass on what we assembled, in its order: policy opening,
  // anchor table, the shared gas gate, then every anchor's opening and every leaf's own anchor time.
  const sids = verified.outcome.leaves.map((l) => l.sid);
  const pol = checkPolicyBody(dep.cfg, envelope);
  const plan = planAnchors(pol, envelope, sids);
  const gate = computeGate(encoded.length, kernelRequestBytes(cfgBytes(dep.cfg).length, history.length), envelope, pol);
  checkAnchors(envelope, plan, verified.outcome.leaves.map((l) => l.referenceTime));
  return { envelope, encoded, verified, gate };
}

/**
 * A conservative size of the burn leaf's contribution to the history projection (the transfer, its
 * certification data with its unlock script and the terminal return reason).
 */
export const BURN_HISTORY_BYTES = 1024;

/**
 * The burn-time preflight. A burn that could never be redeemed under the profile bounds and the shared
 * gas gate is refused before the wallet burns anything: more leaves than the profile admits, a history or
 * envelope over its bound, or a worst-case envelope over the transaction budget. Beyond the bounds the
 * answer is `ErrGasBudget`/`ErrTooManyTx`/`ErrInputTooLarge` (BudgetExceeded), never a truncated history
 * or a partial redemption. `tokenBytes` is the held receipt the burn would spend.
 */
export async function preflightBurn(bridge: NativeBridge, tokenBytes: Uint8Array): Promise<Gate> {
  preflightToken(tokenBytes);
  const token = await Token.fromCBOR(tokenBytes);
  const j = token.genesis.justification ?? fail('ErrMintJustif');
  const parsed = parseJustification(j);
  const dep = bridge.registry.find(token.genesis.networkId.id, parsed.chainId, parsed.vault);
  const leaves = token.transactions.length + 2; // the mint, every transfer and the burn
  if (leaves > MAX_LEAVES) fail('ErrTooManyTx');
  const history = projectToken(token).length + BURN_HISTORY_BYTES;
  if (history > MAX_SEMANTIC_BYTES) fail('ErrInputTooLarge');
  const { gate, envelopeBytes } = projectedGate(cfgBytes(dep.cfg).length, policyBytes(dep.policy).length, dep.policy.shardConfs.length, leaves, history);
  if (envelopeBytes > MAX_ENVELOPE_BYTES) fail('ErrInputTooLarge');
  if (gate.total > TX_GAS_BUDGET) fail('ErrGasBudget');
  return gate;
}
