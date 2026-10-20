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
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import type { Deployment } from './deployment.js';
import { H, arr, cfgBytes, policyBytes, u } from './profile.js';
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
 * anchor), in first-use leaf order, each claim read from its own UC (its shard, shard configuration
 * hash and partition: the policy names only the partition, and the UC authenticates the rest). Nothing
 * here re-queries to make certificates converge: the pairs are used as fetched, and an envelope that
 * needs more anchors than the profile bound, or does not fit the shared gas gate, is `ErrTooManyPaths`
 * or `ErrGasBudget` (BudgetExceeded), never truncated or split.
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
      const ir = p.unicityCertificate.inputRecord;
      const irBytes = ir.toCBOR();
      idx = anchors.length;
      anchorOf.set(key, idx);
      anchors.push({
        partition: Number(p.unicityCertificate.unicityTreeCertificate.partitionIdentifier),
        shard: p.unicityCertificate.shardTreeCertificate.shard.encode(),
        shardConfHash: p.unicityCertificate.shardConfigurationHash,
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
  const gate = computeGate(cfgBytes(dep.cfg), encoded.length, kernelRequestBytes(cfgBytes(dep.cfg).length, history.length), envelope);
  checkAnchors(envelope, plan, verified.outcome.leaves.map((l) => l.referenceTime));
  return { envelope, encoded, verified, gate };
}

/**
 * An upper bound on the size of the burn leaf's contribution to the history projection (the transfer, its
 * certification data with its unlock script and the terminal return reason).
 */
export const BURN_HISTORY_BYTES = 1024;

/**
 * The burn-time preflight. A burn that could never be redeemed under the profile bounds and the shared
 * gas gate is refused before the wallet burns anything: more leaves than the profile admits, a history or
 * envelope over its bound, or an envelope that cannot pass the gas gate (`txGasBudget`) even in the best case. Beyond the bounds the
 * answer is `ErrGasBudget`/`ErrTooManyTx`/`ErrInputTooLarge` (BudgetExceeded), never a truncated history
 * or a partial redemption. `tokenBytes` is the held receipt the burn would spend.
 */
export async function preflightBurn(bridge: NativeBridge, tokenBytes: Uint8Array, shards = 1): Promise<Gate> {
  preflightToken(tokenBytes);
  const token = await Token.fromCBOR(tokenBytes);
  const dep = deploymentOf(bridge, token);
  const leaves = token.transactions.length + 2; // the mint, every transfer and the burn
  if (leaves > MAX_LEAVES) fail('ErrTooManyTx');
  // the best case is the fewest anchors under one seal: one per aggregator shard the leaves touch (`shards`, from the host's routing
  // of `leafStateIds`; 1 when unknown, since a single certificate may serve every leaf). It is a lower bound, not a promise: over 8
  // shards the consolidated bundle is not reachable, yet K = min(m, L) under one seal stays the best case there, since per-SID
  // certificates may share a seal by chance. It holds only while the topology does not merge: the redemption comes later, and a
  // shard merge before it lowers the anchors the leaves need, so a host that may see a merge passes the merged count (or 1);
  // over-counting `shards` could refuse a burn that would pass
  return checkBurnProjection(cfgBytes(dep.cfg).length, policyBytes(dep.policy).length, leaves, projectToken(token).length, Math.min(shards, leaves));
}

/**
 * The size and gate refusals of the preflight, on the projection's inputs. The history bound is hard and
 * no refresh can fix it, so it errs safe: the burn leaf is assumed to add up to `BURN_HISTORY_BYTES`. The
 * gate projection uses the known history only, a lower bound. The envelope bound cannot fire at the
 * best-case sizes (about 22 KB at the largest admitted shape against 65,536), so it is kept as a guard
 * only.
 */
export function checkBurnProjection(cfgLen: number, policyLen: number, leaves: number, history: number, anchors = 1): Gate {
  if (history + BURN_HISTORY_BYTES > MAX_SEMANTIC_BYTES) fail('ErrInputTooLarge');
  const { gate, envelopeBytes } = projectedGate(cfgLen, policyLen, leaves, history, anchors);
  if (envelopeBytes > MAX_ENVELOPE_BYTES) fail('ErrInputTooLarge');
  if (gate.total > TX_GAS_BUDGET) fail('ErrGasBudget');
  return gate;
}

function deploymentOf(bridge: NativeBridge, token: Token): Deployment {
  const j = token.genesis.justification ?? fail('ErrMintJustif');
  const parsed = parseJustification(j);
  return bridge.registry.find(token.genesis.networkId.id, parsed.chainId, parsed.vault);
}

/** The raw 32-byte state ID of every history leaf (genesis first): what `get_inclusion_proof.v2` is asked for. */
export async function leafStateIds(token: Token): Promise<Uint8Array[]> {
  const all = [token.genesis, ...token.transactions];
  return Promise.all(all.map(async (c) => (await StateId.fromCertificationData(c.inclusionProof.certificationData)).data));
}
