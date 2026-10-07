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

import { eq } from './bytes.js';
import { checkAnchor, checkPolicy, encodeEnvelope, type Anchor, type Envelope, type LeafProof } from './envelope.js';
import { fail } from './errors.js';
import { projectToken } from './history.js';
import { MAX_ENVELOPE_BYTES } from './limits.js';
import { EMPTY_PREFIX_SHARD, H, arr, policyBytes, u } from './profile.js';
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
  return Token.fromCBOR(C.encodeTag(39040, arr(u(2), certified[0], arr(...certified.slice(1)))));
}

/**
 * Assemble the return envelope from a token whose every aggregator proof is anchored at one
 * unicity certificate. The token is verified in full as a return first.
 */
export async function buildReturnProof(bridge: NativeBridge, token: Token): Promise<{ envelope: Envelope; encoded: Uint8Array; verified: VerifiedToken }> {
  const verified = await bridge.verifyNativeToken(token, 'return');
  const dep = bridge.registry.deployments[verified.deployment];
  const history = projectToken(token);
  const proofs = [proofOf(token.genesis), ...token.transactions.map(proofOf)];
  const ucBytes = proofs[0].unicityCertificate.toCBOR();
  if (proofs.some((p) => !eq(p.unicityCertificate.toCBOR(), ucBytes))) fail('ErrPolicyAnchors');
  const ir = proofs[0].unicityCertificate.inputRecord;
  const irBytes = ir.toCBOR();
  const anchor: Anchor = {
    partition: dep.policy.partition,
    shard: EMPTY_PREFIX_SHARD,
    shardConfHash: dep.policy.shardConf,
    expectedStateRoot: ir.hash,
    expectedIRHash: H(irBytes),
    uc: ucBytes,
    inputRecord: irBytes,
  };
  const leafProofs: LeafProof[] = proofs.map((p) => {
    const enc = p.inclusionCertificate.encode();
    const siblings: Uint8Array[] = [];
    for (let o = 32; o < enc.length; o += 32) siblings.push(enc.slice(o, o + 32));
    return { anchorIndex: 0, bitmap: enc.slice(0, 32), siblings };
  });
  const envelope: Envelope = { policyBody: policyBytes(dep.policy), history, anchors: [anchor], leafProofs };
  const encoded = encodeEnvelope(envelope);
  if (encoded.length > MAX_ENVELOPE_BYTES) fail('ErrInputTooLarge');
  // The composing verifier's own tuple and opening checks must pass on what we assembled.
  checkPolicy(dep.cfg, envelope, proofs.length);
  checkAnchor(anchor, verified.outcome.leaves.map((l) => l.referenceTime));
  return { envelope, encoded, verified };
}
