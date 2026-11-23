import assert from 'node:assert/strict';
import { UnicityCertificate } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicityCertificate.js';
import { UnicitySeal } from '@unicitylabs/state-transition-sdk/lib/api/bft/UnicitySeal.js';
import { array, cArr, cBytes, cTag, cUint, raw, scanNative, tagContent } from '../../src/nb2/cbor.js';
import { TAG } from '../../src/nb2/config.js';
import { decodeUc } from '../../src/nb2/trust.js';
import type { Root } from './world.js';

export async function withoutQuorum(proof: Uint8Array, root: Root, future: boolean): Promise<Uint8Array> {
  const fields = array(tagContent(scanNative(proof), TAG.inclusion), 5);
  const uc = decodeUc(raw(proof, fields[4]));
  const old = uc.unicitySeal;
  const round = future ? root.trust.origin!.rootRound + 100n : old.rootChainRoundNumber;
  const seal = await UnicitySeal.create(old.networkId, round, old.epoch, old.timestamp,
    old.previousHash, old.hash, new Map(root.signers.slice(0, 1)));
  const candidate = new UnicityCertificate(uc.inputRecord, uc.technicalRecordHash, uc.shardConfigurationHash,
    uc.shardTreeCertificate, uc.unicityTreeCertificate, seal);
  return cTag(TAG.inclusion, cArr(...fields.slice(0, 4).map((field) => raw(proof, field)), candidate.toCBOR()));
}

/** Exact outer framing and request binding, with deliberately invalid inner proof data. */
export function framedProof(request: Uint8Array, length: number): Uint8Array {
  const frame = (n: number) => cTag(TAG.inclusion, cArr(cUint(1), request, cUint(0), cBytes(new Uint8Array(31)), cBytes(new Uint8Array(n))));
  const padded = frame(32_768);
  const proof = frame(32_768 + length - padded.length);
  assert.equal(proof.length, length);
  return proof;
}
