export * from './bytes.js';
export * from './errors.js';
export * from './limits.js';
export * from './profile.js';
export * from './deployment.js';
export * from './envelope.js';
export * from './gas.js';
export * from './header.js';
export * from './history.js';
export * from './lockproof.js';
export * from './manifest.js';
export * from './proof.js';
export * from './trust.js';
export * from './unlock.js';
export * from './verifier.js';
export * from './wallet.js';
export { verifyProof as verifyMptProof } from './mpt.js';
export { decode as rlpDecode, encodeBytes as rlpEncodeBytes, encodeList as rlpEncodeList } from './rlp.js';
export { scanOne, pdrElements } from './scan.js';

import { NativeBridge, type Expect, type VerifiedToken } from './verifier.js';

/** The facade entry point: verify a serialized native token fully offline. */
export function verifyNativeToken(bridge: NativeBridge, bytes: Uint8Array, expect: Expect = 'receipt'): Promise<VerifiedToken> {
  return bridge.verifyNativeTokenBytes(bytes, expect);
}

/** `bridgeTokenPlugin`: the SDK registrations for one bridge (genesis hooks only; see wallet gate). */
export function bridgeTokenPlugin(bridge: NativeBridge, revision = 'native-bridge/0.1.0'): import('@unicitylabs/bridge-core').WalletTokenPlugin {
  return createNativeBridgePluginInternal(bridge, revision);
}

import { createNativeBridgePlugin } from './wallet.js';
function createNativeBridgePluginInternal(bridge: NativeBridge, revision: string): import('@unicitylabs/bridge-core').WalletTokenPlugin {
  return createNativeBridgePlugin(bridge, { manifestRevision: revision, profileRevision: 'v3' }).walletPlugin;
}
