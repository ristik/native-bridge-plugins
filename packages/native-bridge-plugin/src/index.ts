// The package root: the primitives shared with the native bridge v2 wallet plug-in (`./nb2`, protocol 9). The protocol 7 plug-in
// (lock proofs, per-part nullifiers, the claim step) was removed with that bridge (bft-core#1106).
export * from './bytes.js';
export * from './errors.js';
export * from './trust.js';
export * from './trustrefresh.js';
