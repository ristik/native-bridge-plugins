/** The bridge tester's offline parts: its configuration, the vault's ABI, amounts and the token-file append. Nothing here touches the network. */
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { CborDeserializer as D } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { arr, keccak256 } from '../packages/native-bridge-plugin/src/profile.js';
import { hex, unhex } from '../tests/live/lib.js';

/** What an operator publishes for testers (the testnet package writes it as GENERATION/bridge/tester-config.json). Files are relative to the config. */
export interface TesterConfig {
  /** the public JSON-RPC endpoint (the package's gateway) */
  ethUrl: string;
  /** where redemptions are sent, when ethUrl cannot take them (a redeem carries the whole return proof; the package's gateway takes 16 KiB bodies) */
  redeemEthUrl?: string;
  /** the aggregator's JSON-RPC endpoint */
  aggUrl: string;
  /** the lock-proof endpoint (dnb-tool lockproof-serve): GET /v1/lockproof?block=..&nonce=.. */
  lockProofUrl: string;
  chainId: number;
  vault: string;
  /** the trust-base release bundle, its genesis entry id, the EVM shard's PDR and the bridge deployment document (policyBody) */
  files: { trustBundle: string; trustEntryId: string; evmPdr: string; deployment: string };
}

const isUrl = (s: unknown): s is string => typeof s === 'string' && /^https?:\/\/\S+$/.test(s);
export const isAddress = (s: unknown): s is string => typeof s === 'string' && /^0x[0-9a-fA-F]{40}$/.test(s);

/** The configuration, every field checked, with its files resolved against the configuration's directory. */
export function loadTesterConfig(path: string): TesterConfig {
  const c = JSON.parse(readFileSync(path, 'utf8')) as TesterConfig;
  const bad = (what: string): never => {
    throw new Error(`${path}: ${what}`);
  };
  for (const k of ['ethUrl', 'aggUrl', 'lockProofUrl'] as const) if (!isUrl(c[k])) bad(`${k} must be an http(s) URL`);
  if (c.redeemEthUrl !== undefined && !isUrl(c.redeemEthUrl)) bad('redeemEthUrl must be an http(s) URL');
  if (!Number.isSafeInteger(c.chainId) || c.chainId <= 0) bad('chainId must be a positive integer');
  if (!isAddress(c.vault)) bad('vault must be a 0x address');
  const dir = dirname(resolve(path));
  const files = c.files ?? bad('files is missing');
  for (const k of ['trustBundle', 'trustEntryId', 'evmPdr', 'deployment'] as const) {
    if (typeof files[k] !== 'string' || files[k] === '') bad(`files.${k} is missing`);
    files[k] = resolve(dir, files[k]);
  }
  return c;
}

// ---- the vault's ABI (only what the tester calls) ---------------------------------------------------------------------------------------------
const word = (n: bigint): string => n.toString(16).padStart(64, '0');
export const selector = (signature: string): string => hex(keccak256(new TextEncoder().encode(signature)).subarray(0, 4));
export const encUint = (n: bigint): string => word(n);
export const encAddress = (a: string): string => {
  if (!isAddress(a)) throw new Error(`not an address: ${a}`);
  return a.slice(2).toLowerCase().padStart(64, '0');
};
/** abi.encode of one `bytes` argument (offset, length, the bytes padded to 32) */
export const encBytes = (b: Uint8Array): string => word(32n) + word(BigInt(b.length)) + hex(b) + '00'.repeat((32 - (b.length % 32)) % 32);
export const calldata = (signature: string, ...words: string[]): string => `0x${selector(signature)}${words.join('')}`;
/** the returned `bytes` of a call whose only output is `bytes` */
export function decBytes(ret: string): Uint8Array {
  const b = unhex(ret);
  const offset = Number(BigInt(`0x${hex(b.subarray(0, 32))}`));
  const len = Number(BigInt(`0x${hex(b.subarray(offset, offset + 32))}`));
  if (offset + 32 + len > b.length) throw new Error('the returned bytes are truncated');
  return b.subarray(offset + 32, offset + 32 + len);
}
/** The EVM address of a secp256k1 secret key. */
export const ethAddress = (key: string): string => `0x${hex(keccak256(secp256k1.getPublicKey(unhex(key), false).subarray(1)).subarray(12))}`;
export const LOCKED_TOPIC = `0x${hex(keccak256(new TextEncoder().encode('Locked(uint256,address,bytes32,address,bytes32,bytes32,uint256,bytes32,bytes32,bytes32,bytes)')))}`;

// ---- amounts ------------------------------------------------------------------------------------------------------------------------------------
/** The profile carries a token's amount as 8 bytes: one lock is at most 2^64 - 1 wei (about 18.4 ETH). */
export const MAX_LOCK_WEI = (1n << 64n) - 1n;

/** `1.5` (ether) or `1500000000000000000wei` to wei; refuses zero, more than 18 decimals and more than one lock can carry. */
export function parseAmount(s: string): bigint {
  let wei: bigint;
  const m = /^(\d+)wei$/.exec(s);
  if (m) wei = BigInt(m[1]);
  else {
    const e = /^(\d+)(?:\.(\d{1,18}))?$/.exec(s);
    if (!e) throw new Error(`not an amount: ${s} (ether, e.g. 0.5, or wei, e.g. 500000000000000000wei)`);
    wei = BigInt(e[1]) * 10n ** 18n + BigInt((e[2] ?? '').padEnd(18, '0'));
  }
  if (wei === 0n) throw new Error('the amount must be more than zero');
  if (wei > MAX_LOCK_WEI) throw new Error(`one lock carries at most ${MAX_LOCK_WEI} wei (the amount is 8 bytes in the token)`);
  return wei;
}
/** The token's amount bytes: minimal big-endian, no leading zero (interop.md "Canonical primitives"; 1 to 8 bytes for a lock). */
export const amountBytes = (wei: bigint): Uint8Array => {
  if (wei <= 0n) throw new Error('the amount must be more than zero');
  const h = wei.toString(16);
  return unhex(h.length % 2 ? `0${h}` : h);
};

// ---- the token file -----------------------------------------------------------------------------------------------------------------------------
const TOKEN_TAG = 39040n;
/** A token file with one more certified transaction [tx, proof] after its last one. */
export function appendTransaction(tokenBytes: Uint8Array, tx: Uint8Array, proof: Uint8Array): Uint8Array {
  const tagged = D.decodeTag(tokenBytes);
  if (tagged.tag !== TOKEN_TAG) throw new Error(`not a token (CBOR tag ${tagged.tag})`);
  const [version, genesis, txs] = D.decodeArray(tagged.data, 3);
  return C.encodeTag(TOKEN_TAG, arr(version, genesis, arr(...D.decodeArray(txs), arr(tx, proof))));
}

// ---- the wallet's token records -----------------------------------------------------------------------------------------------------------------
export type Phase = 'locked' | 'minted' | 'split' | 'burned' | 'redeemed';
export interface TokenRecord {
  /** the record's name: the lock nonce for the token minted from the lock, `<parent>.<n>` for the n-th part of a split (absent: the nonce) */
  id?: string;
  /** the ROOT lock's nonce (a part redeems against it) */
  nonce: string;
  /** this token's whole amount (a part's own) */
  amountWei: string;
  phase: Phase;
  lockTx: string;
  lockBlockHash: string;
  /** index into the wallet's Unicity keys of the current owner */
  holder: number;
  transfers: number;
  /** the EVM address the burn names (credited by the redemption) */
  recipient?: string;
  redeemTx?: string;
  /** a part's parent record; a split token's parts */
  parent?: string;
  parts?: string[];
}
/** The name a record is selected by (`--token`) and stored under. */
export const recordId = (t: TokenRecord): string => t.id ?? t.nonce;
/** A record name: a nonce, then one `.n` per split level. */
export const RECORD_ID = /^\d+(\.\d+)*$/;
const ORDER: Phase[] = ['locked', 'minted', 'burned', 'redeemed'];
/** Refuses a step out of order, with what to run instead. */
export function requirePhase(t: TokenRecord, want: Phase, step: string): void {
  if (t.phase === want) return;
  if (t.phase === 'split') throw new Error(`token ${recordId(t)} was split: ${step} one of its parts (--token ${(t.parts ?? []).join(' | --token ')})`);
  const next: Record<Phase, string> = { locked: 'mint', minted: 'transfer, split or burn', split: 'its parts', burned: 'redeem', redeemed: 'claim' };
  const ahead = ORDER.indexOf(t.phase) > ORDER.indexOf(want);
  throw new Error(`token ${recordId(t)} is ${t.phase}: ${step} needs it ${want}${ahead ? ' (that step is done)' : ''}; next: ${next[t.phase]}`);
}

/** `--amounts a,b,...`: at least two positive amounts (each as `parseAmount`) that add up to exactly the token's amount. */
export function splitAmounts(text: string, totalWei: bigint): bigint[] {
  const parts = text.split(',').map((x) => parseAmount(x.trim()));
  if (parts.length < 2) throw new Error('--amounts needs at least two amounts, comma separated');
  const sum = parts.reduce((a, b) => a + b, 0n);
  if (sum !== totalWei) throw new Error(`--amounts add up to ${sum} wei, the token holds ${totalWei} wei`);
  return parts;
}
