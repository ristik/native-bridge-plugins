/** Deposit, mint reason and deposit proof (sections 5 and 6; bft-core `nb2ref/deposit.go`). */
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { concat, eq } from '../bytes.js';
import { MAJ_ARRAY, array, ascii, bstr, bytesN, cArr, cBytes, cTag, cUint, scanBoundedArray, tagContent, u256, uintIn, version, type Item } from './cbor.js';
import { DOMAIN, MAX_DEPOSIT, MAX_INDEX, TAG, V2_VERSION, type Config } from './config.js';
import { HE, HU } from './crypto.js';
import { fail } from './errors.js';
import { bindHeader, decodeHeader, type Header } from './header.js';
import { MptError, mptVerify } from './mpt.js';
import { rlpDecode, rlpIndexKey, rlpUint, type RlpItem } from './rlp.js';
import { encodePredicate, valueData, type MintTx } from './token.js';
import { verifyEvmUc, type TrustInput } from './trust.js';

/** Profile bounds of the deposit evidence (`profile.json` `limits`), checked before any cryptography. */
export const LIMITS = {
  justificationBytes: 65536, ucBytes: 16384, headerBytes: 2048, receiptNodes: 65, receiptBranchNodeBytes: 1024, receiptLeafNodeBytes: 49152,
} as const;
export const FIRST_OWNER_BYTES = 42;

export const TAG_DEPOSIT_SECRET = HE(ascii('UNICITY_NB2_DEPOSIT_SECRET'));
export const TAG_ARCHIVE_GENESIS = HE(ascii('UNICITY_NB2_ARCHIVE_GENESIS'));
export const TAG_ARCHIVE_STEP = HE(ascii('UNICITY_NB2_ARCHIVE_STEP'));

export const TOPIC = {
  Deposited: HE(ascii('Deposited(uint64,bytes32,uint256,bytes32,bytes)')),
  ERC20Deposited: HE(ascii('ERC20Deposited(uint64,address,bytes32,uint256,bytes32,bytes)')),
  ERC20Activated: HE(ascii('ERC20Activated(address,address,address,bytes32,bytes32,bytes32)')),
  Paid: HE(ascii('Paid(bytes32,address,uint256)')),
  SegmentSealed: HE(ascii('SegmentSealed(uint64,bytes32,bytes32,bytes)')),
} as const;

export const depositTopic = (token?: Uint8Array) => token ? TOPIC.ERC20Deposited : TOPIC.Deposited;

export function depositTopics(topics: Uint8Array[], token?: Uint8Array): boolean {
  return topics.length === (token ? 3 : 2) && eq(topics[0], depositTopic(token))
    && (!token || eq(topics[2], concat(new Uint8Array(12), token)));
}

/** r = HMAC-SHA256(key = k_w, msg = C(b("UNICITY_NB2_DEPOSIT_INTENT"), b(D), i)). */
export const depositIntentSecret = (kw: Uint8Array, d: Uint8Array, i: bigint): Uint8Array =>
  hmac(sha256, kw, cArr(cBytes(ascii(DOMAIN.depositIntent)), cBytes(d), cUint(i)));
/** rho = H_E(DEPOSIT_SECRET || D || r). */
export const rhoOf = (d: Uint8Array, r: Uint8Array): Uint8Array => HE(TAG_DEPOSIT_SECRET, d, r);
/** salt_n = H_U(C(b("UNICITY_NB2_DEPOSIT_SALT"), b(D), n, b(r))). */
export const depositSalt = (d: Uint8Array, n: bigint, r: Uint8Array): Uint8Array =>
  HU(cArr(cBytes(ascii(DOMAIN.depositSalt)), cBytes(d), cUint(n), cBytes(r)));

/** The 9-byte head of the 42-byte first owner tag(39032, [1, b(0x01), b(key33)]). */
export const FIRST_OWNER_PREFIX = Uint8Array.of(0xd9, 0x98, 0x78, 0x83, 0x01, 0x41, 0x01, 0x58, 0x21);
export const firstOwnerOf = (key33: Uint8Array): Uint8Array => concat(FIRST_OWNER_PREFIX, key33);

/** DepositProof = [1, b(evmUC), b(headerRLP), txIndex, logIndex, [b(receiptNodeRLP), ...]], also the seal receipt container. */
export interface DepositProof { uc: Uint8Array; header: Uint8Array; txIndex: bigint; logIndex: bigint; nodes: Uint8Array[] }

export const encodeDepositProof = (p: DepositProof): Uint8Array =>
  cArr(cUint(V2_VERSION), cBytes(p.uc), cBytes(p.header), cUint(p.txIndex), cUint(p.logIndex), cArr(...p.nodes.map(cBytes)));

/** J = tag(39051, [1, b(D), n, b(r), DepositProof]). */
export interface ReceiptBacking { d: Uint8Array; n: bigint; r: Uint8Array; proof: DepositProof }

export const encodeReceiptBacking = (j: ReceiptBacking): Uint8Array =>
  cTag(TAG.receiptBacking, cArr(cUint(V2_VERSION), cBytes(j.d), cUint(j.n), cBytes(j.r), encodeDepositProof(j.proof)));

export function decodeReceiptBacking(b: Uint8Array): ReceiptBacking {
  if (b.length > LIMITS.justificationBytes) fail('InputTooLarge');
  const k = array(tagContent(scanBoundedArray(b, [0, 4, 5], LIMITS.receiptNodes, 'InputTooLarge'), TAG.receiptBacking), 5);
  version(k[0], V2_VERSION);
  const d = bytesN(k[1], 32);
  const n = uintIn(k[2], 1n, MAX_DEPOSIT);
  const r = bytesN(k[3], 32);
  return { d, n, r, proof: decodeDepositProofItem(k[4]) };
}

/** A standalone DepositProof container (a seal receipt). */
export function decodeDepositProof(b: Uint8Array): DepositProof {
  if (b.length > LIMITS.justificationBytes) fail('InputTooLarge');
  if (b.length !== 0 && b[0] >> 5 !== MAJ_ARRAY) fail('Shape');
  return decodeDepositProofItem(scanBoundedArray(b, [5], LIMITS.receiptNodes, 'InputTooLarge'));
}

function decodeDepositProofItem(it: Item): DepositProof {
  const k = array(it, 6);
  version(k[0], V2_VERSION);
  const blob = (x: Item, max: number): Uint8Array => {
    const v = bstr(x);
    if (v.length > max) fail('InputTooLarge');
    return v;
  };
  const uc = blob(k[1], LIMITS.ucBytes);
  const header = blob(k[2], LIMITS.headerBytes);
  const txIndex = uintIn(k[3], 0n, MAX_INDEX);
  const logIndex = uintIn(k[4], 0n, MAX_INDEX);
  if (k[5].major !== 4) fail('Shape');
  const nodes = k[5].kids.map((x, i) => blob(x, i === k[5].kids.length - 1 ? LIMITS.receiptLeafNodeBytes : LIMITS.receiptBranchNodeBytes));
  return { uc, header, txIndex, logIndex, nodes };
}

export interface ReceiptLog { address: Uint8Array; topics: Uint8Array[]; data: Uint8Array; header: Header }

/** A legacy receipt or type || RLP(...) with type 1..3 (`ReceiptType`), status 1 (`ReceiptStatus`); the logs list. */
function decodeReceipt(v: Uint8Array): RlpItem {
  if (v.length === 0) fail('ReceiptType');
  let body = v;
  if (v[0] < 0xc0) {
    if (v[0] < 1 || v[0] > 3) fail('ReceiptType');
    body = v.subarray(1);
  }
  let it: RlpItem;
  try {
    it = rlpDecode(body);
  } catch {
    return fail('ReceiptType');
  }
  if (!it.list || it.kids.length !== 4) fail('ReceiptType');
  const [status, gas, bloom, logs] = it.kids;
  if (rlpUint(gas) === null || status.list || bloom.list || bloom.str.length !== 256 || !logs.list) fail('ReceiptType');
  if (status.str.length !== 1 || status.str[0] !== 1) fail('ReceiptStatus');
  return logs;
}

/**
 * Section 6.2 steps 2 to 5 up to the emitter: the EVM UC (`DepositUC`), the header bound to its input record (`DepositHeader`), the
 * receipt path keyed by RLP(txIndex) (`ReceiptPath`), type and status, `logs[logIndex]` (`LogIndex`) and its address (`LogEmitter`).
 * The caller checks its event's topics and data.
 */
export async function verifyReceiptLog(c: Config, t: TrustInput, p: DepositProof, emitter: Uint8Array = c.vault): Promise<ReceiptLog> {
  const uc = await verifyEvmUc(t, p.uc, c);
  const header = bindHeader(p.header, uc.inputRecord.blockHash, uc.inputRecord.nullableHash);
  const l = depositReceiptLog(p, header);
  // the emitter before the topics (section 6.2 step 5)
  if (!eq(l.kids[0].str, emitter)) fail('LogEmitter');
  const topics: Uint8Array[] = [];
  for (const tp of l.kids[1].kids) {
    if (tp.list || tp.str.length !== 32) fail('LogTopics');
    topics.push(tp.str);
  }
  return { address: l.kids[0].str, topics, data: l.kids[2].str, header };
}

function depositReceiptLog(p: DepositProof, header: Header): RlpItem {
  let value: Uint8Array;
  try {
    value = mptVerify(header.receiptsRoot, rlpIndexKey(p.txIndex), p.nodes);
  } catch (e) {
    if (e instanceof MptError) fail('ReceiptPath');
    throw e;
  }
  const logs = decodeReceipt(value);
  if (p.logIndex >= BigInt(logs.kids.length)) fail('LogIndex');
  const l = logs.kids[Number(p.logIndex)];
  if (!l.list || l.kids.length !== 3 || l.kids[0].list || l.kids[0].str.length !== 20 || !l.kids[1].list || l.kids[2].list) fail('LogIndex');
  return l;
}

/** Identify a native record in a shared journal from its locally retained root mint receipt. */
export function isNativeUctDeposit(p: DepositProof, domain: Uint8Array): boolean {
  const log = depositReceiptLog(p, decodeHeader(p.header));
  const topics = log.kids[1].kids;
  return topics.length === 2 && !topics[0].list && eq(topics[0].str, TOPIC.Deposited) && !topics[1].list && topics[1].str.length === 32
    && eq(log.kids[2].str.subarray(0, 32), domain);
}

/** The 224-byte data of Deposited(n, D, v, rho, firstOwner). */
export function depositedData(d: Uint8Array, v: bigint, rho: Uint8Array, firstOwner: Uint8Array): Uint8Array {
  const out = concat(d, u256(v), rho, u256(0x80), u256(firstOwner.length), firstOwner);
  const pad = (32 - (out.length % 32)) % 32;
  return concat(out, new Uint8Array(pad));
}

const zeroes = (n: number): Uint8Array => new Uint8Array(n);

/**
 * Section 6.2 steps 1 to 7 for a decoded J: the domain (`MintDomain`), the receipt log, its topics and data, the secret opening. It
 * returns the deposited amount and the first owner. The wallet runs it before minting; the verifier runs it inside the root mint check.
 */
export async function verifyDepositEvidence(c: Config, domain: Uint8Array, t: TrustInput, j: ReceiptBacking): Promise<{ v: bigint; firstOwner: Uint8Array; blockNumber: bigint }> {
  if (!eq(j.d, domain)) fail('MintDomain');
  const log = await verifyReceiptLog(c, t, j.proof);
  if (!depositTopics(log.topics, c.erc20?.token) || !eq(log.topics[1], u256(j.n))) fail('LogTopics');
  const data = log.data;
  if (data.length !== 224) fail('LogData');
  const v = data.subarray(32, 64).reduce((a, x) => (a << 8n) | BigInt(x), 0n);
  const owner = data.slice(160, 160 + FIRST_OWNER_BYTES);
  if (!eq(data.subarray(96, 128), u256(0x80)) || !eq(data.subarray(128, 160), u256(FIRST_OWNER_BYTES))
    || !eq(data.subarray(160 + FIRST_OWNER_BYTES), zeroes(224 - 160 - FIRST_OWNER_BYTES)) || !eq(data.subarray(0, 32), j.d) || v === 0n) {
    fail('LogData');
  }
  if (!eq(rhoOf(j.d, j.r), data.subarray(64, 96))) fail('SecretOpening');
  return { v, firstOwner: owner, blockNumber: log.header.number };
}

/** Section 6.2 for a root mint whose reason is J, in order: J and the deposited amount v. */
export async function verifyRootMint(c: Config, domain: Uint8Array, t: TrustInput, m: MintTx): Promise<{ j: ReceiptBacking; v: bigint }> {
  if (m.justification === null) fail('MintReason');
  const j = decodeReceiptBacking(m.justification!);
  const { v, firstOwner } = await verifyDepositEvidence(c, domain, t, j);
  if (!eq(m.salt, depositSalt(domain, j.n, j.r))) fail('MintSalt');
  if (!eq(m.type, c.ty)) fail('MintType');
  if (!eq(encodePredicate(m.recipient), firstOwner)) fail('MintOwner');
  if (m.data === null || !eq(m.data, valueData(c.aid, v))) fail('MintData');
  return { j, v };
}
