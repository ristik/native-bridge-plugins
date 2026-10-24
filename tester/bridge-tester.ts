/**
 * The bridge tester: one person's round trip through the native bridge of a public test network, with their own keys, against the operator's
 * public endpoints only (tester/README.md). FAKE VALUE: a bridged token is test ether on a network that is reset without notice; nothing carries over.
 *
 *   bridge-tester.ts init --config <tester-config.json> [--eth-key-file <file>]   a new wallet: an EVM key (fund it from the faucet) and the configuration
 *   bridge-tester.ts status [--token <nonce>]                                    the wallet's tokens and what the vault says about each
 *   bridge-tester.ts lock --amount <ether|Nwei>                                  lock test ether in the vault for a new token
 *   bridge-tester.ts mint [--token <nonce>]                                      fetch the lock's proof and mint the token on the aggregator
 *   bridge-tester.ts transfer [--token <nonce>] [--count <n>]                    certified transfers to fresh keys of this wallet
 *   bridge-tester.ts split [--token <id>] --amounts <a,b,...>                     split the token into parts (each a token: --token <id>.1, <id>.2, ...)
 *   bridge-tester.ts burn [--token <id>] [--recipient <0x address>]              burn the token (or a part) for its return to an EVM address (default: this wallet's)
 *   bridge-tester.ts redeem [--token <nonce>]                                    the return proof (consolidated by the aggregator), redeemed in the vault
 *   bridge-tester.ts claim [--to <0x address>]                                   withdraw this wallet's whole credit from the vault
 *
 * The wallet is a directory (--wallet, or BRIDGE_TESTER_WALLET, default ./bridge-wallet): keys.json (owner-only: the EVM key and the Unicity keys),
 * config.json, and tokens/<nonce>/ with the token file and its record. Keep it: a token exists only in its file.
 */
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { ShardRouting } from '@unicitylabs/state-transition-sdk/lib/consolidation/ShardRouting.js';
import { TokenProofClient } from '@unicitylabs/state-transition-sdk/lib/consolidation/TokenProofClient.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { sha256 } from '@noble/hashes/sha2.js';

import { DeploymentRegistry, makeDeployment } from '../packages/native-bridge-plugin/src/deployment.js';
import { configHashOfPdr, encodeJustification } from '../packages/native-bridge-plugin/src/lockproof.js';
import { buildReturnProof, refreshToken } from '../packages/native-bridge-plugin/src/proof.js';
import { decodeCfg, decodePolicy, deriveSalt, deriveTokenId, keccak256, lockDigest, lockRecord, returnReason, u, arr, valueEnvelope } from '../packages/native-bridge-plugin/src/profile.js';
import { TrustInput } from '../packages/native-bridge-plugin/src/trust.js';
import { NativeBridge } from '../packages/native-bridge-plugin/src/verifier.js';
import { planSplit, runSplit, type SplitJournal, type SplitRecord } from '../packages/native-bridge-plugin/src/splitflow.js';
import { consolidatedProofs, createNativeBridgePlugin } from '../packages/native-bridge-plugin/src/wallet.js';
import { hex, signLegacyTx, sleep, unhex } from '../tests/live/lib.js';
import {
  amountBytes, appendTransaction, calldata, checkNetwork, decBytes, GATEWAY_MAX_BODY, HttpError, jsonRpc, encAddress, encBytes, encUint, ethAddress, isAddress, loadTesterConfig, LOCKED_TOPIC, parseAmount,
  RECORD_ID, recordId, requirePhase, splitAmounts, TesterConfig, TokenRecord,
} from './core.js';

async function waitFor<T>(what: string, timeoutMs: number, f: () => Promise<T | undefined>, everyMs = 2000): Promise<T> {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const v = await f();
    if (v !== undefined) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(everyMs);
  }
}

// ---- the wallet -------------------------------------------------------------------------------------------------------------------------------
interface Keys {
  eth: string;
  unicity: string[];
}

class Wallet {
  constructor(readonly dir: string) {}

  get config(): TesterConfig {
    return loadTesterConfig(`${this.dir}/config.json`);
  }

  keys(): Keys {
    return JSON.parse(readFileSync(`${this.dir}/keys.json`, 'utf8')) as Keys;
  }

  saveKeys(k: Keys): void {
    writeFileSync(`${this.dir}/keys.json`, `${JSON.stringify(k, null, 2)}\n`, { mode: 0o600 });
    chmodSync(`${this.dir}/keys.json`, 0o600);
  }

  /** a new Unicity key, saved before it is used */
  newOwner(): { index: number; signer: SigningService } {
    const k = this.keys();
    const key = SigningService.generatePrivateKey();
    k.unicity.push(hex(key));
    this.saveKeys(k);
    return { index: k.unicity.length - 1, signer: new SigningService(key) };
  }

  owner(index: number): SigningService {
    return new SigningService(unhex(this.keys().unicity[index]));
  }

  tokenDir(id: string): string {
    return `${this.dir}/tokens/${id}`;
  }

  /** `--token`: a nonce, or a part (`<nonce>.<n>...`); the newest by default. */
  record(id?: string): TokenRecord {
    const all = this.records();
    if (all.length === 0) throw new Error('this wallet has no tokens yet: run lock');
    const r = id === undefined ? all[all.length - 1] : all.find((t) => recordId(t) === id);
    if (!r) throw new Error(`this wallet has no token ${id} (it has ${all.map(recordId).join(', ')})`);
    return r;
  }

  records(): TokenRecord[] {
    const dir = `${this.dir}/tokens`;
    if (!existsSync(dir)) return [];
    const key = (n: string) => n.split('.').map(Number);
    const cmp = (a: string, b: string) => {
      const [x, y] = [key(a), key(b)];
      for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
      return x.length - y.length;
    };
    return readdirSync(dir).filter((n) => RECORD_ID.test(n)).sort(cmp)
      .map((n) => JSON.parse(readFileSync(`${dir}/${n}/token.json`, 'utf8')) as TokenRecord);
  }

  saveRecord(t: TokenRecord): void {
    mkdirSync(this.tokenDir(recordId(t)), { recursive: true });
    writeFileSync(`${this.tokenDir(recordId(t))}/token.json`, `${JSON.stringify(t, null, 2)}\n`);
  }

  async token(t: TokenRecord): Promise<{ bytes: Uint8Array; token: Token }> {
    const bytes = Uint8Array.from(readFileSync(`${this.tokenDir(recordId(t))}/token.cbor`));
    return { bytes, token: await Token.fromCBOR(bytes) };
  }

  saveToken(t: TokenRecord, bytes: Uint8Array): void {
    mkdirSync(this.tokenDir(recordId(t)), { recursive: true });
    writeFileSync(`${this.tokenDir(recordId(t))}/token.cbor`, bytes);
  }
}

// ---- the chain --------------------------------------------------------------------------------------------------------------------------------
/** The configured chain, after checking that every endpoint the tester sends to is this generation's network with its vault (core checkNetwork). */
async function chainOf(cfg: TesterConfig): Promise<Chain> {
  for (const url of [cfg.ethUrl, ...(cfg.redeemEthUrl ? [cfg.redeemEthUrl] : [])]) {
    const block0 = (await jsonRpc(url, 'eth_getBlockByNumber', ['0x0', false])) as { hash: string } | null;
    checkNetwork(cfg, url, block0?.hash ?? 'none', (await jsonRpc(url, 'eth_getCode', [cfg.vault, 'latest'])) as string);
  }
  return new Chain(cfg);
}

class Chain {
  constructor(readonly cfg: TesterConfig) {}

  call(data: string, from?: string, url = this.cfg.ethUrl): Promise<string> {
    return jsonRpc(url, 'eth_call', [{ to: this.cfg.vault, data, ...(from ? { from } : {}) }, 'latest']);
  }

  async uint(signature: string, ...words: string[]): Promise<bigint> {
    return BigInt(await this.call(calldata(signature, ...words)));
  }

  /** Signs once and sends to one endpoint; waits for the receipt there. */
  async send(key: string, data: string, value = 0n, url = this.cfg.ethUrl): Promise<{ status: string; transactionHash: string; blockHash: string; blockNumber: string; gasUsed: string; logs: { address: string; topics: string[] }[] }> {
    const from = ethAddress(key);
    const tx = { from, to: this.cfg.vault, data, value: `0x${value.toString(16)}` };
    const gas = (BigInt(await jsonRpc(url, 'eth_estimateGas', [tx, 'latest'])) * 6n) / 5n + 20_000n;
    const gasPrice = BigInt(await jsonRpc(url, 'eth_gasPrice', [])) * 2n;
    const balance = BigInt(await jsonRpc(url, 'eth_getBalance', [from, 'latest']));
    if (balance < gas * gasPrice + value) throw new Error(`${from} holds ${balance} wei, and this needs ${gas * gasPrice + value}: get test ether from the faucet`);
    const nonce = BigInt(await jsonRpc(url, 'eth_getTransactionCount', [from, 'pending']));
    const { raw, hash } = signLegacyTx({ nonce, gasPrice, gas, to: this.cfg.vault, value, data: unhex(data), chainId: BigInt(this.cfg.chainId) }, key);
    await jsonRpc(url, 'eth_sendRawTransaction', [raw]);
    console.log(`  sent ${hash} (gas limit ${gas})`);
    const rc = await waitFor(`the receipt of ${hash}`, 180_000, async () => (await jsonRpc(url, 'eth_getTransactionReceipt', [hash])) ?? undefined);
    if (rc.status !== '0x1') throw new Error(`${hash} reverted (gas used ${BigInt(rc.gasUsed)})`);
    return rc;
  }
}

/** The installed bridge as the plug-in verifies it: the vault's Cfg read from the vault, trust, EVM PDR and policy from the operator's published files. */
async function installedBridge(cfg: TesterConfig, chain: Chain) {
  const vaultCfg = decodeCfg(decBytes(await chain.call(calldata('cfgBytes()'))));
  const trust = await TrustInput.fromBundle(Uint8Array.from(readFileSync(cfg.files.trustBundle)), unhex(readFileSync(cfg.files.trustEntryId, 'utf8').trim()));
  const pdr = Uint8Array.from(readFileSync(cfg.files.evmPdr));
  const policy = decodePolicy(unhex(JSON.parse(readFileSync(cfg.files.deployment, 'utf8')).policyBody));
  const code = unhex(await jsonRpc(cfg.ethUrl, 'eth_getCode', [cfg.vault, 'latest']));
  const dep = makeDeployment(vaultCfg, keccak256(code), configHashOfPdr(pdr), { fields: 20 }, policy);
  return { vaultCfg, dep, bridge: new NativeBridge(new DeploymentRegistry([dep]), trust) };
}

/** Submit one certification request and wait for its inclusion proof. */
async function certify(agg: AggregatorClient, cd: CertificationData, what: string) {
  const sid = await StateId.fromCertificationData(cd);
  await agg.submitCertificationRequest(cd);
  return waitFor(`${what} to be certified`, 180_000, async () => (await agg.getInclusionProof(sid)).inclusionProof ?? undefined);
}

// ---- the commands -----------------------------------------------------------------------------------------------------------------------------
async function init(w: Wallet, configPath: string, ethKeyFile?: string): Promise<void> {
  if (existsSync(`${w.dir}/keys.json`)) throw new Error(`${w.dir} already holds a wallet`);
  const cfg = loadTesterConfig(configPath);
  await chainOf(cfg); // a configuration of another generation is refused before the wallet exists
  mkdirSync(`${w.dir}/tokens`, { recursive: true, mode: 0o700 });
  const raw = JSON.parse(readFileSync(configPath, 'utf8')) as TesterConfig;
  raw.files = cfg.files; // absolute, so the copy reads the same files
  writeFileSync(`${w.dir}/config.json`, `${JSON.stringify(raw, null, 2)}\n`);
  const eth = ethKeyFile ? readFileSync(ethKeyFile, 'utf8').trim() : `0x${hex(secp256k1.utils.randomSecretKey())}`;
  if (!/^0x[0-9a-fA-F]{64}$/.test(eth)) throw new Error(`${ethKeyFile}: not a 32-byte hex key`);
  w.saveKeys({ eth, unicity: [] });
  console.log(`wallet ${w.dir}\nEVM address ${ethAddress(eth)}: fund it from the faucet (test ether only), then run lock`);
}

async function status(w: Wallet, nonce?: string): Promise<void> {
  const cfg = w.config;
  const chain = await chainOf(cfg);
  const me = ethAddress(w.keys().eth);
  console.log(`EVM address ${me}: balance ${BigInt(await jsonRpc(cfg.ethUrl, 'eth_getBalance', [me, 'latest']))} wei, vault credit ${await chain.uint('claimable(address)', encAddress(me))} wei`);
  for (const t of nonce === undefined ? w.records() : [w.record(nonce)]) {
    const n = encUint(BigInt(t.nonce));
    const digest = await chain.uint('lockDigest(uint256)', n);
    // protocol 6: the vault keys spent state by (root lock nonce, part token ID); a whole token is the part whose ID is its own
    let spent = 'not minted';
    if (t.phase === 'split') spent = 'split (its parts redeem)';
    else if (t.phase !== 'locked') {
      const { token } = await w.token(t);
      spent = (await chain.uint('spentPart(uint256,bytes32)', n, hex(token.id.bytes))) === 0n ? 'not redeemed' : 'redeemed';
    }
    const remaining = await chain.uint('remaining(uint256)', n);
    console.log(`token ${recordId(t)}: ${t.phase}, ${t.amountWei} wei, ${t.transfers} transfers${t.recipient ? `, returns to ${t.recipient}` : ''}` +
      `${t.parts ? `, split into ${t.parts.join(', ')}` : ''}; vault: ${digest === 0n ? 'NO LOCK' : `lock ${t.nonce} has ${remaining} wei left`}, this token ${spent}`);
  }
}

async function lock(w: Wallet, amountText: string): Promise<void> {
  const cfg = w.config;
  const chain = await chainOf(cfg);
  const amountWei = parseAmount(amountText);
  const owner = w.newOwner();
  const p0 = EncodedPredicate.fromPredicate(SignaturePredicate.create(owner.signer.publicKey)).toCBOR();
  const rc = await chain.send(w.keys().eth, calldata('lock(bytes)', encBytes(p0)), amountWei);
  const log = rc.logs.find((l) => l.address.toLowerCase() === cfg.vault.toLowerCase() && l.topics[0] === LOCKED_TOPIC);
  if (!log) throw new Error(`${rc.transactionHash} has no Locked event of the vault`);
  const t: TokenRecord = { nonce: BigInt(log.topics[1]).toString(), amountWei: amountWei.toString(), phase: 'locked', lockTx: rc.transactionHash, lockBlockHash: rc.blockHash, holder: owner.index, transfers: 0 };
  w.saveRecord(t);
  console.log(`locked ${amountWei} wei as token ${t.nonce} in block ${BigInt(rc.blockNumber)}; next: mint`);
}

async function mint(w: Wallet, nonce?: string): Promise<void> {
  const t = w.record(nonce);
  requirePhase(t, 'locked', 'mint');
  const cfg = w.config;
  const chain = await chainOf(cfg);
  const { vaultCfg, dep } = await installedBridge(cfg, chain);
  // the lock's proof: the endpoint answers 404 until the lock block is certified and archived, and again once it is out of the proof window
  const url = `${cfg.lockProofUrl.replace(/\/$/, '')}/v1/lockproof?block=${t.lockBlockHash}&nonce=${t.nonce}`;
  const lockProof = await waitFor('the lock proof (the lock block certified and archived)', 300_000, async () => {
    const res = await fetch(url);
    if (res.status === 200) return new Uint8Array(await res.arrayBuffer());
    if (res.status === 404 || res.status === 429 || res.status === 502) return undefined;
    throw new Error(`the lock-proof endpoint answered ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }, 5000);
  writeFileSync(`${w.tokenDir(recordId(t))}/lockproof.cbor`, lockProof);
  const owner = w.owner(t.holder);
  const nonceN = BigInt(t.nonce);
  const amount = amountBytes(BigInt(t.amountWei));
  const salt = deriveSalt(dep.cfgHash, nonceN);
  const p0 = EncodedPredicate.fromPredicate(SignaturePredicate.create(owner.publicKey)).toCBOR();
  // the vault's record of this lock must be the one the plug-in derives for this wallet's key and amount
  const onChain = (await chain.call(calldata('lockDigest(uint256)', encUint(nonceN)))).replace(/^0x/, '');
  if (onChain !== hex(lockDigest(dep.cfgHash, nonceN, lockRecord(vaultCfg.zeroAddress, vaultCfg.ty, vaultCfg.aid, amount, deriveTokenId(salt, vaultCfg.network), sha256(p0))))) {
    throw new Error(`the vault's lock ${t.nonce} is not this wallet's (another key or amount)`);
  }
  const tx = await MintTransaction.create(NetworkId.fromId(vaultCfg.network), SignaturePredicate.create(owner.publicKey), {
    data: valueEnvelope(vaultCfg.aid, amount), expiresAt: null, justification: encodeJustification(vaultCfg.chainId, vaultCfg.vault, vaultCfg.zeroAddress, nonceN, lockProof),
    salt: TokenSalt.fromBytes(salt), tokenType: new TokenType(vaultCfg.ty),
  });
  const proof = await certify(new AggregatorClient(cfg.aggUrl), await CertificationData.fromMintTransaction(tx), 'the mint');
  const bytes = C.encodeTag(39040n, arr(u(2), arr(tx.toCBOR(), proof.toCBOR()), arr()));
  await Token.fromCBOR(bytes);
  w.saveToken(t, bytes);
  w.saveRecord({ ...t, phase: 'minted' });
  console.log(`minted token ${t.nonce}; next: transfer, split or burn`);
}

async function transfer(w: Wallet, nonce: string | undefined, count: number): Promise<void> {
  let t = w.record(nonce);
  requirePhase(t, 'minted', 'transfer');
  const agg = new AggregatorClient(w.config.aggUrl);
  let { bytes, token } = await w.token(t);
  for (let i = 0; i < count; i++) {
    const next = w.newOwner();
    const tx = await TransferTransaction.create(token, SignaturePredicate.create(next.signer.publicKey), StateMask.generate());
    const proof = await certify(agg, await CertificationData.fromTransaction(tx, await SignaturePredicateUnlockScript.create(tx, w.owner(t.holder))), `transfer ${i + 1}/${count}`);
    bytes = appendTransaction(bytes, tx.toCBOR(), proof.toCBOR());
    token = await Token.fromCBOR(bytes);
    w.saveToken(t, bytes);
    t = { ...t, holder: next.index, transfers: t.transfers + 1 };
    w.saveRecord(t);
  }
  console.log(`token ${recordId(t)}: ${t.transfers} transfers; next: transfer, split or burn`);
}

/** The split's journal: one file next to the token, replaced atomically (write, then rename), so a crash leaves the last complete record. */
class FileSplitJournal implements SplitJournal {
  constructor(readonly path: string) {}
  put(r: SplitRecord): Promise<void> {
    const json = JSON.stringify({ ...r, source: hex(r.source), burnStateMask: hex(r.burnStateMask), burnRequest: r.burnRequest && hex(r.burnRequest), burned: r.burned && hex(r.burned),
      children: r.children.map((c) => c && hex(c)), outputs: r.outputs.map((o) => ({ recipient: hex(o.recipient), amount: o.amount.toString(), salt: hex(o.salt) })) }, null, 2);
    writeFileSync(`${this.path}.tmp`, `${json}\n`);
    renameSync(`${this.path}.tmp`, this.path);
    return Promise.resolve();
  }
  get(): Promise<SplitRecord | null> {
    if (!existsSync(this.path)) return Promise.resolve(null);
    const j = JSON.parse(readFileSync(this.path, 'utf8'));
    return Promise.resolve({ ...j, source: unhex(j.source), burnStateMask: unhex(j.burnStateMask), burnRequest: j.burnRequest && unhex(j.burnRequest), burned: j.burned && unhex(j.burned),
      children: j.children.map((c: string | null) => c && unhex(c)), outputs: j.outputs.map((o: { recipient: string; amount: string; salt: string }) => ({ recipient: unhex(o.recipient), amount: BigInt(o.amount), salt: unhex(o.salt) })) });
  }
}

/**
 * Split a held token into parts (protocol 6): the manifest burn of the token, then one mint per part, each to a fresh key of this wallet. The plan
 * (amounts, keys, salts, the burn's mask) is journaled in split.json before anything is submitted, and every certified step after it, so running
 * `split` again on the same token after a crash continues the same split (its --amounts must then be the same). Each part is a token of its own
 * (`--token <id>.<n>`) that can be transferred, split again or burned and redeemed against the original lock.
 */
async function split(w: Wallet, id: string | undefined, amountsText: string): Promise<void> {
  const t = w.record(id);
  requirePhase(t, 'minted', 'split');
  const amounts = splitAmounts(amountsText, BigInt(t.amountWei));
  const cfg = w.config;
  const { bridge } = await installedBridge(cfg, await chainOf(cfg));
  const plugin = createNativeBridgePlugin(bridge, { manifestRevision: 'tester', profileRevision: 'tester' });
  const journal = new FileSplitJournal(`${w.tokenDir(recordId(t))}/split.json`);
  let record = await journal.get();
  const owners: number[] = [];
  if (record === null) {
    const { bytes } = await w.token(t);
    const outputs = amounts.map((amount) => {
      const o = w.newOwner();
      owners.push(o.index);
      return { recipient: EncodedPredicate.fromPredicate(SignaturePredicate.create(o.signer.publicKey)).toCBOR(), amount, salt: secp256k1.utils.randomSecretKey() };
    });
    const plan = await planSplit(plugin, recordId(t), bytes, outputs);
    plan.estimates.forEach((g, i) => console.log(`  part ${i + 1}: ${amounts[i]} wei; its redemption needs at least ${g.total} gas`));
    record = plan.record;
    await journal.put(record);
  } else {
    if (record.outputs.length !== amounts.length || record.outputs.some((o, i) => o.amount !== amounts[i])) {
      throw new Error(`token ${recordId(t)} has a split under way with --amounts ${record.outputs.map((o) => `${o.amount}wei`).join(',')}: run it again with those`);
    }
    console.log('  continuing the split journaled in split.json');
    const keys = w.keys().unicity.map((k) => hex(EncodedPredicate.fromPredicate(SignaturePredicate.create(new SigningService(unhex(k)).publicKey)).toCBOR()));
    for (const o of record.outputs) owners.push(keys.indexOf(hex(o.recipient)));
  }
  const agg = new AggregatorClient(cfg.aggUrl);
  const children = await runSplit(plugin, record, {
    journal,
    unlock: (tx) => SignaturePredicateUnlockScript.create(tx, w.owner(t.holder)),
    certify: (cd, what) => certify(agg, cd, what),
  });
  const parts = children.map((bytes, i) => {
    const part: TokenRecord = { ...t, id: `${recordId(t)}.${i + 1}`, amountWei: amounts[i].toString(), phase: 'minted', holder: owners[i], transfers: 0, parent: recordId(t), parts: undefined, recipient: undefined, redeemTx: undefined };
    w.saveToken(part, bytes);
    w.saveRecord(part);
    return recordId(part);
  });
  w.saveRecord({ ...t, phase: 'split', parts });
  console.log(`split token ${recordId(t)} into ${parts.map((p, i) => `${p} (${amounts[i]} wei)`).join(', ')}; next: transfer, split or burn a part (--token ${parts[0]})`);
}

async function burn(w: Wallet, nonce: string | undefined, recipient?: string): Promise<void> {
  const t = w.record(nonce);
  requirePhase(t, 'minted', 'burn');
  const to = recipient ?? ethAddress(w.keys().eth);
  if (!isAddress(to)) throw new Error(`--recipient: not an address: ${to}`);
  const cfg = w.config;
  const { vaultCfg } = await installedBridge(cfg, await chainOf(cfg));
  const { bytes, token } = await w.token(t);
  const reason = returnReason(vaultCfg.chainId, vaultCfg.vault, vaultCfg.zeroAddress, vaultCfg.ty, vaultCfg.aid, unhex(to), amountBytes(BigInt(t.amountWei)));
  const tx = await TransferTransaction.create(token, BurnPredicate.create(sha256(reason)), StateMask.generate(), { data: reason });
  const proof = await certify(new AggregatorClient(cfg.aggUrl), await CertificationData.fromTransaction(tx, await SignaturePredicateUnlockScript.create(tx, w.owner(t.holder))), 'the burn');
  const burned = appendTransaction(bytes, tx.toCBOR(), proof.toCBOR());
  await Token.fromCBOR(burned);
  w.saveToken(t, burned);
  w.saveRecord({ ...t, phase: 'burned', recipient: to });
  console.log(`burned token ${recordId(t)} for its return to ${to}; next: redeem`);
}

async function redeem(w: Wallet, nonce?: string): Promise<void> {
  const t = w.record(nonce);
  requirePhase(t, 'burned', 'redeem');
  const cfg = w.config;
  const chain = await chainOf(cfg);
  const { bridge } = await installedBridge(cfg, chain);
  const { token } = await w.token(t);
  // one consolidated proof set from the aggregator (every leaf under one seal), so the envelope has one anchor whatever the history's length
  const client = new AggregatorClient(cfg.aggUrl);
  const proofClient = new TokenProofClient({ routing: ShardRouting.single(client), verificationContext: await bridge.context() });
  let cons: Awaited<ReturnType<typeof consolidatedProofs>> | undefined;
  for (let attempt = 1; attempt <= 4; attempt++) {
    cons = await consolidatedProofs(token, { partitionShards: 1, consolidate: (tk) => proofClient.consolidate(tk, { timeoutMs: 60_000 }) });
    if (cons.proofs || !(cons.path.kind === 'per-sid' && cons.path.retryable)) break;
    await sleep(5000);
  }
  let ret: Awaited<ReturnType<typeof buildReturnProof>>;
  if (cons?.proofs) ret = await buildReturnProof(bridge, await refreshToken(token, cons.proofs));
  else {
    // no consolidation: the proofs as certified, one anchor per certificate (a short history only)
    const why = `${JSON.stringify(cons?.path)}${cons?.path.kind === 'per-sid' && cons.path.unavailable === 'limit_exceeded' ? ' (one batch carries at most 256 states: 254 transfers)' : ''}`;
    console.log(`  the aggregator did not consolidate the token (${why}); using the proofs as certified`);
    try {
      ret = await buildReturnProof(bridge, token);
    } catch (e) {
      throw new Error(`no return proof: the consolidation was unavailable (${why}) and the proofs as certified do not make one: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  writeFileSync(`${w.tokenDir(recordId(t))}/envelope.bin`, ret.encoded);
  const data = calldata('redeem(bytes)', encBytes(ret.encoded));
  const url = cfg.redeemEthUrl ?? cfg.ethUrl;
  if (url === cfg.ethUrl && data.length + 1024 > GATEWAY_MAX_BODY) {
    console.log(`  note: the redemption is ${data.length} characters of calldata: a gateway that limits eth_call or eth_sendRawTransaction to ${GATEWAY_MAX_BODY} bytes refuses it (the testnet package's takes 4.5 MiB; otherwise configure redeemEthUrl)`);
  }
  // the vault accepts the envelope once the root chain's seal of it is within the registry's usable origin (a few rounds)
  await waitFor('the vault to accept the return proof', 240_000, async () => {
    try {
      // redeem returns (uint256 nonce, bytes32 partId): the root lock's nonce and this token's ID
      const ret = (await chain.call(data, ethAddress(w.keys().eth), url)).replace(/^0x/, '');
      return BigInt(`0x${ret.slice(0, 64)}`) === BigInt(t.nonce) && ret.slice(64, 128) === hex(token.id.bytes) ? true : undefined;
    } catch (e) {
      // not yet accepted (the vault reverts until the seal is within the usable origin) or a transient upstream failure: wait; but a client error
      // (4xx) is the endpoint refusing the request itself, which waiting never changes
      if (e instanceof HttpError && e.status >= 400 && e.status < 500) throw e;
      return undefined;
    }
  }, 3000);
  const rc = await chain.send(w.keys().eth, data, 0n, url);
  w.saveRecord({ ...t, phase: 'redeemed', redeemTx: rc.transactionHash });
  console.log(`redeemed token ${recordId(t)}: ${t.recipient} is credited ${t.amountWei} wei of lock ${t.nonce} (gas used ${BigInt(rc.gasUsed)}); next: claim (by ${t.recipient})`);
}

async function claim(w: Wallet, to?: string): Promise<void> {
  const cfg = w.config;
  const chain = await chainOf(cfg);
  const key = w.keys().eth;
  const me = ethAddress(key);
  const dest = to ?? me;
  if (!isAddress(dest)) throw new Error(`--to: not an address: ${dest}`);
  const credit = await chain.uint('claimable(address)', encAddress(me));
  if (credit === 0n) throw new Error(`${me} has no credit in the vault: redeem a burned token first`);
  await chain.send(key, calldata('claim(uint256,address)', encUint(credit), encAddress(dest)));
  console.log(`claimed ${credit} wei to ${dest}`);
}

// ---- the command line -------------------------------------------------------------------------------------------------------------------------
const USAGE = 'usage: bridge-tester.ts init --config <file> [--eth-key-file <file>] | status | lock --amount <ether|Nwei> | mint | transfer [--count n] | split --amounts a,b[,..] | burn [--recipient 0x..] | redeem | claim [--to 0x..]; ' +
  'options: --wallet <dir> (default $BRIDGE_TESTER_WALLET or ./bridge-wallet), --token <nonce or part, e.g. 5.1> (default the newest)';

export async function main(argv: string[]): Promise<void> {
  const { positionals, values } = parseArgs({
    args: argv, allowPositionals: true, strict: true,
    options: {
      wallet: { type: 'string' }, config: { type: 'string' }, 'eth-key-file': { type: 'string' }, token: { type: 'string' }, amount: { type: 'string' },
      count: { type: 'string' }, recipient: { type: 'string' }, to: { type: 'string' }, amounts: { type: 'string' },
    },
  });
  const w = new Wallet(values.wallet ?? process.env.BRIDGE_TESTER_WALLET ?? './bridge-wallet');
  const [cmd, ...extra] = positionals;
  if (extra.length) throw new Error(`unexpected arguments: ${extra.join(' ')}\n${USAGE}`);
  if (cmd !== 'init' && !existsSync(`${w.dir}/keys.json`)) throw new Error(`no wallet at ${w.dir}: run init first`);
  switch (cmd) {
    case 'init':
      if (!values.config) throw new Error(`init needs --config\n${USAGE}`);
      return init(w, values.config, values['eth-key-file']);
    case 'status':
      return status(w, values.token);
    case 'lock':
      if (!values.amount) throw new Error(`lock needs --amount\n${USAGE}`);
      return lock(w, values.amount);
    case 'mint':
      return mint(w, values.token);
    case 'transfer': {
      const n = Number(values.count ?? '1');
      if (!Number.isInteger(n) || n < 1 || n > 254) throw new Error('--count must be 1 to 254');
      return transfer(w, values.token, n);
    }
    case 'split':
      if (!values.amounts) throw new Error(`split needs --amounts\n${USAGE}`);
      return split(w, values.token, values.amounts);
    case 'burn':
      return burn(w, values.token, values.recipient);
    case 'redeem':
      return redeem(w, values.token);
    case 'claim':
      return claim(w, values.to);
    default:
      throw new Error(USAGE);
  }
}

if (process.argv[1]?.endsWith('bridge-tester.ts')) {
  main(process.argv.slice(2)).catch((e: unknown) => {
    console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
    process.exit(1);
  });
}
