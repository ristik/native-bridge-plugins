/** Build certified protocol 10 evidence for the paired development lane. */
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { fromHex, toHex } from '../src/bytes.js';
import { SdkAggregator } from '../src/nb2/aggregator.js';
import { buildParams, decodeConfig, domainOf } from '../src/nb2/config.js';
import { HU } from '../src/nb2/crypto.js';
import { burnIndex, verifySealReceipt } from '../src/nb2/rules.js';
import { burnPredicate, decodeToken, lineageOf, signaturePredicate, type TransferTx } from '../src/nb2/token.js';
import { appendTransfer, certifyChecked, childMint, localOwner, mintRequest, splitPlan, tokenOfChild, transferRequest } from '../src/nb2/tokenops.js';
import { TrustInput } from '../src/nb2/trust.js';
import { encodeReturnData, verdictAbi, verifyHeld, verifyReturn, verifySplit } from '../src/nb2/verify.js';

const { values } = parseArgs({
  options: {
    gamma: { type: 'string' }, utb: { type: 'string' }, root: { type: 'string' }, owner: { type: 'string' },
    recipient: { type: 'string' }, aggregator: { type: 'string' }, output: { type: 'string' }, history: { type: 'string' },
    build: { type: 'string', default: 'production' }, seal: { type: 'string' },
  },
  strict: true,
});

const { gamma: gammaPath, utb, root, owner: keyPath, recipient: address, aggregator, output, history, build, seal } = values;
if (!gammaPath || !utb || !root || !keyPath || !address || !aggregator || !output) {
  throw new Error('required options: --gamma --utb --root --owner --recipient --aggregator --output --history');
}
if (history !== 'transfers-600' && history !== 'one-split-600' && history !== 'depth-20') throw new Error('unknown --history');
if (build !== 'production' && build !== 'test') throw new Error('unknown --build');
const url = new URL(aggregator);
if (url.hostname !== '127.0.0.1' && url.hostname !== 'localhost' && url.hostname !== '[::1]') throw new Error('use the development lane loopback API');
const recipient = fromHex(address.replace(/^0x/, ''));
const key = fromHex((await readFile(keyPath, 'utf8')).trim().replace(/^0x/, ''));
if (!recipient || recipient.length !== 20 || !key || key.length !== 32) throw new Error('invalid recipient or owner key');
const gamma = await readFile(gammaPath);
const params = buildParams(build);
const cfg = decodeConfig(gamma, params);
if (!recipient.some(Boolean) || Buffer.from(recipient).equals(cfg.vault)) throw new Error('invalid return recipient');
const domain = domainOf(gamma);
const trust = await TrustInput.fromBundle(await readFile(utb), cfg.rootGenesis);
const agg = new SdkAggregator(aggregator, { allowInsecure: url.protocol === 'http:' });
const owner = localOwner(key);
let token: Uint8Array = await readFile(root);
const held = await verifyHeld(cfg, domain, trust, decodeToken(token));
if (!Buffer.from(held.owner.params).equals(owner.publicKey)) throw new Error('root is owned by another key');
if (decodeToken(token).ancestors.length !== 0) throw new Error('workload starts at a root');
const splitCount = history === 'depth-20' ? 20 : history === 'one-split-600' ? 1 : 0;
if (held.amount <= BigInt(splitCount)) throw new Error('root amount is too small for the requested splits');
const { a } = burnIndex(cfg, domain, seal ? await verifySealReceipt(cfg, domain, trust, await readFile(seal)) : null);

async function spend(transfer: TransferTx): Promise<void> {
  const { tx, cd } = await transferRequest(token, owner, transfer);
  token = appendTransfer(token, tx, await certifyChecked(agg, cd));
}

for (let i = 0; i < (history === 'depth-20' ? 0 : 600); i++) {
  await spend({ recipient: signaturePredicate(owner.publicKey), mask: randomBytes(32), data: null, deadline: null });
}

let amount = held.amount;
for (let i = 0; i < splitCount; i++) {
  const plan = splitPlan(decodeToken(token), [
    { ownerKey: owner.publicKey, amount: amount - 1n, salt: randomBytes(32) },
    { ownerKey: owner.publicKey, amount: 1n, salt: randomBytes(32) },
  ], cfg.ty, cfg.aid, randomBytes(32));
  await spend(plan.burn);
  const split = await verifySplit(cfg, domain, trust, decodeToken(token));
  const { mint, allocation } = childMint(split.link, plan.tree, plan.children[0]);
  const { tx, cd } = mintRequest(mint);
  token = tokenOfChild(token, allocation, tx, await certifyChecked(agg, cd));
  amount--;
}

const data = encodeReturnData({ d: domain, asset: cfg.asset, recipient, amount, minIndex: a });
await spend({ recipient: burnPredicate(HU(data)), mask: randomBytes(32), data, deadline: null });
const verdict = await verifyReturn(gamma, token, trust, params);
await writeFile(output, token, { flag: 'wx', mode: 0o600 });
const levels = lineageOf(decodeToken(token)).map((level) => ({
  mintBytes: level.mintRaw.length,
  transfers: level.transfersRaw.length,
  transferBytes: level.transfersRaw.reduce((n, tx) => n + tx.length, 0),
}));
console.log(JSON.stringify({ history, evidenceBytes: token.length, levels, verdict: toHex(verdictAbi(verdict)) }, null, 2));
