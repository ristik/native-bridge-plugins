/** Build certified protocol 10 evidence for the paired development lane. */
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { eq, fromHex } from '../src/bytes.js';
import { SdkAggregator } from '../src/nb2/aggregator.js';
import { buildParams, decodeConfig } from '../src/nb2/config.js';
import { localOwner } from '../src/nb2/tokenops.js';
import { TrustInput } from '../src/nb2/trust.js';
import { runLaneWorkload } from './nb2-lane-run.js';

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
let bundle = await readFile(utb);
let historyTrust = await TrustInput.fromBundle(bundle, cfg.rootGenesis);
async function refreshTrust(): Promise<TrustInput> {
  const offered = await readFile(utb!);
  if (!eq(offered, bundle)) {
    historyTrust = await TrustInput.fromBundle(offered, cfg.rootGenesis);
    bundle = offered;
  }
  return historyTrust;
}
const trust = await refreshTrust();
const agg = new SdkAggregator(aggregator, { allowInsecure: url.protocol === 'http:' });
const startingSeal = seal ? await readFile(seal) : undefined;
const result = await runLaneWorkload({
  gamma, params, trust, refreshTrust, root: await readFile(root), owner: localOwner(key), aggregator: agg, recipient, startingSeal, output, history,
});
console.log(JSON.stringify(result, null, 2));
