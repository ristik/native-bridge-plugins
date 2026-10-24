import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { CborDeserializer as D } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer as C } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { arr, bs, u } from '../packages/native-bridge-plugin/src/profile.js';
import { hex, unhex } from '../tests/live/lib.js';
import {
  amountBytes, appendTransaction, calldata, decBytes, encAddress, encBytes, encUint, ethAddress, loadTesterConfig, LOCKED_TOPIC, MAX_LOCK_WEI, parseAmount,
  RECORD_ID, recordId, requirePhase, selector, splitAmounts, TokenRecord,
} from './core.js';

test('the vault ABI: selectors and the Locked topic match cast at the contracts pin', () => {
  assert.equal(selector('redeem(bytes)'), '9945e3d3');
  assert.equal(selector('lock(bytes)'), '81548319');
  assert.equal(selector('claim(uint256,address)'), 'ddd5e1b2');
  assert.equal(LOCKED_TOPIC, '0xd6db6ea52db1715d2acc9f81b6885abf21767319e404d7d4fd7c8b159a86983e');
});

test('bytes are encoded as abi.encode(bytes) does, and decoded back', () => {
  const b = unhex('0102030405');
  // cast abi-encode 'f(bytes)' 0x0102030405
  assert.equal(encBytes(b), `${'0'.repeat(62)}20${'0'.repeat(63)}50102030405${'0'.repeat(54)}`);
  assert.equal(encBytes(new Uint8Array(32)).length, 64 * 3, 'a whole word gets no padding word');
  assert.deepEqual(decBytes(`0x${encBytes(b)}`), b);
  assert.throws(() => decBytes(`0x${encBytes(b).slice(0, 128)}`), /truncated/);
  assert.equal(calldata('claim(uint256,address)', encUint(1n), encAddress('0x000000000000000000000000000000000000bEEF')),
    `0xddd5e1b2${'0'.repeat(63)}1${'0'.repeat(60)}beef`);
  assert.throws(() => encAddress('0xbeef'), /not an address/);
});

test('the EVM address of a key', () => {
  // anvil's first account
  assert.equal(ethAddress('0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80'), '0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266');
});

test('amounts: ether or wei, more than zero, at most one lock (8 bytes)', () => {
  assert.equal(parseAmount('1'), 10n ** 18n);
  assert.equal(parseAmount('0.5'), 5n * 10n ** 17n);
  assert.equal(parseAmount('0.000000000000000001'), 1n);
  assert.equal(parseAmount('123wei'), 123n);
  assert.equal(parseAmount(`${MAX_LOCK_WEI}wei`), MAX_LOCK_WEI);
  for (const bad of ['0', '0wei', '-1', '1e18', '0.0000000000000000001', '', 'abc']) assert.throws(() => parseAmount(bad), /amount/, bad);
  assert.throws(() => parseAmount(`${MAX_LOCK_WEI + 1n}wei`), /at most/);
  assert.throws(() => parseAmount('19'), /at most/);
  assert.equal(hex(amountBytes(10n ** 18n)), '0de0b6b3a7640000');
  // minimal: no leading zero byte below 2^56 wei (the plug-in refuses a padded amount as ErrIntRange)
  assert.equal(hex(amountBytes(100n)), '64');
  assert.equal(hex(amountBytes(256n)), '0100');
  assert.equal(hex(amountBytes((1n << 56n) - 1n)), 'ff'.repeat(7));
  assert.equal(hex(amountBytes(MAX_LOCK_WEI)), 'ff'.repeat(8));
});

test('the configuration: URLs, chain, vault and files checked; files resolved against its directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'tester-'));
  const good = {
    ethUrl: 'https://rpc.example', aggUrl: 'http://agg:3000', lockProofUrl: 'https://proof.example', chainId: 3, vault: `0x${'11'.repeat(20)}`,
    files: { trustBundle: 'trust-base.bundle.cbor', trustEntryId: 'trust-base.genesis.entryid', evmPdr: 'evm-pdr.cbor', deployment: 'bridge-deployment.json' },
  };
  const write = (c: unknown): string => {
    const p = join(dir, `c${Math.random()}.json`);
    writeFileSync(p, JSON.stringify(c));
    return p;
  };
  const c = loadTesterConfig(write(good));
  assert.equal(c.files.evmPdr, join(dir, 'evm-pdr.cbor'));
  assert.equal(c.redeemEthUrl, undefined);
  // one mutation at a time, each refused for its own field
  const cases: [string, unknown, RegExp][] = [
    ['ethUrl', 'rpc.example', /ethUrl/], ['aggUrl', undefined, /aggUrl/], ['lockProofUrl', 'ftp://x', /lockProofUrl/], ['redeemEthUrl', 'x', /redeemEthUrl/],
    ['chainId', 0, /chainId/], ['chainId', '3', /chainId/], ['vault', '0x11', /vault/],
  ];
  for (const [k, v, re] of cases) assert.throws(() => loadTesterConfig(write({ ...good, [k]: v })), re, `${k}=${String(v)}`);
  assert.throws(() => loadTesterConfig(write({ ...good, files: { ...good.files, evmPdr: '' } })), /files.evmPdr/);
  assert.throws(() => loadTesterConfig(write({ ...good, files: undefined })), /files is missing/);
});

test('a certified transaction is appended after the last one; anything but a token is refused', () => {
  const genesis = arr(bs(unhex('aa')), bs(unhex('bb')));
  const token = C.encodeTag(39040n, arr(u(2), genesis, arr()));
  const once = appendTransaction(token, bs(unhex('01')), bs(unhex('02')));
  const twice = appendTransaction(once, bs(unhex('03')), bs(unhex('04')));
  const [version, g, txs] = D.decodeArray(D.decodeTag(twice).data, 3);
  assert.equal(hex(version), hex(u(2)));
  assert.equal(hex(g), hex(genesis));
  assert.deepEqual(D.decodeArray(txs).map(hex), [hex(arr(bs(unhex('01')), bs(unhex('02')))), hex(arr(bs(unhex('03')), bs(unhex('04'))))]);
  assert.throws(() => appendTransaction(C.encodeTag(1n, arr()), bs(unhex('01')), bs(unhex('02'))), /not a token/);
});

test('steps out of order are refused with the next step named', () => {
  const t: TokenRecord = { nonce: '7', amountWei: '1', phase: 'minted', lockTx: '0x', lockBlockHash: '0x', holder: 0, transfers: 0 };
  assert.doesNotThrow(() => requirePhase(t, 'minted', 'burn'));
  assert.throws(() => requirePhase(t, 'locked', 'mint'), /token 7 is minted: mint needs it locked \(that step is done\); next: transfer, split or burn/);
  assert.throws(() => requirePhase(t, 'burned', 'redeem'), /redeem needs it burned; next: transfer, split or burn/);
  assert.throws(() => requirePhase({ ...t, phase: 'redeemed' }, 'minted', 'transfer'), /next: claim/);
  // a split token is done: every step names its parts instead
  assert.throws(() => requirePhase({ ...t, phase: 'split', parts: ['7.1', '7.2'] }, 'minted', 'burn'), /token 7 was split: burn one of its parts \(--token 7\.1 \| --token 7\.2\)/);
  assert.equal(recordId({ ...t, id: '7.2' }), '7.2');
  assert.ok(RECORD_ID.test('7') && RECORD_ID.test('7.1.2') && !RECORD_ID.test('7.') && !RECORD_ID.test('../7'));
});

test('--amounts: at least two, each an amount, adding up to exactly the token', () => {
  assert.deepEqual(splitAmounts('40wei,60wei', 100n), [40n, 60n]);
  assert.deepEqual(splitAmounts('0.25, 0.75', 10n ** 18n), [25n * 10n ** 16n, 75n * 10n ** 16n]);
  assert.throws(() => splitAmounts('100wei', 100n), /at least two/);
  assert.throws(() => splitAmounts('40wei,59wei', 100n), /add up to 99 wei, the token holds 100 wei/);
  assert.throws(() => splitAmounts('0wei,100wei', 100n), /more than zero/);});
