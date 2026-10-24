import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { toHex } from '../src/bytes.js';
import { keccak256, lockDigestSlot, lockedAmountSlot, redeemedAmountSlot, spentPartSlot, storageTrieKey, word, SLOT_SPENT_PART } from '../src/profile.js';

const CASES = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'protocol', 'vectors', 'vault', 'cases.json');

test('protocol 6 vault slots: lock digest (5), redeemedAmount (6) and lockedAmount (8) of every corpus derive case', () => {
  const derive = JSON.parse(readFileSync(CASES, 'utf8')).cases.filter((c: { op: string }) => c.op === 'derive');
  assert.ok(derive.length >= 4);
  for (const c of derive) {
    const n = BigInt(c.input);
    const v = c.expected.values;
    for (const [slot, name] of [[lockDigestSlot(n), 'lock'], [redeemedAmountSlot(n), 'redeemed'], [lockedAmountSlot(n), 'lockedAmount']] as const) {
      assert.equal(toHex(slot), v[`${name}Slot`], `${c.id} ${name}Slot`);
      assert.equal(toHex(storageTrieKey(slot)), v[`${name}TrieKey`], `${c.id} ${name}TrieKey`);
    }
  }
});

test('protocol 6 vault slots: spentPart[nonce][partId] is the nested mapping slot (contracts test_layout_u64MaxNonceSlotsHoldTheAmountsAndTheSpentPart)', () => {
  const part = new Uint8Array(32).fill(0xab);
  const n = (1n << 64n) - 1n;
  // keccak256(abi.encode(partId, keccak256(abi.encode(nonce, 9))))
  assert.deepEqual(spentPartSlot(n, part), keccak256(part, keccak256(word(n), word(SLOT_SPENT_PART))));
  assert.notDeepEqual(spentPartSlot(n, part), spentPartSlot(n - 1n, part));
  assert.notDeepEqual(spentPartSlot(n, part), spentPartSlot(n, new Uint8Array(32).fill(0xac)));
});
