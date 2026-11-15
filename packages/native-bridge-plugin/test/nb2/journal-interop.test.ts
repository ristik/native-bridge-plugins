/** A journal written by the Rust plug-in continues here, and this plug-in's own stage A snapshot continues too (bft-core#1104). */
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { stageA, stageB } from './journal-interop.js';

const DIR = new URL('../../../../tests/nb2-journal/', import.meta.url);

test('a journal written by the Rust plug-in continues in the TypeScript plug-in', async () => {
  await stageB(JSON.parse(readFileSync(new URL('rust-written.json', DIR), 'utf8')));
});

test('the committed TypeScript-written snapshot continues here too', async () => {
  await stageB(JSON.parse(readFileSync(new URL('ts-written.json', DIR), 'utf8')));
});

test('stage A then stage B in this plug-in, through a JSON round trip of the snapshot', async () => {
  await stageB(JSON.parse(JSON.stringify(await stageA())));
});
