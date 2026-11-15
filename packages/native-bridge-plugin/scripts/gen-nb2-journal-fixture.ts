/**
 * The TypeScript-written journal snapshot of the cross-language round trip (bft-core#1104):
 *
 *   npx tsx scripts/gen-nb2-journal-fixture.ts
 *
 * writes ../../tests/nb2-journal/ts-written.json; the Rust plug-in continues it (`nb2_journal_interop.rs`).
 */
import { writeFileSync } from 'node:fs';

import { stageA } from '../test/nb2/journal-interop.js';

writeFileSync(new URL('../../../tests/nb2-journal/ts-written.json', import.meta.url), `${JSON.stringify(await stageA(), null, 1)}\n`);
