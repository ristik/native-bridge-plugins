/**
 * Provisional cross-stack fixtures: positive histories and isolated negative mutations, generated
 * with TypeScript SDK constructors. The Rust suite replays every case and independently rebuilds
 * the positives byte for byte. These are NOT the normative corpus (protocol/vectors, owned by
 * PR1/PR2); they exist so PR3's two stacks are checked against each other until that corpus lands.
 *
 *   npx tsx scripts/gen-fixtures.ts > ../../tests/interop/fixtures.json
 */
import { toHex } from '../src/bytes.js';
import { cfgBytes, policyBytes, returnReason } from '../src/profile.js';
import { fromHex } from '../src/bytes.js';
import { buildToken, burnStep, lockParts, makeUc, makeWorld, signer, spec, txStep, type MintSpec, type Step, type Tweaks, type World } from '../test/world.js';
import { valueEnvelope } from '../src/profile.js';

const T0 = 1_700_000_040n;
const UC_TS = 1_700_000_900n;

interface Case {
  name: string;
  expect: 'receipt' | 'return';
  result: string;
  token: string;
}

export async function generate(): Promise<unknown> {
  const w = makeWorld();
  const cases: Case[] = [];
  const add = async (name: string, expect: 'receipt' | 'return', s: MintSpec, steps: Step[], opts: { tw?: Tweaks; mintT?: bigint; ucTs?: bigint; parts?: (w: World, s: MintSpec) => ReturnType<typeof lockParts> } = {}): Promise<void> => {
    const parts = opts.parts ? await opts.parts(w, s) : undefined;
    const out = await buildToken(w, s, steps, opts.mintT ?? T0, opts.ucTs ?? UC_TS, opts.tw ?? {}, parts);
    let result = 'ok';
    try {
      await w.bridge.verifyNativeToken(out.token, expect);
    } catch (e) {
      result = (e as { reason?: string }).reason ?? String(e);
    }
    cases.push({ name, expect, result, token: toHex(out.bytes) });
  };
  const withDeadlines = (): MintSpec => ({ ...spec(1), mintDeadline: T0 + 1n });
  await add('receipt_genesis', 'receipt', spec(1), []);
  await add('receipt_two_transfers', 'receipt', spec(1), [txStep(2, 7, T0 + 10n), txStep(3, 8, T0 + 20n)]);
  await add('return_burn', 'return', spec(1), [txStep(2, 7, T0 + 10n), burnStep(T0 + 20n)]);
  await add('receipt_explicit_deadlines', 'receipt', withDeadlines(), [txStep(2, 7, T0 + 10n, T0 + 11n)]);
  await add('neg_deadline_equal_t', 'receipt', { ...spec(1), mintDeadline: T0 }, []);
  await add('neg_cd_deadline_mismatch', 'receipt', spec(1), [], { tw: { cdDeadline: [[0, T0 + 5n]] } });
  await add('neg_unlock_flipped_parity', 'receipt', spec(1), [txStep(2, 7, T0 + 10n)], { tw: { unlock: [[1, (u) => Uint8Array.of(...u.slice(0, 64), u[64] ^ 1)]] } });
  await add('neg_unlock_recovery_id_4', 'receipt', spec(1), [txStep(2, 7, T0 + 10n)], { tw: { unlock: [[1, (u) => Uint8Array.of(...u.slice(0, 64), 4)]] } });
  await add('neg_bare_dialect_payload', 'receipt', spec(1), [], { tw: { mintData: Uint8Array.from(fromHex(`82582${'0'}${toHex(w.dep.cfg.aid)}4203e8`)!) } });
  await add('neg_stored_digest_other_lock', 'receipt', { ...spec(1), evm: { ...spec(1).evm, stored: new Uint8Array(32).fill(0x42) } }, []);
  await add('neg_vault_code_hash', 'receipt', { ...spec(1), evm: { ...spec(1).evm, vaultCodeHash: new Uint8Array(32).fill(0x77) } }, []);
  await add('neg_evm_quorum_short', 'receipt', spec(1), [], { parts: async (ww, s) => { const p = await lockParts(ww, s); p.uc = await makeUc(ww.evm, { ...p.ucSpec, signers: 2 }); return p; } });
  await add('neg_leaf_time_after_anchor', 'receipt', spec(1), [], { mintT: UC_TS + 1n });
  await add('neg_receipt_with_burn', 'receipt', spec(1), [burnStep(T0 + 10n)]);
  await add('neg_return_without_burn', 'return', spec(1), [txStep(2, 7, T0 + 10n)]);
  await add('neg_burn_amount', 'return', spec(1), [{ kind: 'burnWith', reason: returnReason(7777n, w.dep.cfg.vault, new Uint8Array(20), w.dep.cfg.ty, w.dep.cfg.aid, new Uint8Array(20).fill(0xd0), Uint8Array.of(3, 231)), t: T0 + 10n }]);
  await add('neg_wrong_envelope_amount', 'receipt', spec(1), [], { tw: { mintData: valueEnvelope(w.dep.cfg.aid, Uint8Array.of(3, 233)) } });
  void signer;
  return {
    description: 'provisional cross-stack fixtures for native-bridge-plugins PR3 (SDK 3.0.1, protocol v3); not the normative corpus',
    trustDocument: toHex(w.agg.doc),
    deployment: {
      cfg: toHex(cfgBytes(w.dep.cfg)),
      policy: toHex(policyBytes(w.policy)),
      vaultCodeHash: toHex(w.dep.vaultCodeHash),
      evmConfigHash: toHex(w.dep.evmConfigHash),
      headerFields: w.dep.header.fields,
    },
    cases,
  };
}

if (process.argv[1]?.endsWith('gen-fixtures.ts')) {
  console.log(JSON.stringify(await generate(), null, 1));
}
