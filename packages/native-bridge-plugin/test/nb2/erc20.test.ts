import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { addressWord } from '../../src/nb2/abi.js';
import { decodeConfig, domainOf, encodeConfig, erc20Identities, PRODUCTION_PARAMS } from '../../src/nb2/config.js';
import { HE } from '../../src/nb2/crypto.js';
import { erc20Create2 } from '../../src/nb2/erc20.js';
import { RecoveryAuthority, RecoverySession, recoveredSettlementEta } from '../../src/nb2/recovery.js';
import { preflightRecovery } from '../../src/nb2/recovery-cost.js';
import { decodeToken } from '../../src/nb2/token.js';
import { TrustInput } from '../../src/nb2/trust.js';
import { verdictAbi, verifyHeld, verifyReturn } from '../../src/nb2/verify.js';

const bytes = (h: string) => Uint8Array.from(Buffer.from(h.slice(2), 'hex'));
const files = new URL('../../../../protocol/vectors/', import.meta.url);
const fixture = JSON.parse(readFileSync(new URL('erc20-nb2/vectors.json', files), 'utf8')) as {
  Factory: string; VaultTemplate: string; RecoveryTemplate: string;
  Assets: Record<'Gamma' | 'Domain' | 'Asset' | 'Type' | 'Coin' | 'Vault' | 'Recovery' | 'Evidence' | 'Held' | 'Verdict' | 'ReturnProof', string>[];
};

test('Go ERC20 vectors isolate tokens, genesis and generation before accepting a fragment', async () => {
  for (const asset of fixture.Assets) {
    const gamma = bytes(asset.Gamma);
    const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
    const domain = domainOf(gamma);
    assert.deepEqual(domain, bytes(asset.Domain));
    assert.deepEqual(encodeConfig(cfg), gamma);
    const token = cfg.erc20!.token;
    const ids = erc20Identities(cfg.chainId, token, cfg.executionGenesis);
    assert.deepEqual(ids.asset, bytes(asset.Asset));
    assert.deepEqual(ids.ty, bytes(asset.Type));
    assert.deepEqual(ids.aid, bytes(asset.Coin));
    const salt = addressWord(token);
    assert.deepEqual(erc20Create2(bytes(fixture.Factory), salt, bytes(fixture.VaultTemplate)), bytes(asset.Vault));
    assert.deepEqual(erc20Create2(bytes(fixture.Factory), HE(salt), bytes(fixture.RecoveryTemplate)), bytes(asset.Recovery));
    const trust = await TrustInput.fromBundle(readFileSync(new URL('nb2-continuation-v1.1/transcripts/root/utb.cbor', files)), cfg.rootGenesis);
    const held = decodeToken(bytes(asset.Held));
    assert.equal((await verifyHeld(cfg, domain, trust, held)).amount, 40n);
    const another = { ...cfg, erc20: { ...cfg.erc20!, generation: HE(cfg.erc20!.generation) } };
    await assert.rejects(verifyHeld(another, domainOf(encodeConfig(another)), trust, held), { rule: 'MintDomain' });
    for (const foreign of fixture.Assets.filter((other) => other !== asset)) {
      await assert.rejects(verifyHeld(cfg, domain, trust, decodeToken(bytes(foreign.Held))));
    }
    const verdict = await verifyReturn(gamma, bytes(asset.Evidence), trust, PRODUCTION_PARAMS);
    assert.deepEqual(verdictAbi(verdict), bytes(asset.Verdict));
    assert.deepEqual(await recoveredSettlementEta(cfg, domain, trust, bytes(asset.Recovery), bytes(asset.ReturnProof)), verdict.eta);
  }
});

test('ERC20 recovery refuses either generation or graph pins that contradict Γ', async () => {
  const asset = fixture.Assets[0];
  const gamma = bytes(asset.Gamma);
  const cfg = decodeConfig(gamma, PRODUCTION_PARAMS);
  const { generation, pins } = cfg.erc20!;
  const trust = await TrustInput.fromBundle(readFileSync(new URL('nb2-continuation-v1.1/transcripts/root/utb.cbor', files)), cfg.rootGenesis);
  const authority = new RecoveryAuthority(trust, async () => {});
  const deployment = { salt: generation, pins, recovery: bytes(asset.Recovery), runtimeHash: new Uint8Array(32).fill(1),
    vaultRuntimeHash: new Uint8Array(32).fill(2) };
  const good = await RecoverySession.create(gamma, bytes(asset.Evidence), authority, PRODUCTION_PARAMS, deployment);
  assert.equal(good.id.length, 32);
  const limits = { signedBytes: 524_288, calldataBytes: 393_216, gas: 24_000_000n, chainId: cfg.chainId,
    maxNonce: 255n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n, balance: 10n ** 20n, feeBudget: 10n ** 20n };
  const backlog = { signedStart: 0n, observed: 0n, duringProgress: 3n, peakSeals: 1n, elapsedMs: 1000n,
    receiptP99Ms: 1000n, advancePeakSeals: 1n, finalInclusionMs: 25n, finalPeakSeals: 1n, qualifiedForMs: 200_000n };
  for (const mismatch of [{ ...deployment, salt: HE(generation) }, { ...deployment, pins: HE(pins) }]) {
    await assert.rejects(RecoverySession.create(gamma, bytes(asset.Evidence), authority, PRODUCTION_PARAMS, mismatch), { rule: 'ConfigShape' });
    await assert.rejects(preflightRecovery(gamma, bytes(asset.Held), trust, PRODUCTION_PARAMS, mismatch, {
      pins: mismatch.pins, runtimeHash: mismatch.runtimeHash, vaultRuntimeHash: mismatch.vaultRuntimeHash, ranges: [],
    }, limits, backlog), /unqualified recovery deployment/);
  }
});
