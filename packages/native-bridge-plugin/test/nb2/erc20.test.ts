import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { addressWord } from '../../src/nb2/abi.js';
import { decodeConfig, domainOf, encodeConfig, erc20Identities, PRODUCTION_PARAMS } from '../../src/nb2/config.js';
import { HE } from '../../src/nb2/crypto.js';
import { erc20Create2 } from '../../src/nb2/erc20.js';
import { recoveredSettlementEta } from '../../src/nb2/recovery.js';
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
