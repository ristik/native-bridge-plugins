/** The SDK's aggregator client behind the plug-in's {@link Aggregator} seam (a network module: the verifier never imports it). */
import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';

import { eq } from '../bytes.js';
import { refuse } from './errors.js';
import type { Aggregator } from './tokenops.js';

export interface SdkAggregatorOptions { apiKey?: string | null; allowInsecure?: boolean; pollMs?: number; timeoutMs?: number; sleep?: (ms: number) => Promise<void> }

/** The SDK's aggregator client: submit, then wait for the certified proof of exactly this request. */
export class SdkAggregator implements Aggregator {
  private readonly client: AggregatorClient;
  public constructor(url: string, private readonly opts: SdkAggregatorOptions = {}) {
    this.client = new AggregatorClient(url, opts.apiKey ?? null, opts.allowInsecure ?? false);
  }

  public async certify(request: Uint8Array): Promise<Uint8Array> {
    const cd = CertificationData.fromCBOR(request);
    const r = await this.client.submitCertificationRequest(cd);
    if (!r.isAccepted && !r.isAlreadySubmitted && !r.isStateIdQueued) refuse('Reverted', `the aggregator refused the request: ${r.status}`);
    const sid = await StateId.fromCertificationData(cd);
    const sleep = this.opts.sleep ?? ((ms: number) => new Promise<void>((res) => setTimeout(res, ms)));
    const deadline = Date.now() + (this.opts.timeoutMs ?? 120_000);
    for (;;) {
      const resp = await this.client.getInclusionProof(sid, { waitMs: this.opts.pollMs ?? 2_000 });
      const p = resp.inclusionProof;
      if (p !== null) {
        const bytes = p.toCBOR();
        if (!eq(p.certificationData.toCBOR(), request)) refuse('ProviderFault', 'the aggregator certified another request for this state');
        return bytes;
      }
      if (Date.now() > deadline) refuse('Unconfirmed', 'no inclusion proof yet: call again with the same request');
      await sleep(this.opts.pollMs ?? 2_000);
    }
  }
}

