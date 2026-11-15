//! The SDK's aggregator client behind the plug-in's [`Aggregator`] seam (`aggregator.ts`): submit, then wait for the certified
//! proof of exactly this request. The transport is the SDK's caller-supplied [`AggregatorClient`] (its `http` feature, or the
//! wallet's own); the verifier never uses this module.

use std::time::{Duration, Instant};

use unicity_token::api::{CertificationData, StateId};
use unicity_token::cbor::Decoder;
use unicity_token::client::AggregatorClient;

use super::errors::{refuse, Error, Result, WalletReason};
use super::tokenops::Aggregator;

/// The SDK client as an [`Aggregator`].
pub struct SdkAggregator<C: AggregatorClient> {
    pub client: C,
    pub poll: Duration,
    pub timeout: Duration,
    pub sleep: Box<dyn Fn(Duration) + Send + Sync>,
}

impl<C: AggregatorClient> SdkAggregator<C> {
    pub fn new(client: C) -> Self {
        SdkAggregator {
            client,
            poll: Duration::from_millis(2_000),
            timeout: Duration::from_millis(120_000),
            sleep: Box::new(std::thread::sleep),
        }
    }
}

impl<C: AggregatorClient> Aggregator for SdkAggregator<C>
where
    C::Error: core::fmt::Debug,
{
    fn certify(&self, request: &[u8]) -> Result<Vec<u8>> {
        let cd = CertificationData::from_cbor(Decoder::new(request))
            .map_err(|e| Error::Other(format!("nb2: not a certification request: {e:?}")))?;
        if let Err(e) = self.client.submit_certification_request(&cd) {
            return refuse(
                WalletReason::Reverted,
                format!("the aggregator refused the request: {e:?}"),
            );
        }
        let sid = StateId::derive(cd.lock_script(), cd.source_state_hash());
        let deadline = Instant::now() + self.timeout;
        loop {
            // the SDK transport reports a proof not yet served as an error: poll until the deadline
            if let Ok(p) = self.client.get_inclusion_proof(&sid) {
                if p.certification_data.to_cbor() != request {
                    return refuse(
                        WalletReason::ProviderFault,
                        "the aggregator certified another request for this state",
                    );
                }
                return Ok(p.to_cbor());
            }
            if Instant::now() > deadline {
                return refuse(
                    WalletReason::Unconfirmed,
                    "no inclusion proof yet: call again with the same request",
                );
            }
            (self.sleep)(self.poll);
        }
    }
}
