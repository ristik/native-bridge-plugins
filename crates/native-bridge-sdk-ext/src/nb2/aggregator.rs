//! The SDK's aggregator client behind the plug-in's [`Aggregator`] seam (`aggregator.ts`): submit, then wait for the certified
//! proof of exactly this request. The transport is the SDK's caller-supplied [`AggregatorClient`] (its `http` feature, or the
//! wallet's own); the verifier never uses this module.
//!
//! Resubmitting the same signed request must be harmless, as in the TypeScript adapter, which accepts the aggregator's
//! "already submitted" and "state ID queued" answers. The SDK's plain `submit_certification_request` reports both as errors,
//! so a failed submission is followed by the same wait for the proof: a proof certifying exactly this request is accepted, a
//! proof of other data is refused, and the submission error is reported only when no proof arrives. A read of the proof that
//! fails with anything but "not yet" (classified by the wallet's `not_yet`, the SDK error types being transport-specific) is
//! passed through, never turned into a timeout.

use std::time::{Duration, Instant};

use unicity_token::api::{CertificationData, StateId};
use unicity_token::cbor::Decoder;
use unicity_token::client::AggregatorClient;

use super::errors::{refuse, Error, Result, WalletReason};
use super::tokenops::Aggregator;

/// Which proof-read errors mean "not certified yet, keep waiting". For the SDK's `HttpAggregatorClient` that is
/// `|e| matches!(e, HttpError::Timeout | HttpError::ServerBusy | HttpError::OverloadTimeout { .. })`; `StateExpired`,
/// `StateUnknown`, authentication, configuration and transport errors are not.
pub type NotYet<E> = Box<dyn Fn(&E) -> bool + Send + Sync>;

/// The SDK client as an [`Aggregator`].
pub struct SdkAggregator<C: AggregatorClient> {
    pub client: C,
    pub not_yet: NotYet<C::Error>,
    pub poll: Duration,
    pub timeout: Duration,
    pub sleep: Box<dyn Fn(Duration) + Send + Sync>,
}

impl<C: AggregatorClient> SdkAggregator<C> {
    pub fn new(client: C, not_yet: NotYet<C::Error>) -> Self {
        SdkAggregator {
            client,
            not_yet,
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
        // an already submitted or queued request is not a failure: wait for its proof either way
        let submitted = self.client.submit_certification_request(&cd).err();
        let refused = |e: &C::Error| {
            refuse(
                WalletReason::Reverted,
                format!("the aggregator refused the request: {e:?}"),
            )
        };
        let sid = StateId::derive(cd.lock_script(), cd.source_state_hash());
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.client.get_inclusion_proof(&sid) {
                Ok(p) => {
                    if p.certification_data.to_cbor() != request {
                        return refuse(
                            WalletReason::ProviderFault,
                            "the aggregator certified another request for this state",
                        );
                    }
                    return Ok(p.to_cbor());
                }
                Err(e) if (self.not_yet)(&e) => {
                    if Instant::now() > deadline {
                        if let Some(s) = &submitted {
                            return refused(s);
                        }
                        return refuse(
                            WalletReason::Unconfirmed,
                            "no inclusion proof yet: call again with the same request",
                        );
                    }
                    (self.sleep)(self.poll);
                }
                // no proof of this request exists: the submission's own error, else the read's
                Err(e) => {
                    if let Some(s) = &submitted {
                        return refused(s);
                    }
                    return Err(Error::Other(format!(
                        "nb2: the aggregator's proof read failed: {e:?}"
                    )));
                }
            }
        }
    }
}
