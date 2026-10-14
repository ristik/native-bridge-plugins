//! The registry origin as a host sees it (`protocol/interop.md`, "Assembly and refresh"). Protocol 4 has no certificate-age
//! window: B1 accepts an anchor whose seal round `r` lies in its epoch's permanent registry entry, `start <= r <= O` (and
//! `r < end` for a closed epoch), `O` being the registry `clock.rootRound` at the redemption's execution block. An old
//! certificate never expires; a new one can be ahead of the registry. The only advisory check left is `max(r) <= O` on the
//! origin the host last read. Fetching, waiting and resending are the host's; this is the pure judgement it shares with the
//! TypeScript plug-in (`classifyReadiness`). An exhausted wait is the unavailable family (`ProofUnavailable`), never a budget
//! refusal.

/// How a bundle's anchors stand against the origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// No anchor is ahead of the origin.
    Ok,
    /// The newest anchor is beyond the origin: the registry cannot know it yet (waiting helps).
    Future,
}

/// Classify the seal rounds of a bundle's distinct anchors. `None` for no anchor.
pub fn classify_readiness(rounds: &[u64], origin: u64) -> Option<Readiness> {
    let max = *rounds.iter().max()?;
    Some(if max > origin {
        Readiness::Future
    } else {
        Readiness::Ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_newest_anchor_against_the_origin_matters() {
        assert_eq!(classify_readiness(&[100], 100), Some(Readiness::Ok));
        assert_eq!(classify_readiness(&[100], 99), Some(Readiness::Future));
        // an old certificate never expires
        assert_eq!(classify_readiness(&[100], 1_000_000), Some(Readiness::Ok));
        assert_eq!(
            classify_readiness(&[100, 105], 104),
            Some(Readiness::Future)
        );
        assert_eq!(classify_readiness(&[105, 100], 105), Some(Readiness::Ok));
        assert_eq!(classify_readiness(&[], 1), None);
    }
}
