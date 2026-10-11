//! The B1 window as a host sees it (`protocol/interop.md`, "Assembly and refresh"). B1 accepts an anchor with seal round `r` only
//! if `r <= O` and `O - r <= W_cert`, `O` being the registry `clock.rootRound` at the redemption's execution block. A host keeps an
//! execution margin `M` (a measured inclusion margin, not a protocol constant) and sends only when `max(r) <= O` and
//! `O - min(r) <= W_cert - M`. Fetching, waiting and resending are the host's; this is the pure judgement it shares with the
//! TypeScript plug-in (`classifyFreshness`). Exhausted freshness is the unavailable family (`ProofUnavailable`), never a budget refusal.

/// How a bundle's anchors stand against the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Inside the window with the margin kept.
    Ok,
    /// The newest anchor is beyond the origin: the registry cannot know it yet (waiting helps).
    Future,
    /// The oldest anchor is too old for the origin (only newer proofs help).
    Stale,
    /// `max - min > W_cert - M`: no origin admits the bundle; waiting never helps, only newer proofs.
    Spread,
}

/// Classify the seal rounds of a bundle's distinct anchors. `None` for no anchor or a margin that is not below `w_cert`.
pub fn classify_freshness(
    rounds: &[u64],
    origin: u64,
    w_cert: u64,
    margin: u64,
) -> Option<Freshness> {
    if rounds.is_empty() || margin >= w_cert {
        return None;
    }
    let min = *rounds.iter().min()?;
    let max = *rounds.iter().max()?;
    let allowed = w_cert - margin;
    Some(if max - min > allowed {
        Freshness::Spread
    } else if max > origin {
        Freshness::Future
    } else if origin - min > allowed {
        Freshness::Stale
    } else {
        Freshness::Ok
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_boundaries() {
        let (w, m) = (15, 6);
        assert_eq!(classify_freshness(&[100], 100, w, m), Some(Freshness::Ok));
        assert_eq!(classify_freshness(&[100], 109, w, m), Some(Freshness::Ok));
        assert_eq!(
            classify_freshness(&[100], 110, w, m),
            Some(Freshness::Stale)
        );
        assert_eq!(
            classify_freshness(&[100], 99, w, m),
            Some(Freshness::Future)
        );
        assert_eq!(
            classify_freshness(&[100, 109], 109, w, m),
            Some(Freshness::Ok)
        );
        assert_eq!(
            classify_freshness(&[100, 110], 110, w, m),
            Some(Freshness::Spread)
        );
        assert_eq!(
            classify_freshness(&[100, 110], 105, w, m),
            Some(Freshness::Spread)
        );
        assert_eq!(classify_freshness(&[100], 115, w, 0), Some(Freshness::Ok));
        assert_eq!(
            classify_freshness(&[100], 116, w, 0),
            Some(Freshness::Stale)
        );
        assert_eq!(classify_freshness(&[], 1, w, m), None);
        assert_eq!(classify_freshness(&[1], 1, w, w), None);
    }
}
