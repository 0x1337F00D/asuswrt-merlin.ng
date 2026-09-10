//! Emission budget and duplicate suppression.
//!
//! Both structures are deliberately allocation-free and driven by a caller
//! supplied monotonic millisecond clock, so the whole policy is testable
//! without a timer and cannot be perturbed by a wall-clock step.

/// Tokens available for a burst of replies.
pub const DEFAULT_BURST: u32 = 8;

/// Milliseconds between token refills. Eight tokens with one added every
/// 250 ms is four replies a second sustained, which is far above what a
/// mapper needs and far below what makes the responder a useful reflector.
pub const DEFAULT_REFILL_MILLIS: u64 = 250;

/// How long a mapper's generation number is remembered.
///
/// MS-LLTD mappers repeat Discover during a sweep; answering every copy with a
/// full Hello is the amplification an attacker would use. Remembering the
/// (mapper, generation) pair for this long collapses a sweep to one Hello and
/// forces an attacker to walk the generation number, which the token bucket
/// then caps.
pub const DEFAULT_GENERATION_MILLIS: u64 = 3_000;

/// Number of (mapper, generation) pairs remembered. A fixed array: no
/// allocation can be driven from the network.
pub const MAX_REMEMBERED: usize = 32;

/// A token bucket that is charged only when a reply is actually emitted.
///
/// Charging on receipt rather than on emission is what makes a rate limiter
/// work for the attacker: a flood of malformed frames would exhaust the budget
/// and silence the responder for the legitimate mapper. Nothing here is
/// consumed until the caller has a complete reply in hand.
#[derive(Clone, Copy, Debug)]
pub struct RateLimiter {
    tokens: u32,
    burst: u32,
    refill_millis: u64,
    last_refill: u64,
}

impl RateLimiter {
    /// Creates a full bucket. A zero `refill_millis` is raised to one so the
    /// refill arithmetic can never divide by zero.
    #[must_use]
    pub fn new(burst: u32, refill_millis: u64, now_millis: u64) -> Self {
        Self {
            tokens: burst,
            burst,
            refill_millis: refill_millis.max(1),
            last_refill: now_millis,
        }
    }

    /// Tokens currently available.
    #[must_use]
    pub fn tokens(&self) -> u32 {
        self.tokens
    }

    /// Adds any tokens the elapsed time has earned, saturating at the burst.
    fn refill(&mut self, now_millis: u64) {
        let elapsed = now_millis.saturating_sub(self.last_refill);
        let earned = elapsed / self.refill_millis;
        if earned == 0 {
            return;
        }
        let earned = u32::try_from(earned).unwrap_or(u32::MAX);
        self.tokens = self.tokens.saturating_add(earned).min(self.burst);
        // Advance by whole intervals only, so a stream of sub-interval calls
        // cannot keep resetting the clock and starve the refill.
        self.last_refill = self
            .last_refill
            .saturating_add(u64::from(earned).saturating_mul(self.refill_millis));
    }

    /// Spends one token, or reports that the budget is exhausted.
    ///
    /// Call this immediately before sending, never before validating.
    pub fn try_charge(&mut self, now_millis: u64) -> bool {
        self.refill(now_millis);
        match self.tokens.checked_sub(1) {
            Some(remaining) => {
                self.tokens = remaining;
                true
            }
            None => false,
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_BURST, DEFAULT_REFILL_MILLIS, 0)
    }
}

/// One remembered Discover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Seen {
    mapper: [u8; 6],
    generation: u16,
    at_millis: u64,
}

/// Remembers which (mapper, generation) pairs have already been answered.
#[derive(Clone, Copy, Debug)]
pub struct GenerationFilter {
    entries: [Option<Seen>; MAX_REMEMBERED],
    next: usize,
    window_millis: u64,
}

impl GenerationFilter {
    /// Creates an empty filter with the given memory window.
    #[must_use]
    pub fn new(window_millis: u64) -> Self {
        Self {
            entries: [None; MAX_REMEMBERED],
            next: 0,
            window_millis,
        }
    }

    /// Records the pair and reports whether it is new.
    ///
    /// Returns false when this mapper's generation was already answered inside
    /// the window; the caller must then drop the frame without replying and
    /// without charging the rate limiter.
    pub fn accept(&mut self, mapper: [u8; 6], generation: u16, now_millis: u64) -> bool {
        let mut free = None;
        for (index, slot) in self.entries.iter_mut().enumerate() {
            match slot {
                Some(seen) if now_millis.saturating_sub(seen.at_millis) >= self.window_millis => {
                    *slot = None;
                    if free.is_none() {
                        free = Some(index);
                    }
                }
                Some(seen) if seen.mapper == mapper && seen.generation == generation => {
                    seen.at_millis = now_millis;
                    return false;
                }
                Some(_) => {}
                None => {
                    if free.is_none() {
                        free = Some(index);
                    }
                }
            }
        }
        // A full table evicts round-robin: the memory is a best-effort
        // suppression, and the token bucket is the hard limit behind it.
        let index = free.unwrap_or(self.next);
        self.next = self.next.saturating_add(1) % MAX_REMEMBERED;
        if let Some(slot) = self.entries.get_mut(index) {
            *slot = Some(Seen {
                mapper,
                generation,
                at_millis: now_millis,
            });
        }
        true
    }
}

impl Default for GenerationFilter {
    fn default() -> Self {
        Self::new(DEFAULT_GENERATION_MILLIS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_and_then_the_bucket_is_empty() {
        let mut limiter = RateLimiter::new(3, 100, 0);
        assert!(limiter.try_charge(0));
        assert!(limiter.try_charge(0));
        assert!(limiter.try_charge(0));
        assert!(!limiter.try_charge(0));
        assert_eq!(limiter.tokens(), 0);
    }

    #[test]
    fn tokens_come_back_one_interval_at_a_time_and_stop_at_the_burst() {
        let mut limiter = RateLimiter::new(3, 100, 0);
        for _ in 0..3 {
            assert!(limiter.try_charge(0));
        }
        assert!(!limiter.try_charge(99));
        assert!(limiter.try_charge(100));
        assert!(!limiter.try_charge(199));
        assert!(limiter.try_charge(200));
        // Ten intervals of idling cannot bank more than the burst.
        assert!(!limiter.try_charge(201));
        let mut limiter = RateLimiter::new(3, 100, 0);
        assert_eq!(limiter.tokens(), 3);
        assert!(limiter.try_charge(10_000));
        assert_eq!(limiter.tokens(), 2);
    }

    #[test]
    fn sub_interval_calls_do_not_starve_the_refill() {
        // Regression shape: advancing last_refill to `now` on every call
        // would mean a caller polling every 99 ms never earns a token.
        let mut limiter = RateLimiter::new(1, 100, 0);
        assert!(limiter.try_charge(0));
        for now in [50, 99, 120, 150] {
            let charged = limiter.try_charge(now);
            if now >= 100 {
                assert!(charged || limiter.tokens() == 0);
            } else {
                assert!(!charged);
            }
        }
    }

    #[test]
    fn a_zero_refill_interval_cannot_divide_by_zero() {
        let mut limiter = RateLimiter::new(1, 0, 0);
        assert!(limiter.try_charge(0));
        assert!(limiter.try_charge(1));
    }

    #[test]
    fn a_repeated_generation_is_suppressed_until_the_window_expires() {
        let mut filter = GenerationFilter::new(1_000);
        let mapper = [1, 2, 3, 4, 5, 6];
        assert!(filter.accept(mapper, 7, 0));
        assert!(!filter.accept(mapper, 7, 100));
        assert!(filter.accept(mapper, 8, 100));
        assert!(filter.accept([9; 6], 7, 100));
        // The repeat at 100 refreshed the entry, so it expires at 1100.
        assert!(!filter.accept(mapper, 7, 1_099));
        assert!(filter.accept(mapper, 7, 2_500));
    }

    #[test]
    fn a_full_table_keeps_accepting_without_growing() {
        let mut filter = GenerationFilter::new(1_000_000);
        for index in 0..(MAX_REMEMBERED as u32 * 4) {
            let mapper = [2, 0, 0, 0, 0, index as u8];
            assert!(filter.accept(mapper, index as u16, 0));
        }
    }
}
