//! The reply budget.
//!
//! The firewall accepts every new LAN `INPUT` connection
//! (`rc/firewall.c`), so both service ports are reachable by every device on
//! the bridge, a compromised IoT client included.  The vendor had no rate
//! limit of any kind.
//!
//! The budget is charged when a reply is admitted for transmission (an I/O
//! failure may still consume a reservation). Charging
//! on arrival would let a flood of malformed datagrams -- which cost almost
//! nothing to produce -- spend the budget a legitimate client needs, which
//! protects the attacker rather than the service.

/// Replies allowed in any one-second window, per protocol.
///
/// A LAN full of Windows machines produces a burst of probes at boot and then
/// almost nothing; 32 replies a second is far above that and far below a rate
/// that could matter to an upstream link.
pub const REPLIES_PER_SECOND: u32 = 32;

use std::time::Duration;

/// A fixed-size, allocation-free reply budget.
#[derive(Clone, Copy, Debug)]
pub struct Budget {
    window_start: Option<Duration>,
    used: u32,
    limit: u32,
}

impl Default for Budget {
    fn default() -> Self {
        Self::new(REPLIES_PER_SECOND)
    }
}

impl Budget {
    /// A budget of `limit` replies per one-second window.
    #[must_use]
    pub const fn new(limit: u32) -> Self {
        Self {
            window_start: None,
            used: 0,
            limit,
        }
    }

    /// Consumes one reply, returning false when the window is exhausted.
    ///
    /// `now` is elapsed monotonic time, independent of protocol wall-clock
    /// timestamps. An out-of-order reading fails closed without refilling.
    pub fn allow(&mut self, now: Duration) -> bool {
        let elapsed = match self.window_start {
            Some(start) => match now.checked_sub(start) {
                Some(elapsed) => elapsed,
                None => return false,
            },
            None => Duration::from_secs(1),
        };
        if elapsed >= Duration::from_secs(1) {
            self.window_start = Some(now);
            self.used = 0;
        }
        if self.used >= self.limit {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }

    /// How much of the current window has been spent.
    #[must_use]
    pub const fn used(&self) -> u32 {
        self.used
    }
}
