//! Clock discipline: peer filtering, peer selection and the decision to step
//! or slew. Every function here is pure; applying a decision to the real
//! kernel clock is the caller's job, so the whole state machine is testable
//! without touching system time.

use crate::client::Sample;
use crate::packet::Leap;

/// Offsets larger than this are stepped, not slewed (seconds). Same value the
/// busybox applet used; reference ntpd uses 0.128.
pub const STEP_THRESHOLD: f64 = 1.0;
/// Largest offset the kernel PLL will accept in one `adjtimex` (seconds).
pub const SLEW_THRESHOLD: f64 = 0.5;
/// Smallest poll exponent, log2 seconds (64 s).
pub const MIN_POLL_EXP: u8 = 6;
/// Largest poll exponent, log2 seconds (18.2 h).
pub const MAX_POLL_EXP: u8 = 16;
/// Poll exponent above which an offset spike lowers the interval at once.
pub const BIG_POLL_EXP: u8 = 9;
/// Poll-adjust hysteresis limit.
pub const POLLADJ_LIMIT: i32 = 36;
/// Offset/jitter ratio below which the poll interval may grow.
pub const POLLADJ_GATE: u32 = 4;
/// Offset/jitter ratio above which the PLL time constant is made sharper.
pub const TIMECONST_HACK_GATE: u32 = 2;
/// Number of first adjustments that hold the kernel frequency steady.
pub const MIN_FREQHOLD: i32 = 12;
/// Local clock precision as a log2 exponent, published in outgoing packets.
pub const PRECISION_EXP: i8 = -9;
/// Local clock precision in seconds; deliberately a round number in logs.
pub const PRECISION_SECONDS: f64 = 0.002;
/// Assumed oscillator tolerance, 15 ppm.
pub const FREQ_TOLERANCE: f64 = 0.000_015;
/// Minimum dispersion contributed by any measurement, seconds.
pub const MIN_DISPERSION: f64 = 0.01;
/// Maximum root distance a peer may have and still be selectable, seconds.
pub const MAX_DISTANCE: f64 = 1.0;
/// Datapoints kept per peer.
pub const DATAPOINTS: usize = 8;
/// Seconds between unconditional `-S PROG periodic` runs.
pub const SCRIPT_PERIOD: f64 = 11.0 * 60.0;
/// Stratum value meaning "not synchronised".
pub const MAX_STRATUM: u8 = 16;

/// `2^exponent`, clamped so a hostile precision byte cannot overflow.
#[must_use]
pub fn log2_to_seconds(exponent: i8) -> f64 {
    2.0_f64.powi(i32::from(exponent).clamp(-64, 64))
}

/// One filtered measurement.
#[derive(Clone, Copy, Debug)]
struct Datapoint {
    offset: f64,
    received_at: f64,
    dispersion: f64,
}

impl Default for Datapoint {
    fn default() -> Self {
        Self {
            offset: 0.0,
            received_at: 0.0,
            dispersion: crate::client::MAX_ROOT_DISTANCE,
        }
    }
}

/// The per-peer clock filter: an eight-deep shift register whose statistics
/// feed peer selection. Mirrors the algorithm busybox actually compiles (the
/// averaging variant in that file is `#if 0`-ed out).
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerFilter {
    datapoints: [Datapoint; DATAPOINTS],
    index: usize,
    /// Shift register of the last eight query outcomes, LSB is most recent.
    pub reachable_bits: u8,
    /// Offset of the most recent datapoint, seconds.
    pub offset: f64,
    /// Weighted dispersion of the register, seconds.
    pub dispersion: f64,
    /// RMS spread of the register around its mean, seconds.
    pub jitter: f64,
    /// Delay of the most recent accepted reply, seconds.
    pub delay: f64,
    /// Local time of the most recent accepted reply, seconds since 1900.
    pub received_at: f64,
    /// Root delay reported by the peer, seconds.
    pub root_delay: f64,
    /// Root dispersion reported by the peer, seconds.
    pub root_dispersion: f64,
    /// Stratum reported by the peer.
    pub stratum: u8,
    /// Leap indicator reported by the peer.
    pub leap: Leap,
    /// Reference id reported by the peer.
    pub reference_id: [u8; 4],
}

impl PeerFilter {
    /// A filter with no datapoints yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            leap: Leap::NoWarning,
            jitter: PRECISION_SECONDS,
            ..Self::default()
        }
    }

    /// Records that a query was sent; the register shifts even when the send
    /// fails locally, so a pulled cable still ends in loss of sync.
    pub fn note_query_sent(&mut self) {
        self.reachable_bits <<= 1;
    }

    /// True when the peer answered at least one of the last eight queries.
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.reachable_bits != 0
    }

    /// Folds an accepted reply into the register and recomputes statistics.
    pub fn accept(&mut self, sample: &Sample, now: f64) {
        let first = self.reachable_bits == 0;
        self.index = if first {
            0
        } else {
            (self.index + 1) % DATAPOINTS
        };
        let datapoint = Datapoint {
            offset: sample.offset,
            received_at: sample.received_at,
            dispersion: log2_to_seconds(sample.precision) + PRECISION_SECONDS,
        };
        if first {
            // The very first reply seeds every slot, otherwise the register
            // would carry seven fabricated zero offsets into selection.
            self.datapoints = [datapoint; DATAPOINTS];
        } else if let Some(slot) = self.datapoints.get_mut(self.index) {
            *slot = datapoint;
        }
        self.reachable_bits |= 1;
        self.delay = sample.delay;
        self.received_at = sample.received_at;
        self.root_delay = sample.root_delay;
        self.root_dispersion = sample.root_dispersion;
        self.stratum = sample.stratum;
        self.leap = sample.leap;
        self.reference_id = sample.reference_id;
        self.recompute(now);
    }

    /// Recomputes offset/dispersion/jitter for the current time.
    pub fn recompute(&mut self, now: f64) {
        let mut index = self.index;
        let mut dispersion_sum = 0.0;
        let mut offset_sum = 0.0;
        self.offset = self
            .datapoints
            .get(self.index)
            .map_or(0.0, |datapoint| datapoint.offset);
        for step in 0..DATAPOINTS {
            let Some(datapoint) = self.datapoints.get(index) else {
                break;
            };
            let age = (now - datapoint.received_at).max(0.0);
            let dispersion = datapoint.dispersion + FREQ_TOLERANCE * age;
            // Weight 1/2, 1/4, ... 1/256 from the newest datapoint backwards.
            dispersion_sum += dispersion / f64::from(2_u32.saturating_pow(step as u32 + 1));
            offset_sum += datapoint.offset;
            index = (index + DATAPOINTS - 1) % DATAPOINTS;
        }
        self.dispersion = dispersion_sum;
        let mean = offset_sum / DATAPOINTS as f64;
        let variance: f64 = self
            .datapoints
            .iter()
            .map(|datapoint| {
                let difference = mean - datapoint.offset;
                difference * difference
            })
            .sum::<f64>()
            / DATAPOINTS as f64;
        self.jitter = variance.sqrt().max(PRECISION_SECONDS);
    }

    /// Root synchronisation distance: half the total delay plus all
    /// dispersion plus this peer's jitter.
    #[must_use]
    pub fn root_distance(&self, now: f64) -> f64 {
        (self.root_delay + self.delay).max(MIN_DISPERSION) / 2.0
            + self.root_dispersion
            + self.dispersion
            + FREQ_TOLERANCE * (now - self.received_at).max(0.0)
            + self.jitter
    }

    /// Shifts every stored time by `offset` after the clock was stepped, so a
    /// step does not invalidate data that is still good.
    pub fn rebase_after_step(&mut self, offset: f64, now: f64) {
        let small = offset.abs() < STEP_THRESHOLD;
        for datapoint in &mut self.datapoints {
            if small {
                datapoint.received_at += offset;
                if datapoint.offset != 0.0 {
                    datapoint.offset -= offset;
                }
            } else {
                datapoint.received_at = now;
                datapoint.offset = 0.0;
            }
        }
        if small {
            self.received_at += offset;
        } else {
            self.received_at = now;
        }
        self.recompute(now);
    }
}

/// A peer offered to the selection algorithm.
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    /// Index of the peer in the caller's table.
    pub index: usize,
    /// Filtered offset, seconds.
    pub offset: f64,
    /// Root distance, seconds.
    pub root_distance: f64,
    /// Stratum.
    pub stratum: u8,
    /// Reachability register.
    pub reachable_bits: u8,
}

/// Decides whether a peer may take part in selection.
///
/// `trust_network` is the `-t` flag: it drops the root-distance test, exactly
/// as busybox's `fit()` does. It never drops the reachability test and, unlike
/// busybox, it never disables the packet-level sanity checks.
#[must_use]
pub fn is_fit(candidate: &Candidate, poll_exp: u8, trust_network: bool) -> bool {
    // At least two of the last eight queries must have been answered.
    if candidate.reachable_bits & candidate.reachable_bits.wrapping_sub(1) == 0 {
        return false;
    }
    if trust_network {
        return true;
    }
    let poll_seconds = f64::from(1_u32.wrapping_shl(u32::from(poll_exp.min(30))));
    candidate.root_distance <= MAX_DISTANCE + FREQ_TOLERANCE * poll_seconds
}

/// Marzullo intersection followed by the lowest `MAXDIST * stratum +
/// root_distance` metric, which is the ordering busybox's cluster stage ends
/// up with for the one or two peers this firmware configures.
///
/// Returns the index the caller passed in [`Candidate::index`].
#[must_use]
pub fn select_peer(candidates: &[Candidate]) -> Option<usize> {
    if candidates.is_empty() {
        return None;
    }
    // Correctness intervals as (edge, type) with type -1 low, 0 mid, +1 high.
    let mut points: Vec<(f64, i32)> = Vec::with_capacity(candidates.len() * 3);
    for candidate in candidates {
        points.push((candidate.offset - candidate.root_distance, -1));
        points.push((candidate.offset, 0));
        points.push((candidate.offset + candidate.root_distance, 1));
    }
    points.sort_by(|left, right| left.0.total_cmp(&right.0));

    let total = candidates.len() as i32;
    let mut falsetickers = 0_i32;
    let (low, high) = loop {
        let mut midpoints = 0_i32;
        let mut counter = 0_i32;
        let mut low = f64::INFINITY;
        for (edge, kind) in &points {
            counter -= kind;
            if counter >= total - falsetickers {
                low = *edge;
                break;
            }
            if *kind == 0 {
                midpoints += 1;
            }
        }
        let mut counter = 0_i32;
        let mut high = f64::NEG_INFINITY;
        for (edge, kind) in points.iter().rev() {
            counter += kind;
            if counter >= total - falsetickers {
                high = *edge;
                break;
            }
            if *kind == 0 {
                midpoints += 1;
            }
        }
        if midpoints <= falsetickers && low < high {
            break (low, high);
        }
        falsetickers += 1;
        if falsetickers * 2 >= total {
            return None;
        }
    };

    candidates
        .iter()
        .filter(|candidate| candidate.offset >= low && candidate.offset <= high)
        .min_by(|left, right| metric(left).total_cmp(&metric(right)))
        .map(|candidate| candidate.index)
}

fn metric(candidate: &Candidate) -> f64 {
    MAX_DISTANCE * f64::from(candidate.stratum) + candidate.root_distance
}

/// What the caller must do to the system clock.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClockAction {
    /// Nothing to apply.
    None,
    /// Set the clock forward or backward by this many seconds.
    Step(f64),
    /// Hand these `adjtimex` parameters to the kernel PLL.
    Slew {
        /// `timex.offset`, microseconds, already clamped to the slew window.
        offset_micros: i64,
        /// `timex.status`.
        status: i32,
        /// `timex.constant`.
        constant: i32,
    },
}

/// Which action word the `-S PROG` script must be run with.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptAction {
    /// The clock was stepped. This is the only word `rc/ntpd.c` reacts to.
    Step,
    /// The local stratum changed.
    Stratum,
    /// Eleven minutes passed without any other run.
    Periodic,
    /// Every peer fell out of reach while we were synchronised.
    Unsync,
}

impl ScriptAction {
    /// The literal argument passed to the script.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Step => "step",
            Self::Stratum => "stratum",
            Self::Periodic => "periodic",
            Self::Unsync => "unsync",
        }
    }
}

/// How the poll interval should react to this update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PollFeedback {
    /// The datapoint was not usable; leave the interval alone.
    Leave,
    /// Good datapoint: grow or shrink depending on the offset/jitter ratio.
    Adjust,
}

/// Result of folding one selected sample into the discipline.
#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    /// What to do to the system clock.
    pub action: ClockAction,
    /// Which script run this update triggers, if any.
    pub script: Option<ScriptAction>,
    /// How the caller should adjust the poll interval.
    pub feedback: PollFeedback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    /// Nothing has been set yet.
    Unset,
    /// Normal operation.
    Synchronised,
}

/// The local clock discipline state machine.
#[derive(Clone, Copy, Debug)]
pub struct Discipline {
    state: State,
    /// Current poll exponent, log2 seconds.
    pub poll_exp: u8,
    polladj_count: i32,
    /// Local stratum: selected peer's stratum plus one, or 16 when unsynced.
    pub stratum: u8,
    freqhold: i32,
    jitter: f64,
    last_offset: f64,
    last_received_at: f64,
    /// Ratio of the last offset to the discipline jitter, used by poll adjust.
    pub offset_to_jitter_ratio: u32,
    /// Leap indicator of the selected peer, forwarded to the kernel and to
    /// LAN clients.
    pub leap: Leap,
}

impl Default for Discipline {
    fn default() -> Self {
        Self::new()
    }
}

impl Discipline {
    /// A discipline that has never seen a usable sample.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: State::Unset,
            poll_exp: MIN_POLL_EXP,
            polladj_count: 0,
            stratum: MAX_STRATUM,
            freqhold: -1,
            jitter: PRECISION_SECONDS,
            last_offset: 0.0,
            last_received_at: 0.0,
            offset_to_jitter_ratio: 0,
            leap: Leap::NoWarning,
        }
    }

    /// True once the clock has been disciplined at least once.
    #[must_use]
    pub fn is_synchronised(&self) -> bool {
        self.stratum < MAX_STRATUM
    }

    /// True once a usable datapoint has been folded in. `-q` exits here even
    /// when the offset was already small enough to need no correction, which
    /// is what busybox's ntpd did in its NSET state.
    #[must_use]
    pub fn has_usable_sample(&self) -> bool {
        self.state == State::Synchronised
    }

    /// The offset of the most recent usable datapoint, in seconds. Reported
    /// to the `-S` program on a `periodic` run.
    #[must_use]
    pub fn last_offset(&self) -> f64 {
        self.last_offset
    }

    /// Current poll interval in seconds.
    #[must_use]
    pub fn poll_seconds(&self) -> u32 {
        1_u32.wrapping_shl(u32::from(self.poll_exp.min(30)))
    }

    /// Folds the selected peer's filtered offset into the discipline.
    ///
    /// `offset` and `received_at` come from the peer filter; `now` is the
    /// current local time in seconds since 1900.
    pub fn update(&mut self, offset: f64, received_at: f64, stratum: u8, leap: Leap) -> Outcome {
        if !offset.is_finite() || received_at <= self.last_received_at {
            // Never use the same or an older sample twice.
            return Outcome {
                action: ClockAction::None,
                script: None,
                feedback: PollFeedback::Leave,
            };
        }
        let magnitude = offset.abs();
        if magnitude > STEP_THRESHOLD {
            self.clamp_poll_and_unsync();
            self.state = State::Synchronised;
            self.last_offset = 0.0;
            self.last_received_at = received_at + offset;
            return Outcome {
                action: ClockAction::Step(offset),
                script: Some(ScriptAction::Step),
                feedback: PollFeedback::Leave,
            };
        }

        self.offset_to_jitter_ratio = ratio(magnitude, self.jitter);
        // RMS of exponentially weighted offset differences.
        let previous = self.jitter * self.jitter;
        let difference = offset - self.last_offset;
        self.jitter = (previous + (difference * difference - previous) / 4.0)
            .max(0.0)
            .sqrt()
            .max(PRECISION_SECONDS);

        if self.state == State::Unset {
            // First usable datapoint: record it, discipline nothing yet.
            self.state = State::Synchronised;
            self.last_offset = offset;
            self.last_received_at = received_at;
            return Outcome {
                action: ClockAction::None,
                script: None,
                feedback: PollFeedback::Leave,
            };
        }
        self.last_offset = offset;
        self.last_received_at = received_at;
        self.leap = leap;

        let new_stratum = stratum.saturating_add(1);
        let script = if self.stratum != new_stratum {
            self.stratum = new_stratum;
            Some(ScriptAction::Stratum)
        } else {
            None
        };

        Outcome {
            action: self.slew_action(offset, leap),
            script,
            feedback: PollFeedback::Adjust,
        }
    }

    /// The zero-offset PLL update that follows a step, so the kernel does
    /// not keep slewing towards an offset the step already removed.
    pub fn post_step_slew(&mut self) -> ClockAction {
        self.slew_action(0.0, self.leap)
    }

    fn slew_action(&mut self, offset: f64, leap: Leap) -> ClockAction {
        let clamped = offset.clamp(-SLEW_THRESHOLD, SLEW_THRESHOLD);
        let offset_micros = (clamped * 1_000_000.0) as i64;
        let mut status = libc_sta_pll();
        if self.freqhold != 0 {
            if self.freqhold < 0 {
                // Hold the kernel frequency for the first adjustments so a
                // restart on a new network cannot destroy a good drift value.
                let magnitude = offset_micros.unsigned_abs().min(u64::from(u32::MAX)) as u32;
                self.freqhold = 1_i32
                    .saturating_add(MIN_FREQHOLD)
                    .saturating_add((magnitude >> 16) as i32);
            }
            self.freqhold = self.freqhold.saturating_sub(1);
            status |= libc_sta_freqhold();
        }
        match leap {
            Leap::AddSecond => status |= libc_sta_ins(),
            Leap::DeleteSecond => status |= libc_sta_del(),
            Leap::NoWarning | Leap::Unsynchronised => {}
        }
        let mut constant = i32::from(self.poll_exp) - 4;
        if self.offset_to_jitter_ratio >= TIMECONST_HACK_GATE {
            constant -= 1;
        }
        ClockAction::Slew {
            offset_micros,
            status,
            constant: constant.max(0),
        }
    }

    /// Applies the poll-interval hysteresis. `count` is added to the internal
    /// counter; crossing `POLLADJ_LIMIT` moves the exponent one step.
    ///
    /// Returns true when the exponent decreased, which the caller uses to pull
    /// pending queries forward.
    pub fn adjust_poll(&mut self, count: i32) -> bool {
        self.polladj_count = self.polladj_count.saturating_add(count);
        if self.polladj_count > POLLADJ_LIMIT {
            self.polladj_count = 0;
            if self.poll_exp < MAX_POLL_EXP {
                self.poll_exp += 1;
            }
            false
        } else if self.polladj_count < -POLLADJ_LIMIT || (count < 0 && self.poll_exp > BIG_POLL_EXP)
        {
            self.polladj_count = 0;
            if self.poll_exp > MIN_POLL_EXP {
                self.poll_exp -= 1;
                return true;
            }
            false
        } else {
            false
        }
    }

    /// The poll adjustment implied by an accepted update.
    pub fn apply_feedback(&mut self, feedback: PollFeedback) -> bool {
        match feedback {
            PollFeedback::Leave => false,
            PollFeedback::Adjust => {
                if self.offset_to_jitter_ratio <= POLLADJ_GATE {
                    self.adjust_poll(i32::from(MIN_POLL_EXP))
                } else {
                    self.adjust_poll(-i32::from(self.poll_exp).saturating_mul(2))
                }
            }
        }
    }

    /// Grows the poll interval by one hysteresis step, used when a peer is
    /// unusable or no peer could be selected.
    pub fn increase_poll(&mut self) {
        self.adjust_poll(i32::from(MIN_POLL_EXP));
    }

    /// Clamps the poll exponent and declares the local clock unsynchronised.
    pub fn clamp_poll_and_unsync(&mut self) {
        self.poll_exp = self.poll_exp.clamp(MIN_POLL_EXP, BIG_POLL_EXP);
        self.polladj_count = 0;
        self.stratum = MAX_STRATUM;
    }
}

fn ratio(magnitude: f64, jitter: f64) -> u32 {
    if jitter <= 0.0 || !magnitude.is_finite() {
        return 0;
    }
    let value = magnitude / jitter;
    if value >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        value as u32
    }
}

// These four mirror <sys/timex.h>; keeping them here lets the discipline stay
// a pure, host-testable module with no libc dependency of its own.
const fn libc_sta_pll() -> i32 {
    0x0001
}
const fn libc_sta_ins() -> i32 {
    0x0010
}
const fn libc_sta_del() -> i32 {
    0x0020
}
const fn libc_sta_freqhold() -> i32 {
    0x0080
}
