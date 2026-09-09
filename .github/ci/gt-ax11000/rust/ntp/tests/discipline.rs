//! Clock-discipline tests.
//!
//! The discipline never calls a system function: it returns a [`ClockAction`]
//! that the daemon applies. `FakeClock` below stands in for the kernel, so no
//! test in this file can touch the real system time.

use ntp::client::Sample;
use ntp::clock::{
    is_fit, log2_to_seconds, select_peer, Candidate, ClockAction, Discipline, PeerFilter,
    ScriptAction, BIG_POLL_EXP, MAX_POLL_EXP, MAX_STRATUM, MIN_POLL_EXP, SLEW_THRESHOLD,
    STEP_THRESHOLD,
};
use ntp::packet::Leap;

/// Records everything the daemon would have done to the kernel clock.
#[derive(Debug, Default)]
struct FakeClock {
    now: f64,
    steps: Vec<f64>,
    slews: Vec<(i64, i32, i32)>,
}

impl FakeClock {
    fn apply(&mut self, action: ClockAction) {
        match action {
            ClockAction::None => {}
            ClockAction::Step(offset) => {
                self.now += offset;
                self.steps.push(offset);
            }
            ClockAction::Slew {
                offset_micros,
                status,
                constant,
            } => self.slews.push((offset_micros, status, constant)),
        }
    }
}

fn sample(offset: f64, received_at: f64, precision: i8) -> Sample {
    Sample {
        offset,
        delay: 0.01,
        raw_delay: 0.01,
        received_at,
        stratum: 2,
        leap: Leap::NoWarning,
        precision,
        root_delay: 0.01,
        root_dispersion: 0.01,
        reference_id: *b"TEST",
    }
}

#[test]
fn the_first_sample_records_but_does_not_discipline() {
    let mut clock = FakeClock::default();
    let mut discipline = Discipline::new();
    let outcome = discipline.update(0.1, 1_000.0, 2, Leap::NoWarning);
    clock.apply(outcome.action);
    assert_eq!(outcome.action, ClockAction::None);
    assert!(outcome.script.is_none());
    assert!(clock.steps.is_empty() && clock.slews.is_empty());
}

#[test]
fn an_offset_above_the_step_threshold_steps_and_runs_the_step_script() {
    let mut clock = FakeClock {
        now: 1_000.0,
        ..FakeClock::default()
    };
    let mut discipline = Discipline::new();
    // Seed the state machine, then hand it a large offset.
    let _ = discipline.update(0.01, 1_000.0, 2, Leap::NoWarning);
    let outcome = discipline.update(4.5, 1_064.0, 2, Leap::NoWarning);
    clock.apply(outcome.action);

    assert_eq!(outcome.action, ClockAction::Step(4.5));
    assert_eq!(outcome.script, Some(ScriptAction::Step));
    assert_eq!(clock.steps, vec![4.5]);
    assert!((clock.now - 1_004.5).abs() < 1e-9);
    // busybox declares the clock unsynchronised again right after a step and
    // clamps the poll interval, so server mode goes quiet until the next
    // accepted datapoint.
    assert_eq!(discipline.stratum, MAX_STRATUM);
    assert!(!discipline.is_synchronised());
    assert!(discipline.poll_exp >= MIN_POLL_EXP && discipline.poll_exp <= BIG_POLL_EXP);
}

#[test]
fn exactly_the_step_threshold_still_slews() {
    let mut discipline = Discipline::new();
    let _ = discipline.update(0.0, 1_000.0, 2, Leap::NoWarning);
    let outcome = discipline.update(STEP_THRESHOLD, 1_064.0, 2, Leap::NoWarning);
    assert!(
        matches!(outcome.action, ClockAction::Slew { .. }),
        "{:?}",
        outcome.action
    );
}

#[test]
fn a_small_offset_slews_within_the_kernel_window() {
    let mut clock = FakeClock::default();
    let mut discipline = Discipline::new();
    let _ = discipline.update(0.0, 1_000.0, 2, Leap::NoWarning);
    let outcome = discipline.update(0.9, 1_064.0, 2, Leap::NoWarning);
    clock.apply(outcome.action);

    let (offset_micros, status, constant) = clock.slews[0];
    // 0.9 s is below the step threshold but above the slew threshold, so the
    // kernel gets the clamped 0.5 s.
    assert_eq!(offset_micros, (SLEW_THRESHOLD * 1_000_000.0) as i64);
    assert_eq!(status & 0x0001, 0x0001, "STA_PLL");
    assert_eq!(status & 0x0080, 0x0080, "STA_FREQHOLD on the first updates");
    assert!(constant >= 0);
    assert!(discipline.is_synchronised());
    assert_eq!(discipline.stratum, 3, "our stratum is the peer's plus one");
}

#[test]
fn leap_warnings_reach_the_kernel_status_word() {
    for (leap, bit) in [(Leap::AddSecond, 0x0010), (Leap::DeleteSecond, 0x0020)] {
        let mut clock = FakeClock::default();
        let mut discipline = Discipline::new();
        let _ = discipline.update(0.0, 1_000.0, 2, leap);
        let outcome = discipline.update(0.01, 1_064.0, 2, leap);
        clock.apply(outcome.action);
        let (_, status, _) = clock.slews[0];
        assert_eq!(status & bit, bit, "{leap:?}");
    }
}

#[test]
fn a_stratum_change_runs_the_stratum_script() {
    let mut discipline = Discipline::new();
    let _ = discipline.update(0.0, 1_000.0, 2, Leap::NoWarning);
    let first = discipline.update(0.01, 1_064.0, 2, Leap::NoWarning);
    assert_eq!(first.script, Some(ScriptAction::Stratum));
    let second = discipline.update(0.01, 1_128.0, 2, Leap::NoWarning);
    assert_eq!(second.script, None, "no change, no script");
    let third = discipline.update(0.01, 1_192.0, 4, Leap::NoWarning);
    assert_eq!(third.script, Some(ScriptAction::Stratum));
    assert_eq!(discipline.stratum, 5);
}

#[test]
fn an_old_or_repeated_datapoint_is_never_used_twice() {
    let mut discipline = Discipline::new();
    let _ = discipline.update(0.0, 1_000.0, 2, Leap::NoWarning);
    let _ = discipline.update(0.01, 1_064.0, 2, Leap::NoWarning);
    for received_at in [1_064.0, 1_000.0, 900.0] {
        let outcome = discipline.update(5.0, received_at, 2, Leap::NoWarning);
        assert_eq!(
            outcome.action,
            ClockAction::None,
            "received_at {received_at} must be ignored"
        );
        assert!(outcome.script.is_none());
    }
}

#[test]
fn a_non_finite_offset_is_ignored_rather_than_applied() {
    let mut discipline = Discipline::new();
    for offset in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let outcome = discipline.update(offset, 2_000.0, 2, Leap::NoWarning);
        assert_eq!(outcome.action, ClockAction::None);
    }
}

#[test]
fn the_poll_interval_grows_and_shrinks_within_its_bounds() {
    let mut discipline = Discipline::new();
    assert_eq!(discipline.poll_exp, MIN_POLL_EXP);
    for _ in 0..200 {
        discipline.increase_poll();
    }
    assert_eq!(discipline.poll_exp, MAX_POLL_EXP);
    assert_eq!(discipline.poll_seconds(), 1 << MAX_POLL_EXP);
    for _ in 0..200 {
        discipline.adjust_poll(-1_000);
    }
    assert_eq!(discipline.poll_exp, MIN_POLL_EXP);
}

#[test]
fn the_clock_filter_seeds_every_slot_from_the_first_reply() {
    let mut filter = PeerFilter::new();
    assert!(!filter.is_reachable());
    filter.note_query_sent();
    filter.accept(&sample(0.25, 1_000.0, -20), 1_000.0);
    assert!(filter.is_reachable());
    assert_eq!(filter.reachable_bits, 1);
    assert!((filter.offset - 0.25).abs() < 1e-12);
    // Every slot holds the same value, so the jitter is the precision floor
    // rather than an artefact of seven fabricated zeroes.
    assert!((filter.jitter - 0.002).abs() < 1e-12, "{}", filter.jitter);
}

#[test]
fn the_clock_filter_reports_the_newest_offset_and_the_spread_as_jitter() {
    let mut filter = PeerFilter::new();
    let mut now = 1_000.0;
    for (index, offset) in [0.10, 0.12, 0.11, 0.13].into_iter().enumerate() {
        filter.note_query_sent();
        filter.accept(&sample(offset, now, -20), now);
        now += 64.0;
        assert!(
            (filter.offset - offset).abs() < 1e-12,
            "datapoint {index} must be the reported offset"
        );
    }
    assert!(filter.jitter > 0.0);
    assert!(filter.dispersion > 0.0);
    assert!(filter.root_distance(now) > filter.dispersion);
}

#[test]
fn an_unanswered_query_shifts_the_reachability_register_to_zero() {
    let mut filter = PeerFilter::new();
    filter.note_query_sent();
    filter.accept(&sample(0.01, 1_000.0, -20), 1_000.0);
    for _ in 0..8 {
        filter.note_query_sent();
    }
    assert!(!filter.is_reachable(), "eight losses clear the register");
}

#[test]
fn a_step_rebases_the_filter_instead_of_discarding_it() {
    let mut filter = PeerFilter::new();
    filter.note_query_sent();
    filter.accept(&sample(0.2, 1_000.0, -20), 1_000.0);
    filter.rebase_after_step(0.2, 1_000.2);
    // A small step keeps the datapoints and moves them with the clock.
    assert!(filter.offset.abs() < 1e-12, "{}", filter.offset);

    let mut coarse = PeerFilter::new();
    coarse.note_query_sent();
    coarse.accept(&sample(0.2, 1_000.0, -20), 1_000.0);
    coarse.rebase_after_step(5_000.0, 6_000.0);
    assert!(coarse.offset.abs() < 1e-12);
    assert!((coarse.received_at - 6_000.0).abs() < 1e-9);
}

#[test]
fn a_peer_answering_fewer_than_two_of_eight_queries_is_never_selected() {
    let candidate = Candidate {
        index: 0,
        offset: 0.0,
        root_distance: 0.01,
        stratum: 2,
        reachable_bits: 0b0000_0001,
    };
    assert!(!is_fit(&candidate, MIN_POLL_EXP, false));
    assert!(
        !is_fit(&candidate, MIN_POLL_EXP, true),
        "-t must not weaken the reachability test"
    );
    let reachable = Candidate {
        reachable_bits: 0b0000_0011,
        ..candidate
    };
    assert!(is_fit(&reachable, MIN_POLL_EXP, false));
}

#[test]
fn a_far_away_peer_is_unfit_unless_the_network_is_trusted() {
    let distant = Candidate {
        index: 0,
        offset: 0.0,
        // Above MAXDIST (1 s), which is exactly what -t waives.
        root_distance: 4.0,
        stratum: 2,
        reachable_bits: 0b1111_1111,
    };
    assert!(!is_fit(&distant, MIN_POLL_EXP, false));
    assert!(is_fit(&distant, MIN_POLL_EXP, true));
}

#[test]
fn selection_prefers_the_lower_stratum_then_the_shorter_distance() {
    let candidates = [
        Candidate {
            index: 7,
            offset: 0.010,
            root_distance: 0.05,
            stratum: 3,
            reachable_bits: 0xff,
        },
        Candidate {
            index: 9,
            offset: 0.011,
            root_distance: 0.05,
            stratum: 2,
            reachable_bits: 0xff,
        },
    ];
    assert_eq!(select_peer(&candidates), Some(9));

    let same_stratum = [
        Candidate {
            index: 1,
            offset: 0.010,
            root_distance: 0.20,
            stratum: 2,
            reachable_bits: 0xff,
        },
        Candidate {
            index: 2,
            offset: 0.011,
            root_distance: 0.02,
            stratum: 2,
            reachable_bits: 0xff,
        },
    ];
    assert_eq!(select_peer(&same_stratum), Some(2));
}

#[test]
fn two_peers_that_cannot_both_be_right_select_nobody() {
    // Intervals [9.9, 10.1] and [-0.1, 0.1] do not intersect and neither can
    // out-vote the other, so no peer is trusted.
    let candidates = [
        Candidate {
            index: 0,
            offset: 10.0,
            root_distance: 0.1,
            stratum: 2,
            reachable_bits: 0xff,
        },
        Candidate {
            index: 1,
            offset: 0.0,
            root_distance: 0.1,
            stratum: 2,
            reachable_bits: 0xff,
        },
    ];
    assert_eq!(select_peer(&candidates), None);
    assert_eq!(select_peer(&[]), None);
}

#[test]
fn a_majority_outvotes_a_single_falseticker() {
    let candidates = [
        Candidate {
            index: 0,
            offset: 0.00,
            root_distance: 0.05,
            stratum: 2,
            reachable_bits: 0xff,
        },
        Candidate {
            index: 1,
            offset: 0.01,
            root_distance: 0.05,
            stratum: 2,
            reachable_bits: 0xff,
        },
        Candidate {
            index: 2,
            offset: 30.0,
            root_distance: 0.05,
            stratum: 2,
            reachable_bits: 0xff,
        },
    ];
    let selected = select_peer(&candidates).expect("a majority exists");
    assert!(selected == 0 || selected == 1, "picked {selected}");
}

#[test]
fn a_hostile_precision_byte_cannot_overflow_the_dispersion() {
    for precision in [i8::MIN, -64, -9, 0, 63, i8::MAX] {
        let seconds = log2_to_seconds(precision);
        assert!(seconds.is_finite(), "precision {precision}");
        let mut filter = PeerFilter::new();
        filter.note_query_sent();
        filter.accept(&sample(0.01, 1_000.0, precision), 1_000.0);
        assert!(filter.dispersion.is_finite());
        assert!(filter.root_distance(1_000.0).is_finite());
    }
}
