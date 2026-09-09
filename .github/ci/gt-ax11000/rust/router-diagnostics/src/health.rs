//! ICMP is a diagnostic, not proof of Internet/application availability.
use std::collections::VecDeque;

pub const HISTORY: usize = 600;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Sample {
    Reply(f64),
    Miss,
    Unknown,
}

/// Match the pinned router's BusyBox ping output. Parse failures and command
/// errors are UNKNOWN, not packet loss. Each probe sends exactly one packet.
pub fn parse_ping(success: bool, output: &str) -> Sample {
    if success {
        for line in output.lines() {
            if !line.contains("bytes from ") || !line.contains("seq=") || line.contains("DUP") {
                continue;
            }
            if let Some((_, timing)) = line.split_once("time=") {
                if let Some(value) = timing
                    .strip_suffix(" ms")
                    .and_then(|value| value.parse::<f64>().ok())
                {
                    if value.is_finite() && (0.0..=2000.0).contains(&value) {
                        return Sample::Reply(value);
                    }
                }
            }
        }
    } else if output.contains("1 packets transmitted, 0 packets received, 100% packet loss") {
        return Sample::Miss;
    }
    Sample::Unknown
}

#[derive(Clone, Debug)]
pub struct Point {
    pub epoch_ms: u64,
    pub uptime_ms: u64,
    pub lag_ms: u64,
    pub samples: [Sample; 3],
}

#[derive(Default)]
pub struct Window {
    pub points: VecDeque<Point>,
}

#[derive(Debug, Default)]
pub struct Stats {
    pub replies: usize,
    pub misses: usize,
    pub unknown: usize,
    pub p95_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub mean_ms: Option<f64>,
    /// Mean absolute difference of consecutive RTTs, NOT RTP/one-way jitter.
    pub rtt_variation_ms: Option<f64>,
    pub max_miss_streak: usize,
}

impl Window {
    pub fn push(&mut self, point: Point) {
        if self.points.len() == HISTORY {
            self.points.pop_front();
        }
        self.points.push_back(point);
    }
    pub fn stats(&self, target: usize) -> Stats {
        let mut result = Stats::default();
        let mut timings = Vec::new();
        let mut variation = 0.0;
        let mut pairs = 0;
        let mut previous: Option<f64> = None;
        let mut last_uptime = None;
        let mut streak = 0;
        for point in &self.points {
            if last_uptime.is_some_and(|last| point.uptime_ms.saturating_sub(last) > 1500) {
                previous = None;
                streak = 0;
            }
            last_uptime = Some(point.uptime_ms);
            match point.samples[target] {
                Sample::Reply(value) => {
                    timings.push(value);
                    result.replies += 1;
                    if let Some(previous) = previous {
                        variation += (value - previous).abs();
                        pairs += 1;
                    }
                    previous = Some(value);
                    streak = 0;
                }
                Sample::Miss => {
                    result.misses += 1;
                    streak += 1;
                    result.max_miss_streak = result.max_miss_streak.max(streak);
                    previous = None;
                }
                Sample::Unknown => {
                    result.unknown += 1;
                    previous = None;
                    streak = 0;
                }
            }
        }
        timings.sort_by(f64::total_cmp);
        if !timings.is_empty() {
            result.p95_ms = Some(timings[(timings.len() * 95).div_ceil(100) - 1]);
            result.max_ms = timings.last().copied();
            result.mean_ms = Some(timings.iter().sum::<f64>() / timings.len() as f64);
        }
        if pairs > 0 {
            result.rtt_variation_ms = Some(variation / pairs as f64);
        }
        result
    }
}

pub fn number(value: Option<f64>) -> String {
    value
        .filter(|value| value.is_finite())
        .map_or_else(|| "null".to_owned(), |value| format!("{value:.3}"))
}
pub fn sample_json(sample: Sample) -> String {
    match sample {
        Sample::Reply(value) => number(Some(value)),
        Sample::Miss => "-1".to_owned(),
        Sample::Unknown => "null".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn busybox_success_loss_and_errors_are_distinct() {
        assert_eq!(
            parse_ping(true, "24 bytes from 1.1.1.1: seq=0 ttl=56 time=12.345 ms\n"),
            Sample::Reply(12.345)
        );
        assert_eq!(
            parse_ping(
                false,
                "1 packets transmitted, 0 packets received, 100% packet loss"
            ),
            Sample::Miss
        );
        for text in [
            "ping: network unreachable",
            "time=1 ms",
            "24 bytes from 1.1.1.1: seq=0 time=NaN ms",
            "24 bytes from 1.1.1.1: seq=0 time=-1 ms",
        ] {
            assert_eq!(parse_ping(true, text), Sample::Unknown);
            assert_eq!(parse_ping(false, text), Sample::Unknown);
        }
    }
    #[test]
    fn bounded_history_gaps_and_variation() {
        let mut window = Window::default();
        for (index, sample) in [
            Sample::Reply(10.0),
            Sample::Reply(30.0),
            Sample::Miss,
            Sample::Miss,
            Sample::Unknown,
            Sample::Miss,
        ]
        .into_iter()
        .enumerate()
        {
            window.push(Point {
                epoch_ms: 0,
                uptime_ms: index as u64 * 1000,
                lag_ms: 0,
                samples: [sample; 3],
            });
        }
        let stats = window.stats(0);
        assert_eq!(
            (
                stats.replies,
                stats.misses,
                stats.unknown,
                stats.max_miss_streak
            ),
            (2, 3, 1, 2)
        );
        assert_eq!(stats.rtt_variation_ms, Some(20.0));
        assert_eq!(stats.p95_ms, Some(30.0));
        for index in 0..1000 {
            window.push(Point {
                epoch_ms: 0,
                uptime_ms: index * 1000,
                lag_ms: 0,
                samples: [Sample::Unknown; 3],
            });
        }
        assert_eq!(window.points.len(), HISTORY);
    }
    #[test]
    fn scheduler_gap_does_not_extend_an_outage() {
        let mut window = Window::default();
        for uptime_ms in [1000, 2000, 9000] {
            window.push(Point {
                epoch_ms: 0,
                uptime_ms,
                lag_ms: 0,
                samples: [Sample::Miss; 3],
            });
        }
        assert_eq!(window.stats(0).max_miss_streak, 2);
    }
}
