use crate::PolicyError;

/// QoS modes which are implemented entirely by the local kernel/userspace
/// stack.  Mode 1 is deliberately absent: on this platform it selects the
/// proprietary Trend Micro/BWDPI engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalQosMode {
    Traditional,
    BandwidthLimiter,
}

impl LocalQosMode {
    pub fn parse(value: &str) -> Result<Self, PolicyError> {
        match value {
            "0" => Ok(Self::Traditional),
            "2" => Ok(Self::BandwidthLimiter),
            _ => Err(PolicyError::InvalidValue("local QoS mode")),
        }
    }
}

pub fn local_qos_mode_allowed(value: &str) -> bool {
    LocalQosMode::parse(value).is_ok()
}

/// Validate the bandwidth values used by the local HTB/fq_codel path.  Values
/// are integer kbit/s, bounded to keep legacy shell-script arithmetic in range.
pub fn validate_bandwidth_kbit(value: &str) -> Result<u32, PolicyError> {
    if value.is_empty() {
        return Err(PolicyError::Empty);
    }
    if value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PolicyError::InvalidFormat);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|rate| (1..=10_000_000).contains(rate))
        .ok_or(PolicyError::InvalidValue("QoS bandwidth"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proprietary_and_unknown_modes_fail_closed() {
        for value in ["", "1", "3", "4", "9", "adaptive", "01", "-1"] {
            assert!(!local_qos_mode_allowed(value), "accepted {value}");
        }
        assert_eq!(LocalQosMode::parse("0"), Ok(LocalQosMode::Traditional));
        assert_eq!(LocalQosMode::parse("2"), Ok(LocalQosMode::BandwidthLimiter));
    }

    #[test]
    fn bandwidth_is_bounded_decimal_only() {
        for value in ["1", "1000", "10000000"] {
            assert!(validate_bandwidth_kbit(value).is_ok());
        }
        for value in ["", "0", "10000001", "1.5", "+1", " 1", "1kbit"] {
            assert!(validate_bandwidth_kbit(value).is_err(), "accepted {value}");
        }
    }
}
