#![forbid(unsafe_op_in_unsafe_fn)]

use core::ffi::c_int;

const DISCONNECTED: c_int = 0;
const CONNECTED: c_int = 1;
const CONNECTED_TO_DISCONNECTED: c_int = 3;
const DISCONNECTED_TO_CONNECTED: c_int = 4;
const PHYSICAL_RECONNECT: c_int = 5;
const SET_PIN: c_int = 7;
const SET_USB_SCAN: c_int = 8;

const CASE_SAME_SUBNET: c_int = 6;
const IDLE_COUNTER: c_int = -1;
const START_COUNTER: c_int = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkState {
    Disconnected,
    Connected,
    PhysicalReconnect,
    SetPin,
    SetUsbScan,
}

impl LinkState {
    fn from_legacy(value: c_int, special_states_enabled: bool) -> Option<Self> {
        match value {
            DISCONNECTED => Some(Self::Disconnected),
            CONNECTED => Some(Self::Connected),
            PHYSICAL_RECONNECT => Some(Self::PhysicalReconnect),
            SET_PIN if special_states_enabled => Some(Self::SetPin),
            SET_USB_SCAN if special_states_enabled => Some(Self::SetUsbScan),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WanduckTransitionInput {
    pub observed_state: c_int,
    pub previous_state: c_int,
    pub changed_state: c_int,
    pub disconnect_count: c_int,
    pub maximum_disconnect_count: c_int,
    pub data_limit_reached: c_int,
    pub disconnect_case: c_int,
    pub wan_disabled: c_int,
    pub ppp_auth_failed: c_int,
    pub other_configured: c_int,
    pub other_link_up: c_int,
    pub other_data_limited: c_int,
    pub special_states_enabled: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WanduckTransitionOutput {
    pub previous_state: c_int,
    pub changed_state: c_int,
    pub disconnect_count: c_int,
}

pub fn transition(input: WanduckTransitionInput) -> Option<WanduckTransitionOutput> {
    let observed = LinkState::from_legacy(input.observed_state, input.special_states_enabled != 0)?;
    let mut output = WanduckTransitionOutput {
        previous_state: input.previous_state,
        changed_state: input.changed_state,
        disconnect_count: input.disconnect_count,
    };

    if observed == LinkState::PhysicalReconnect {
        output.changed_state = PHYSICAL_RECONNECT;
        output.previous_state = DISCONNECTED;
        if input.other_configured != 0 && input.other_link_up != 0 {
            output.disconnect_count = START_COUNTER;
        }
        return Some(output);
    }

    if input.data_limit_reached != 0 {
        output.changed_state = if input.previous_state == CONNECTED {
            CONNECTED_TO_DISCONNECTED
        } else {
            DISCONNECTED
        };
        output.previous_state = DISCONNECTED;
        output.disconnect_count = if input.other_configured != 0
            && input.other_link_up != 0
            && input.other_data_limited == 0
        {
            input.maximum_disconnect_count
        } else {
            IDLE_COUNTER
        };
        return Some(output);
    }

    match observed {
        LinkState::SetPin => {
            output.changed_state = SET_PIN;
            output.previous_state = DISCONNECTED;
            output.disconnect_count = IDLE_COUNTER;
        }
        LinkState::SetUsbScan => {
            output.changed_state = CONNECTED_TO_DISCONNECTED;
            output.previous_state = DISCONNECTED;
            output.disconnect_count = IDLE_COUNTER;
        }
        LinkState::Connected => {
            output.changed_state = if input.previous_state == DISCONNECTED {
                DISCONNECTED_TO_CONNECTED
            } else {
                CONNECTED
            };
            output.previous_state = CONNECTED;
            output.disconnect_count = IDLE_COUNTER;
        }
        LinkState::Disconnected => {
            output.changed_state = if input.previous_state == CONNECTED {
                CONNECTED_TO_DISCONNECTED
            } else {
                DISCONNECTED
            };
            output.previous_state = DISCONNECTED;

            if input.disconnect_case == CASE_SAME_SUBNET || input.other_link_up == 0 {
                output.disconnect_count = IDLE_COUNTER;
            } else if input.wan_disabled == 0 && input.other_configured != 0 {
                if input.disconnect_count == IDLE_COUNTER {
                    output.disconnect_count = START_COUNTER;
                }
            } else if input.ppp_auth_failed != 0 {
                output.disconnect_count = IDLE_COUNTER;
            }
        }
        LinkState::PhysicalReconnect => unreachable!("handled before data-limit priority"),
    }

    Some(output)
}

/// Apply the pure dual-WAN failover/failback state transition.
///
/// Returns `1` and initializes `output` when the observed legacy state is
/// recognized. Unknown states and invalid pointers return `0`, allowing the C
/// caller to use its legacy fallback without accepting a partially initialized
/// result.
///
/// # Safety
///
/// `input` must point to a readable `WanduckTransitionInput` and `output` must
/// point to writable `WanduckTransitionOutput` storage. The allocations may not
/// overlap.
#[no_mangle]
pub unsafe extern "C" fn rust_wanduck_transition(
    input: *const WanduckTransitionInput,
    output: *mut WanduckTransitionOutput,
) -> c_int {
    if input.is_null() || output.is_null() {
        return 0;
    }

    // SAFETY: Pointer validity and non-overlap are required by the ABI contract.
    let Some(result) = transition(unsafe { *input }) else {
        return 0;
    };
    // SAFETY: `output` is valid writable storage by the ABI contract.
    unsafe { output.write(result) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(observed_state: c_int, previous_state: c_int) -> WanduckTransitionInput {
        WanduckTransitionInput {
            observed_state,
            previous_state,
            changed_state: 99,
            disconnect_count: IDLE_COUNTER,
            maximum_disconnect_count: 12,
            data_limit_reached: 0,
            disconnect_case: 0,
            wan_disabled: 0,
            ppp_auth_failed: 0,
            other_configured: 1,
            other_link_up: 1,
            other_data_limited: 0,
            special_states_enabled: 1,
        }
    }

    #[test]
    fn connected_edges_are_typed_and_reset_counter() {
        let up = transition(input(CONNECTED, DISCONNECTED)).unwrap();
        assert_eq!(up.changed_state, DISCONNECTED_TO_CONNECTED);
        assert_eq!(up.previous_state, CONNECTED);
        assert_eq!(up.disconnect_count, IDLE_COUNTER);

        let steady = transition(input(CONNECTED, CONNECTED)).unwrap();
        assert_eq!(steady.changed_state, CONNECTED);
    }

    #[test]
    fn disconnected_edge_starts_failover_counter_once() {
        let down = transition(input(DISCONNECTED, CONNECTED)).unwrap();
        assert_eq!(down.changed_state, CONNECTED_TO_DISCONNECTED);
        assert_eq!(down.previous_state, DISCONNECTED);
        assert_eq!(down.disconnect_count, START_COUNTER);

        let mut counting = input(DISCONNECTED, DISCONNECTED);
        counting.disconnect_count = 4;
        assert_eq!(transition(counting).unwrap().disconnect_count, 4);
    }

    #[test]
    fn disconnected_line_does_not_count_without_viable_alternate() {
        let mut no_link = input(DISCONNECTED, CONNECTED);
        no_link.other_link_up = 0;
        assert_eq!(transition(no_link).unwrap().disconnect_count, IDLE_COUNTER);

        let mut same_subnet = input(DISCONNECTED, CONNECTED);
        same_subnet.disconnect_case = CASE_SAME_SUBNET;
        assert_eq!(
            transition(same_subnet).unwrap().disconnect_count,
            IDLE_COUNTER
        );
    }

    #[test]
    fn auth_failure_stops_single_line_retry_counter() {
        let mut auth = input(DISCONNECTED, CONNECTED);
        auth.other_configured = 0;
        auth.ppp_auth_failed = 1;
        auth.disconnect_count = 3;
        assert_eq!(transition(auth).unwrap().disconnect_count, IDLE_COUNTER);
    }

    #[test]
    fn physical_reconnect_has_priority_over_data_limit() {
        let mut reconnect = input(PHYSICAL_RECONNECT, CONNECTED);
        reconnect.data_limit_reached = 1;
        reconnect.disconnect_count = IDLE_COUNTER;
        let output = transition(reconnect).unwrap();
        assert_eq!(output.changed_state, PHYSICAL_RECONNECT);
        assert_eq!(output.previous_state, DISCONNECTED);
        assert_eq!(output.disconnect_count, START_COUNTER);
    }

    #[test]
    fn data_limit_uses_maximum_only_for_viable_alternate() {
        let mut limited = input(DISCONNECTED, CONNECTED);
        limited.data_limit_reached = 1;
        let output = transition(limited).unwrap();
        assert_eq!(output.changed_state, CONNECTED_TO_DISCONNECTED);
        assert_eq!(output.disconnect_count, 12);

        limited.other_data_limited = 1;
        assert_eq!(transition(limited).unwrap().disconnect_count, IDLE_COUNTER);
    }

    #[test]
    fn usb_attention_states_never_start_retry_counter() {
        let pin = transition(input(SET_PIN, CONNECTED)).unwrap();
        assert_eq!(pin.changed_state, SET_PIN);
        assert_eq!(pin.disconnect_count, IDLE_COUNTER);

        let scan = transition(input(SET_USB_SCAN, CONNECTED)).unwrap();
        assert_eq!(scan.changed_state, CONNECTED_TO_DISCONNECTED);
        assert_eq!(scan.disconnect_count, IDLE_COUNTER);
    }

    #[test]
    fn disabled_usb_states_and_unknown_values_use_c_fallback() {
        let mut disabled = input(SET_PIN, CONNECTED);
        disabled.special_states_enabled = 0;
        assert_eq!(transition(disabled), None);
        assert_eq!(transition(input(1234, CONNECTED)), None);
    }

    #[test]
    fn ffi_rejects_null_and_does_not_write_for_unknown_state() {
        let mut output = WanduckTransitionOutput {
            previous_state: 10,
            changed_state: 11,
            disconnect_count: 12,
        };
        // SAFETY: Passing null deliberately exercises the guarded ABI path.
        assert_eq!(
            unsafe { rust_wanduck_transition(core::ptr::null(), &mut output) },
            0
        );

        let unknown = input(1234, CONNECTED);
        // SAFETY: Both pointers reference valid, non-overlapping local values.
        assert_eq!(unsafe { rust_wanduck_transition(&unknown, &mut output) }, 0);
        assert_eq!(output.disconnect_count, 12);
    }
}
