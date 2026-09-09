#![forbid(unsafe_code)]
//! Optional connection collector; the security/VPN work does not depend on it.
pub use router_vpn_audit::capture;
pub mod health;
pub mod wifi;
