//! Memory-safe Link Layer Topology Discovery (LLTD) responder library.
//!
//! This crate replaces the closed `release/src/router/lltd.arm/lld2d.hnd`
//! binary that ASUS ships for the GT-AX11000. Frame preparation and admission
//! are separate from emission: [`Responder::prepare`] returns a
//! [`PreparedReply`], admission returns an [`AdmittedReply`], and only a
//! successful transport callback commits the token and generation. Dropped
//! permits and failed sends record no reply. All socket I/O, privileges and
//! `unsafe` live in the binary's `sys` module.
//!
//! The wire layout implemented here was established from the shipped blob
//! (`packetio_recv_handler`, `packetio_tx_hello` and the 24-entry `Tlvs`
//! table) cross-checked against the public MS-LLTD description. The exact
//! provenance of every constant is recorded next to it.
//!
//! Only a deliberately reduced subset of the protocol is answered; see
//! [`responder`] for the list and the reasoning.

#![forbid(unsafe_code)]

pub mod device;
pub mod limit;
pub mod responder;
pub mod tlv;
pub mod wire;

pub use device::Device;
pub use limit::RateLimiter;
pub use responder::{
    AdmittedReply, Dropped, PreparedReply, Responder, MAX_AMPLIFICATION, MAX_RESPONSE_LEN,
};
pub use wire::{Frame, Opcode, ETHERTYPE_LLTD, MAX_FRAME_LEN, MIN_FRAME_LEN};
