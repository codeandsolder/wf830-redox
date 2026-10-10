#![no_std]

//! Typed codecs for the small GCT LAPI subset needed to bring up the WF830.
//!
//! This is a clean implementation from recovered wire behavior. It does not
//! expose the historical OEM C ABI and intentionally omits commands until
//! their payload format is proven.

pub mod at;
pub mod attach;
pub mod common;
pub mod emm;
pub mod misc;
pub mod pdn;
pub mod plmn;
pub mod rrc;
pub mod uicc;

#[cfg(test)]
mod tests;
