// Licensed under the Apache-2.0 license
//
#![no_std]
#![cfg_attr(hw_rev = "latest", doc = "Hardware revision: _latest_")]
#![cfg_attr(hw_rev = "2.1", doc = "Hardware revision: _2.1_")]
#![cfg_attr(hw_rev = "2.0", doc = "Hardware revision: _2.0_")]

#[cfg(not(any(hw_rev = "latest", hw_rev = "2.1", hw_rev = "2.0")))]
compile_error!("Select one of the supported HW revisions by setting the `hw_rev` cfg");

#[cfg(hw_rev = "latest")]
pub use caliptra_registers_latest::*;

/// Hardware version represented by the selected register definitions.
#[cfg(hw_rev = "latest")]
pub const HW_REVISION: &str = "2.2";

#[cfg(hw_rev = "2.1")]
pub use caliptra_registers_rev_2_1::*;

/// Hardware version represented by the selected register definitions.
#[cfg(hw_rev = "2.1")]
pub const HW_REVISION: &str = "2.1";

#[cfg(hw_rev = "2.0")]
compile_error!("TODO: add v2.0 HW register definitions");
