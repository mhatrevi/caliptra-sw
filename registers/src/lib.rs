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

/// Whether HMAC requires an explicit final-block command.
pub const HMAC_HAS_LAST: bool = cfg!(hw_rev = "latest");

/// Set the HMAC final-block modifier when supported by the selected hardware.
/// Legacy hardware computes the outer hash after every block.
pub fn hmac512_ctrl_last(
    ctrl: hmac::regs::Hmac512CtrlWriteVal,
    last: bool,
) -> hmac::regs::Hmac512CtrlWriteVal {
    #[cfg(hw_rev = "latest")]
    {
        ctrl.last(last)
    }
    #[cfg(hw_rev = "2.1")]
    {
        let _ = last;
        ctrl
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_last_preserves_other_control_fields() {
        let control = hmac::regs::Hmac512CtrlWriteVal::from(0)
            .init(true)
            .mode(true)
            .csr_mode(true);
        let last = u32::from(hmac512_ctrl_last(control, true));
        assert_eq!(last, 0x19 | if HMAC_HAS_LAST { 0x20 } else { 0 });
        assert_eq!(u32::from(hmac512_ctrl_last(control, false)), 0x19);
    }
}
