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

/// Whether the selected hardware implements ICCM boot-phase region enforcement.
pub const HAS_BOOT_FLOW_INTEGRITY: bool = cfg!(hw_rev = "latest");

/// Whether subsystem builds support hardware ICCM write measurement.
pub const HAS_ICCM_WRITE_MEASUREMENT: bool = cfg!(hw_rev = "latest");

/// Commit and lock all four shadow-hardened ICCM-relative boot regions.
pub fn program_iccm_regions(soc_ifc: &mut soc_ifc::SocIfcReg, bounds: [u32; 4]) -> bool {
    #[cfg(hw_rev = "latest")]
    {
        let regs = soc_ifc.regs_mut();
        for _ in 0..2 {
            regs.internal_iccm_fmc_start_addr()
                .write(|w| w.addr(bounds[0]));
        }
        for _ in 0..2 {
            regs.internal_iccm_fmc_end_addr()
                .write(|w| w.addr(bounds[1]));
        }
        for _ in 0..2 {
            regs.internal_iccm_rt_start_addr()
                .write(|w| w.addr(bounds[2]));
        }
        for _ in 0..2 {
            regs.internal_iccm_rt_end_addr()
                .write(|w| w.addr(bounds[3]));
        }
        if regs.internal_iccm_fmc_start_addr().read().addr() != bounds[0]
            || regs.internal_iccm_fmc_end_addr().read().addr() != bounds[1]
            || regs.internal_iccm_rt_start_addr().read().addr() != bounds[2]
            || regs.internal_iccm_rt_end_addr().read().addr() != bounds[3]
        {
            return false;
        }
        regs.internal_iccm_region_lock().write(|w| w.lock(true));
        regs.internal_iccm_region_lock().read().lock()
    }
    #[cfg(hw_rev = "2.1")]
    {
        let _ = (soc_ifc, bounds);
        false
    }
}

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
