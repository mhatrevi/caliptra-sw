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

#[cfg(hw_rev = "2.1")]
pub use caliptra_registers_rev_2_1::*;

#[cfg(hw_rev = "2.0")]
compile_error!("TODO: add v2.0 HW register definitions");

#[cfg(hw_rev = "latest")]
pub use soc_ifc::regs::{
    EntropyConfig0ReadVal as CptraItrngEntropyConfig0ReadVal,
    EntropyConfig0WriteVal as CptraItrngEntropyConfig0WriteVal,
    EntropyConfig1ReadVal as CptraItrngEntropyConfig1ReadVal,
    EntropyConfig1WriteVal as CptraItrngEntropyConfig1WriteVal,
};

#[cfg(hw_rev = "2.1")]
pub use soc_ifc::regs::{
    CptraItrngEntropyConfig0ReadVal, CptraItrngEntropyConfig0WriteVal,
    CptraItrngEntropyConfig1ReadVal, CptraItrngEntropyConfig1WriteVal,
};

/// Whether the selected hardware revision requires HMAC final-block signaling.
pub const HMAC_LAST_BLOCK_SUPPORTED: bool = cfg!(hw_rev = "latest");

/// Returns the hardware ML-DSA signature-verification verdict when supported.
#[inline(always)]
pub fn mldsa_verify_pass(status: abr::regs::MldsaStatusReadVal) -> bool {
    #[cfg(hw_rev = "latest")]
    {
        status.verify_pass()
    }

    #[cfg(hw_rev = "2.1")]
    {
        let _ = status;
        true
    }
}

/// Programs and locks the ICCM regions used by the hardware boot-flow monitor.
#[inline(always)]
pub fn configure_iccm_regions(
    soc_ifc: &mut soc_ifc::SocIfcReg,
    fmc_start: u32,
    fmc_end: u32,
    runtime_start: u32,
    runtime_end: u32,
) {
    #[cfg(hw_rev = "latest")]
    {
        let regs = soc_ifc.regs_mut();

        for _ in 0..2 {
            regs.internal_iccm_fmc_start_addr()
                .write(|w| w.addr(fmc_start));
            regs.internal_iccm_fmc_end_addr().write(|w| w.addr(fmc_end));
            regs.internal_iccm_rt_start_addr()
                .write(|w| w.addr(runtime_start));
            regs.internal_iccm_rt_end_addr()
                .write(|w| w.addr(runtime_end));
        }

        regs.internal_iccm_region_lock().write(|w| w.lock(true));
    }

    #[cfg(hw_rev = "2.1")]
    {
        let _ = (soc_ifc, fmc_start, fmc_end, runtime_start, runtime_end);
    }
}

/// Sets the HMAC final-block control bit when supported by the selected hardware revision.
#[inline(always)]
pub fn set_hmac_last_block(
    value: hmac::regs::Hmac512CtrlWriteVal,
    last: bool,
) -> hmac::regs::Hmac512CtrlWriteVal {
    #[cfg(hw_rev = "latest")]
    {
        value.last(last)
    }

    #[cfg(hw_rev = "2.1")]
    {
        let _ = last;
        value
    }
}
