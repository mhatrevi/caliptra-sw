// Licensed under the Apache-2.0 license

use crate::helpers;
use caliptra_api::SocManager;
use caliptra_builder::ImageOptions;
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, QuotePcrsEcc384Req, QuotePcrsEcc384Resp,
};
use caliptra_common::RomBootStatus::ColdResetComplete;
use caliptra_error::CaliptraError;
use caliptra_hw_model::{
    BootParams, DefaultHwModel, DeviceLifecycle, Fuses, HwModel, InitParams, SecurityState,
};
use caliptra_image_types::ImageBundle;
use caliptra_test::{bytes_to_be_words_48, image_pk_desc_hash};
use openssl::sha::sha384;
use zerocopy::FromBytes;

fn model_and_image(subsystem_mode: bool, debug_locked: bool) -> (DefaultHwModel, ImageBundle) {
    let image = helpers::build_image_bundle(ImageOptions::default());
    let (vendor_pk_hash, owner_pk_hash) = image_pk_desc_hash(&image.manifest);
    let rom = caliptra_builder::build_firmware_rom(helpers::rom_from_env()).unwrap();
    let security_state = *SecurityState::default()
        .set_debug_locked(debug_locked)
        .set_device_lifecycle(DeviceLifecycle::Production);
    let model = caliptra_hw_model::new(
        InitParams {
            rom: &rom,
            subsystem_mode,
            security_state,
            fuses: Fuses {
                vendor_pk_hash,
                owner_pk_hash,
                fuse_pqc_key_type: image.manifest.pqc_key_type as u32,
                ..Default::default()
            },
            ..Default::default()
        },
        BootParams::default(),
    )
    .unwrap();
    (model, image)
}

fn read_pcr(model: &mut DefaultHwModel, index: u32) -> [u8; 48] {
    model.read_pcr(u8::try_from(index).unwrap())
}

fn expected_extension(previous: [u8; 48], stream: &[u8]) -> [u8; 48] {
    let digest = sha384(stream);
    let mut extended = [0u8; 96];
    extended[..48].copy_from_slice(&previous);
    extended[48..].copy_from_slice(&digest);
    sha384(&extended)
}

fn expected_current(image: &ImageBundle) -> [u8; 48] {
    let mut stream = image.fmc.clone();
    stream.extend_from_slice(&image.runtime);
    expected_extension([0; 48], &stream)
}

fn wait_for_runtime(model: &mut DefaultHwModel) {
    model.step_until_or_timeout("Runtime entry or a boot-integrity error", 40_000_000, |m| {
        m.soc_ifc().cptra_flow_status().read().ready_for_runtime()
            || u32::from(m.soc_ifc().cptra_hw_error_fatal().read()) != 0
            || m.soc_ifc().cptra_fw_error_fatal().read() != 0
    });
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
    let hardware_error: u32 = model.soc_ifc().cptra_hw_error_fatal().read().into();
    assert_eq!(hardware_error, 0);
    assert!(model
        .soc_ifc()
        .cptra_flow_status()
        .read()
        .ready_for_runtime());
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_subsystem_current_and_warm_journey() {
    if !caliptra_registers::HAS_ICCM_WRITE_MEASUREMENT {
        return;
    }
    for debug_locked in [false, true] {
        let (mut model, image) = model_and_image(true, debug_locked);
        helpers::test_upload_firmware(
            &mut model,
            &image.to_bytes().unwrap(),
            caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
                .unwrap(),
        );
        wait_for_runtime(&mut model);
        let current = read_pcr(&mut model, 4);
        let journey = read_pcr(&mut model, 5);
        assert_eq!(current, expected_current(&image));
        assert_eq!(journey, current);

        model.warm_reset_flow().unwrap();
        wait_for_runtime(&mut model);
        assert_eq!(read_pcr(&mut model, 4), current);
        assert_eq!(read_pcr(&mut model, 5), journey);
    }
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_update_runtime_only_journey_and_larger_bounds() {
    if !caliptra_registers::HAS_ICCM_WRITE_MEASUREMENT {
        return;
    }
    let (mut model, mut image) = model_and_image(true, true);
    let pqc_key_type =
        caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
            .unwrap();
    helpers::test_upload_firmware(&mut model, &image.to_bytes().unwrap(), pqc_key_type);
    wait_for_runtime(&mut model);
    let previous = read_pcr(&mut model, 5);
    assert_eq!(previous, expected_current(&image));

    image.runtime.extend_from_slice(&[0xa5; 64]);
    image.manifest.runtime.size += 64;
    image.manifest.runtime.digest = bytes_to_be_words_48(&sha384(&image.runtime));
    let updated = crate::test_update_reset::rebuild_image_after_toc_change(&mut image);
    model
        .start_mailbox_execute(CommandId::FIRMWARE_LOAD.into(), &updated)
        .unwrap();
    assert_eq!(model.finish_mailbox_execute(), Ok(None));
    // Debug-locked firmware hides boot status; match only fresh Runtime output.
    model
        .output()
        .set_search_term("RT listening for mailbox commands...");
    model.step_until_or_timeout("Runtime re-entry after update", 40_000_000, |m| {
        m.output().search_matched()
            || u32::from(m.soc_ifc().cptra_hw_error_fatal().read()) != 0
            || m.soc_ifc().cptra_fw_error_fatal().read() != 0
    });
    wait_for_runtime(&mut model);
    let current = expected_extension([0; 48], &image.runtime);
    let journey = expected_extension(previous, &image.runtime);
    assert_eq!(read_pcr(&mut model, 4), current);
    assert_eq!(read_pcr(&mut model, 5), journey);
    assert_ne!(journey, current);

    let mut request = MailboxReq::QuotePcrsEcc384(QuotePcrsEcc384Req {
        hdr: MailboxReqHeader { chksum: 0 },
        nonce: [0; 32],
    });
    request.populate_chksum().unwrap();
    let response = model
        .mailbox_execute(
            CommandId::QUOTE_PCRS_ECC384.into(),
            request.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let quote = QuotePcrsEcc384Resp::read_from_bytes(response.as_slice()).unwrap();
    assert_eq!(quote.pcrs[4], current);
    assert_eq!(quote.pcrs[5], journey);

    model.warm_reset_flow().unwrap();
    wait_for_runtime(&mut model);
    assert_eq!(read_pcr(&mut model, 4), current);
    assert_eq!(read_pcr(&mut model, 5), journey);
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_production_passive_rejected_before_copy() {
    if !caliptra_registers::HAS_ICCM_WRITE_MEASUREMENT {
        return;
    }
    let (mut model, image) = model_and_image(false, true);
    helpers::assert_fatal_fw_load(
        &mut model,
        caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
            .unwrap(),
        &image.to_bytes().unwrap(),
        CaliptraError::ROM_ICCM_MEASUREMENT_UNSUPPORTED,
    );
    assert_eq!(read_pcr(&mut model, 4), [0; 48]);
    assert_eq!(read_pcr(&mut model, 5), [0; 48]);
}

#[test]
#[cfg_attr(
    any(
        feature = "fpga_realtime",
        feature = "fpga_subsystem",
        feature = "verilator"
    ),
    ignore
)]
fn test_iccm_integrity_debug_passive_keeps_readback() {
    let (mut model, image) = model_and_image(false, false);
    helpers::test_upload_firmware(
        &mut model,
        &image.to_bytes().unwrap(),
        caliptra_image_types::FwVerificationPqcKeyType::from_u8(image.manifest.pqc_key_type)
            .unwrap(),
    );
    model.step_until_boot_status(ColdResetComplete.into(), true);
    assert_eq!(model.soc_ifc().cptra_fw_error_fatal().read(), 0);
}
