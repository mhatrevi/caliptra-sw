/*++

Licensed under the Apache-2.0 license.

File Name:

    loaded_image.rs

Abstract:

    File contains helpers for verifying firmware after it has been loaded.

--*/

#[cfg(feature = "cfi")]
use caliptra_cfi_derive::cfi_mod_fn;
use caliptra_common::verifier::ImageSource;
use caliptra_drivers::{
    pcr_log::PCR_ID_ICCM_CURRENT, Array4x12, CaliptraResult, PcrBank, Sha2DigestOpTrait,
    Sha2_512_384, Sha2_512_384Acc, ShaAccLockState, SocIfc, StreamEndianness,
};
use caliptra_error::CaliptraError;
use caliptra_image_types::{ImageManifest, ImageTocEntry};
use zerocopy::IntoBytes;

const SOURCE_CHUNK_WORDS: usize = 32;
const MEASUREMENT_COMPLETION_POLLS: usize = 100_000;

/// Bind the expected write-stream measurement to the authenticated staging bytes.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub(super) fn prepare_iccm_measurement(
    manifest: &ImageManifest,
    source: &ImageSource<'_, '_>,
    include_fmc: bool,
    soc_ifc: &SocIfc,
    sha: &mut Sha2_512_384,
    sha_acc: &mut Sha2_512_384Acc,
) -> CaliptraResult<Option<Array4x12>> {
    if !caliptra_registers::HAS_ICCM_WRITE_MEASUREMENT {
        return Ok(None);
    }
    if !soc_ifc.subsystem_mode() {
        if soc_ifc.debug_locked() {
            return Err(CaliptraError::ROM_ICCM_MEASUREMENT_UNSUPPORTED);
        }
        return Ok(None);
    }

    for (entry, invalid_entry) in [
        (
            &manifest.fmc,
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_ENTRY_POINT_INVALID,
        ),
        (
            &manifest.runtime,
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_ENTRY_POINT_INVALID,
        ),
    ] {
        let end = entry
            .load_addr
            .checked_add(entry.size)
            .ok_or(invalid_entry)?;
        if !(entry.load_addr..end).contains(&entry.entry_point) {
            return Err(invalid_entry);
        }
    }

    let entries = [
        (
            &manifest.fmc,
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE,
            CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH,
        ),
        (
            &manifest.runtime,
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE,
            CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH,
        ),
    ];
    let mut stream = sha.sha384_digest_init()?;
    let first_entry = usize::from(!include_fmc);
    for (entry, digest_failure, digest_mismatch) in &entries[first_entry..] {
        if entry.size == 0 || !entry.size.is_multiple_of(4) || !entry.offset.is_multiple_of(4) {
            return Err(CaliptraError::FW_PROC_INVALID_IMAGE_SIZE);
        }
        let mut component = sha_acc
            .try_start_operation(ShaAccLockState::NotAcquired)?
            .ok_or(CaliptraError::DRIVER_SHA2_512_384_ACC_DIGEST_START_OP_FAILURE)?;
        // DATAIN is packed from raw bytes as little-endian dwords; do not swap them.
        component.stream_start_384(entry.size, StreamEndianness::Reorder)?;
        let mut buffer = [0u32; SOURCE_CHUNK_WORDS];
        let mut copied = 0u32;
        while copied < entry.size {
            let count = (entry.size - copied).min((SOURCE_CHUNK_WORDS * 4) as u32);
            let words = &mut buffer[..count as usize / 4];
            let source_offset = entry
                .offset
                .checked_add(copied)
                .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS)?;
            match source {
                ImageSource::MboxMemory(image) => {
                    let start = source_offset as usize;
                    let end = start
                        .checked_add(count as usize)
                        .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS)?;
                    let bytes = image
                        .get(start..end)
                        .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS)?;
                    words.as_mut_bytes().copy_from_slice(bytes);
                }
                ImageSource::Axi { dma, axi_start } => {
                    let address = u64::from(*axi_start)
                        .checked_add(u64::from(source_offset))
                        .ok_or(CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS)?;
                    dma.read_buffer(address.into(), words);
                }
                ImageSource::FipsTest { .. } => {
                    return Err(CaliptraError::IMAGE_VERIFIER_ERR_DIGEST_OUT_OF_BOUNDS);
                }
            }
            // Both engines receive the same captured chunk, never a second staging read.
            let bytes = words.as_bytes();
            component
                .stream_update(bytes)
                .map_err(|_| *digest_failure)?;
            stream.update(bytes).map_err(|_| *digest_failure)?;
            copied += count;
        }
        let mut actual = Array4x12::default();
        component
            .stream_finish_384(&mut actual)
            .map_err(|_| *digest_failure)?;
        if actual.0 != entry.digest {
            return Err(*digest_mismatch);
        }
        caliptra_cfi_lib::cfi_assert_eq_12_words(&entry.digest, &actual.0);
    }
    let mut digest = Array4x12::default();
    stream.finalize(&mut digest)?;
    let mut extend_block = [0u8; 96];
    let digest_bytes: [u8; 48] = digest.into();
    extend_block[48..].copy_from_slice(&digest_bytes);
    sha.sha384_digest(&extend_block).map(Some)
}

/// Finalize hardware measurement without reading ICCM and compare its current PCR.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub(super) fn verify_iccm_measurement(
    expected: &Array4x12,
    soc_ifc: &mut SocIfc,
    sha_acc: &mut Sha2_512_384Acc,
    pcr_bank: &PcrBank,
) -> CaliptraResult<()> {
    soc_ifc.set_iccm_lock(true);
    for _ in 0..MEASUREMENT_COMPLETION_POLLS {
        if let Some(operation) = sha_acc.try_start_operation(ShaAccLockState::NotAcquired)? {
            drop(operation);
            let actual = pcr_bank.read_pcr(PCR_ID_ICCM_CURRENT);
            if actual != *expected {
                return Err(CaliptraError::ROM_ICCM_MEASUREMENT_MISMATCH);
            }
            caliptra_cfi_lib::cfi_assert_eq_12_words(&expected.0, &actual.0);
            return Ok(());
        }
    }
    Err(CaliptraError::ROM_ICCM_MEASUREMENT_TIMEOUT)
}

/// Verify the FMC and runtime images after they have been loaded into ICCM.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub(super) fn verify_fmc_and_runtime(
    manifest: &ImageManifest,
    sha2_512_384: &mut Sha2_512_384,
) -> CaliptraResult<()> {
    verify_entry(
        &manifest.fmc,
        sha2_512_384,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_FAILURE,
        CaliptraError::IMAGE_VERIFIER_ERR_FMC_DIGEST_MISMATCH,
    )?;
    verify_runtime(manifest, sha2_512_384)
}

/// Verify the runtime image after it has been loaded into ICCM.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
pub(super) fn verify_runtime(
    manifest: &ImageManifest,
    sha2_512_384: &mut Sha2_512_384,
) -> CaliptraResult<()> {
    verify_entry(
        &manifest.runtime,
        sha2_512_384,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_FAILURE,
        CaliptraError::IMAGE_VERIFIER_ERR_RUNTIME_DIGEST_MISMATCH,
    )
}

/// Verify one loaded image entry against its manifest digest.
#[cfg_attr(feature = "cfi", cfi_mod_fn)]
fn verify_entry(
    entry: &ImageTocEntry,
    sha2_512_384: &mut Sha2_512_384,
    digest_failure: CaliptraError,
    digest_mismatch: CaliptraError,
) -> CaliptraResult<()> {
    // SAFETY: Image verification has already validated that this entry's load range is
    // entirely within ICCM and that the entry size is non-zero. ROM has just copied this
    // range into ICCM, so it is valid to read it as bytes for the post-copy digest check.
    let image =
        unsafe { core::slice::from_raw_parts(entry.load_addr as *const u8, entry.size as usize) };
    let actual = sha2_512_384
        .sha384_digest(image)
        .map_err(|_| digest_failure)?
        .0;

    if entry.digest != actual {
        Err(digest_mismatch)?;
    }
    caliptra_cfi_lib::cfi_assert_eq_12_words(&entry.digest, &actual);

    Ok(())
}
