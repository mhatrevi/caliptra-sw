// Licensed under the Apache-2.0 license

use caliptra_api::{
    mailbox::{GetLdevEcc384CertReq, MailboxRespHeader, RevokeExportedCdiHandleReq},
    SocManager,
};
use caliptra_common::mailbox_api::{
    CommandId, MailboxReq, MailboxReqHeader, SignWithExportedEcdsaReq, SignWithExportedEcdsaResp,
};
use caliptra_dpe::{
    commands::{Command, DeriveContextCmd, DeriveContextFlags, RotateCtxCmd, RotateCtxFlags},
    context::ContextHandle,
    error::DpeErrorCode,
    response::{DeriveContextExportedCdiResp, DeriveContextResp, NewHandleResp, Response},
    TCI_SIZE,
};
use caliptra_dpe_crypto::{CryptoError, MAX_EXPORTED_CDI_SIZE};
use caliptra_error::CaliptraError;
use caliptra_hw_model::{HwModel, ModelError, SecurityState};
use caliptra_runtime::{CaliptraDpeProfile, RtBootStatus, TciMeasurement};
use caliptra_x509::{Ecdsa384CertBuilder, Ecdsa384Signature};
use openssl::{
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    nid::Nid,
    pkey::{PKey, Private},
    sha::sha384,
    stack::Stack,
    x509::{
        store::X509StoreBuilder,
        verify::{X509VerifyFlags, X509VerifyParam},
        X509Ref, X509StoreContext, X509VerifyResult, X509,
    },
};
use x509_cert::{
    certificate::Version,
    der::{Decode, Encode},
    ext::{
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, KeyUsages, SubjectKeyIdentifier,
        },
        AsExtension,
    },
    name::Name,
    spki::{SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef},
    Certificate, TbsCertificate,
};
use zerocopy::{FromBytes, IntoBytes};

use crate::common::{
    assert_error, execute_dpe_cmd, get_certs, get_ecc_fmc_alias_cert, get_rt_alias_ecc384_cert,
    run_rt_test, DpeResult, RuntimeTestArgs, TEST_DIGEST,
};

fn check_certificate_signature(
    sign_resp: &SignWithExportedEcdsaResp,
    exported_cdi_resp: &DeriveContextExportedCdiResp,
) -> bool {
    let sig = EcdsaSig::from_private_components(
        BigNum::from_slice(&sign_resp.signature_r).unwrap(),
        BigNum::from_slice(&sign_resp.signature_s).unwrap(),
    )
    .unwrap();

    // Verify that the certificate from DeriveContext can verify the signature.
    let x509 = X509::from_der(
        &exported_cdi_resp.new_certificate[..exported_cdi_resp
            .header
            .certificate_size
            .try_into()
            .unwrap()],
    )
    .unwrap();
    let ec_pub_key = x509.public_key().unwrap().ec_key().unwrap();
    if !sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap() {
        return false;
    }

    // Let's also check that the returned public key can verify the signature.
    let x = BigNum::from_slice(&sign_resp.derived_pubkey_x).unwrap();
    let y = BigNum::from_slice(&sign_resp.derived_pubkey_y).unwrap();
    let ec_pub_key = EcKey::from_public_key_affine_coordinates(
        &EcGroup::from_curve_name(Nid::SECP384R1).unwrap(),
        &x,
        &y,
    )
    .unwrap();
    sig.verify(&TEST_DIGEST, &ec_pub_key).unwrap()
}

#[test]
fn test_sign_with_exported_cdi() {
    // Exports a CDI and then signs a well known hash.
    // Verifies the signature using the CA certificate paired with the export-cdi, as well as the
    // public key returned by SIGN_WITH_EXPORTED_ECDSA.
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let derive_ctx_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));
}

fn pathlen_test_tbs(
    issuer: &X509,
    subject_key: &PKey<Private>,
    subject_name: &str,
    serial: u32,
    ca: bool,
) -> Vec<u8> {
    let issuer_tbs = Certificate::from_der(&issuer.to_der().unwrap())
        .unwrap()
        .tbs_certificate;
    let (_, issuer_key_id) = issuer_tbs.get::<SubjectKeyIdentifier>().unwrap().unwrap();
    let public_key_der = subject_key.public_key_to_der().unwrap();
    let subject: Name = format!("CN={subject_name}").parse().unwrap();
    let subject_key_id =
        SubjectKeyIdentifier::try_from(SubjectPublicKeyInfoRef::from_der(&public_key_der).unwrap())
            .unwrap();
    // Leave subordinate CAs unconstrained so only the inherited limits are tested.
    let basic_constraints = BasicConstraints {
        ca,
        path_len_constraint: None,
    };
    let key_usage = KeyUsage(if ca {
        KeyUsages::DigitalSignature | KeyUsages::KeyCertSign
    } else {
        KeyUsages::DigitalSignature.into()
    });
    let authority_key_id = AuthorityKeyIdentifier {
        key_identifier: Some(issuer_key_id.0),
        ..Default::default()
    };
    let extensions = vec![
        basic_constraints.to_extension(&subject, &[]).unwrap(),
        key_usage.to_extension(&subject, &[]).unwrap(),
        subject_key_id.to_extension(&subject, &[]).unwrap(),
        authority_key_id.to_extension(&subject, &[]).unwrap(),
    ];

    TbsCertificate {
        version: Version::V3,
        serial_number: serial.into(),
        signature: issuer_tbs.signature,
        issuer: issuer_tbs.subject,
        validity: issuer_tbs.validity,
        subject,
        subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(&public_key_der).unwrap(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    }
    .to_der()
    .unwrap()
}

fn pathlen_test_sign(tbs: &[u8], issuer_key: &PKey<Private>) -> Ecdsa384Signature {
    let signature = EcdsaSig::sign(&sha384(tbs), &issuer_key.ec_key().unwrap()).unwrap();
    Ecdsa384Signature {
        r: signature.r().to_vec_padded(48).unwrap().try_into().unwrap(),
        s: signature.s().to_vec_padded(48).unwrap().try_into().unwrap(),
    }
}

fn pathlen_test_cert(tbs: &[u8], signature: &Ecdsa384Signature) -> X509 {
    let builder = Ecdsa384CertBuilder::new(tbs, signature).unwrap();
    let mut der = vec![0; builder.len()];
    builder.build(&mut der).unwrap();
    X509::from_der(&der).unwrap()
}

fn check_exported_cdi_chain_pathlen(intermediate_ca_count: u32, expect_success: bool) {
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until_ready_for_runtime();

    let ldev_resp = get_certs::<GetLdevEcc384CertReq>(&mut model);
    let ldev_cert = X509::from_der(&ldev_resp.data[..ldev_resp.data_size as usize]).unwrap();
    let fmc_resp = get_ecc_fmc_alias_cert(&mut model);
    let fmc_cert = X509::from_der(&fmc_resp.data[..fmc_resp.data_size as usize]).unwrap();
    let rt_resp = get_rt_alias_ecc384_cert(&mut model);
    let rt_der = &rt_resp.data[..rt_resp.data_size as usize];
    let rt_cert = X509::from_der(rt_der).unwrap();
    let rt_tbs = Certificate::from_der(rt_der).unwrap().tbs_certificate;
    let (critical, constraints) = rt_tbs.get::<BasicConstraints>().unwrap().unwrap();
    assert!(critical);
    assert!(constraints.ca);
    assert_eq!(constraints.path_len_constraint, Some(4));
    let rt_pathlen = constraints.path_len_constraint.unwrap();

    let derive_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let Some(Response::DeriveContextExportedCdi(derive_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&derive_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected exported-CDI certificate and handle");
    };
    let dpe_der = &derive_resp.new_certificate[..derive_resp.header.certificate_size as usize];
    let dpe_cert = X509::from_der(dpe_der).unwrap();
    let dpe_tbs = Certificate::from_der(dpe_der).unwrap().tbs_certificate;
    let (critical, constraints) = dpe_tbs.get::<BasicConstraints>().unwrap().unwrap();
    assert!(critical);
    assert!(constraints.ca);
    assert_eq!(constraints.path_len_constraint, None);
    assert!(dpe_tbs
        .get::<KeyUsage>()
        .unwrap()
        .unwrap()
        .1
        .key_cert_sign());
    assert!(dpe_cert.verify(&rt_cert.public_key().unwrap()).unwrap());

    let mut chain = Stack::new().unwrap();
    chain.push(fmc_cert).unwrap();
    chain.push(rt_cert).unwrap();
    chain.push(dpe_cert.clone()).unwrap();
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    let mut issuer_cert = dpe_cert;
    let mut issuer_key: Option<PKey<Private>> = None;
    for index in 1..=intermediate_ca_count {
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let tbs = pathlen_test_tbs(
            &issuer_cert,
            &key,
            &format!("Intermediate CA {index}"),
            index,
            true,
        );
        let signature = if let Some(key) = &issuer_key {
            pathlen_test_sign(&tbs, key)
        } else {
            let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
                hdr: MailboxReqHeader { chksum: 0 },
                exported_cdi_handle: derive_resp.header.exported_cdi,
                tbs: sha384(&tbs),
            });
            cmd.populate_chksum().unwrap();
            let resp = model
                .mailbox_execute(
                    CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
                    cmd.as_bytes().unwrap(),
                )
                .unwrap()
                .unwrap();
            let resp = SignWithExportedEcdsaResp::ref_from_bytes(&resp).unwrap();
            Ecdsa384Signature {
                r: resp.signature_r,
                s: resp.signature_s,
            }
        };
        let cert = pathlen_test_cert(&tbs, &signature);
        assert!(cert.verify(&issuer_cert.public_key().unwrap()).unwrap());
        chain.push(cert.clone()).unwrap();
        issuer_cert = cert;
        issuer_key = Some(key);
    }

    let leaf_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let leaf_tbs = pathlen_test_tbs(&issuer_cert, &leaf_key, "Leaf", 100, false);
    let leaf_signature = pathlen_test_sign(&leaf_tbs, issuer_key.as_ref().unwrap());
    let leaf_cert = pathlen_test_cert(&leaf_tbs, &leaf_signature);
    assert!(leaf_cert
        .verify(&issuer_cert.public_key().unwrap())
        .unwrap());

    // Trust LDevID, not DPE or RT Alias, so their inherited constraints are checked.
    let mut roots = X509StoreBuilder::new().unwrap();
    roots.add_cert(ldev_cert).unwrap();
    roots
        .set_flags(X509VerifyFlags::X509_STRICT | X509VerifyFlags::PARTIAL_CHAIN)
        .unwrap();
    let mut params = X509VerifyParam::new().unwrap();
    params.set_depth(16);
    roots.set_param(&params).unwrap();
    let roots = roots.build();
    let common_name = |cert: &X509Ref| {
        cert.subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .as_utf8()
            .unwrap()
            .to_string()
    };
    X509StoreContext::new()
        .unwrap()
        .init(&roots, &leaf_cert, &chain, |ctx| {
            println!(
                "\n[pathlen] === {} case: {intermediate_ca_count} intermediate CAs below DPE ===",
                if expect_success {
                    "POSITIVE"
                } else {
                    "NEGATIVE"
                }
            );
            println!(
                "[pathlen] CA1 signature verified against DPE CA after SIGN_WITH_EXPORTED_ECDSA"
            );
            println!("[pathlen] Trust anchor: LDevID; RT Alias and DPE are not trusted directly");
            let success = ctx.verify_cert().unwrap();
            println!(
                "[pathlen] OpenSSL verification: {} (error {}: {})",
                if success { "ACCEPTED" } else { "REJECTED" },
                ctx.error().as_raw(),
                ctx.error()
            );
            let built_chain = ctx.chain().unwrap();
            let rt_depth = built_chain
                .iter()
                .position(|cert| cert.to_der().unwrap() == rt_der)
                .unwrap();
            let mut ca_count_below_rt = 0;
            println!("[pathlen] OpenSSL-built chain (trust anchor -> leaf):");
            for (depth, cert) in built_chain.iter().enumerate().rev() {
                let tbs = Certificate::from_der(&cert.to_der().unwrap())
                    .unwrap()
                    .tbs_certificate;
                let (_, constraints) = tbs.get::<BasicConstraints>().unwrap().unwrap();
                if depth < rt_depth
                    && constraints.ca
                    && cert.subject_name().try_cmp(cert.issuer_name()).unwrap()
                        != std::cmp::Ordering::Equal
                {
                    ca_count_below_rt += 1;
                }
                println!(
                    "[pathlen]   depth {depth}: {} | CA={} | pathLen={}",
                    common_name(cert),
                    constraints.ca,
                    constraints
                        .path_len_constraint
                        .map_or_else(|| "none".to_string(), |limit| limit.to_string())
                );
            }
            println!(
                "[pathlen] RT Alias pathLenConstraint={rt_pathlen}; \
                 non-self-issued CAs below it={ca_count_below_rt} (leaf excluded)"
            );
            if !success {
                println!(
                    "[pathlen] Error certificate: {} at depth {}",
                    common_name(ctx.current_cert().unwrap()),
                    ctx.error_depth()
                );
            }
            assert_eq!(
                ca_count_below_rt,
                usize::try_from(intermediate_ca_count + 1).unwrap()
            );
            assert_eq!(
                success,
                expect_success,
                "OpenSSL: {} at depth {}",
                ctx.error(),
                ctx.error_depth()
            );
            if expect_success {
                assert_eq!(ctx.error(), X509VerifyResult::OK);
                assert_eq!(
                    ctx.chain().unwrap().len(),
                    usize::try_from(intermediate_ca_count).unwrap() + 5
                );
                println!(
                    "[pathlen] PASS: leaf accepted with {ca_count_below_rt} CAs \
                     below RT Alias (limit {rt_pathlen})"
                );
            } else {
                // X509_V_ERR_PATH_LENGTH_EXCEEDED.
                assert_eq!(ctx.error().as_raw(), 25, "{}", ctx.error());
                assert_eq!(ctx.error_depth(), intermediate_ca_count + 2);
                assert_eq!(ctx.current_cert().unwrap().to_der().unwrap(), rt_der);
                println!(
                    "[pathlen] PASS: expected rejection at RT Alias; \
                     {ca_count_below_rt} subordinate CAs exceed limit {rt_pathlen}"
                );
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn test_exported_cdi_chain_pathlen_allows_three_intermediates() {
    check_exported_cdi_chain_pathlen(3, true);
}

#[test]
fn test_exported_cdi_chain_pathlen_rejects_four_intermediates() {
    check_exported_cdi_chain_pathlen(4, false);
}

#[test]
fn test_sign_with_exported_incorrect_cdi_handle() {
    // Verifies that an invalid CDI handle cannot derive an exported ECDSA key.
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let get_cert_chain_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&get_cert_chain_cmd),
        DpeResult::Success,
    );

    match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFF; MAX_EXPORTED_CDI_SIZE],
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        result.unwrap_err(),
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED.into(),
        )
    );
}

#[test]
fn test_sign_with_exported_never_derived() {
    // Verifies that an exported ECDSA key cannot be derived without first exporting a CDI.
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: [0xFF; MAX_EXPORTED_CDI_SIZE],
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );
    assert_eq!(
        result.unwrap_err(),
        ModelError::MailboxCmdFailed(
            CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED.into(),
        )
    );
}

#[test]
fn test_sign_with_exported_cdi_measurement_update_duplicate_cdi() {
    // Tests the following sequence:
    // 1. Export a CDI.
    //   - This CDI is know as the "original_cdi".
    // 2. Verify signing of `SIGN_WITH_EXPORTED_ECDSA` with the CA signed by the "original_cdi".
    // 3. Add a new measurement using the `DeriveContextFlags::RECURSIVE` flag.
    // 4. Try to export a new CDI, verify that it failes with
    //    `DpeErrorCode::Crypto(CryptoError::ExportedCdiHandleDuplicateCdi))`.
    // 5. Verify signing of `SIGN_WITH_EXPORTED_ECDSA` with the CA signed by the "original_cdi".
    //    This ensures that the failure in step 4 did not overwrite the "original_cdi".
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT
            | DeriveContextFlags::ALLOW_RECURSIVE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &original_cdi_resp));

    let measurement_cmd = DeriveContextCmd {
        data: TciMeasurement([0xa; TCI_SIZE]),
        flags: DeriveContextFlags::RECURSIVE,
        tci_type: if model.subsystem_mode() {
            // MCU ROM stashes field_entropy_state as the last measurement,
            // making it the default context with tci_type 0.
            0
        } else {
            u32::from_le_bytes(*b"CCIV")
        },
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&measurement_cmd),
        DpeResult::Success,
    );

    let Some(Response::Error(e)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::DpeCmdFailure,
    ) else {
        panic!("Expected the second export cdi command to fail.")
    };
    assert_eq!(
        e.status,
        DpeErrorCode::Crypto(CryptoError::ExportedCdiHandleDuplicateCdi).get_error_code()
    );

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &original_cdi_resp));
}

#[test]
fn test_sign_with_exported_cdi_measurement_update() {
    // Tests the following sequence:
    // 1. Export a CDI.
    //   - This CDI is know as the "original_cdi".
    // 2. Add a new measurement using the `DeriveContextFlags::RECURSIVE` flag.
    // 3. Revoke the "original_cdi".
    // 3. Export a new CDI known as the "updated_cdi".
    // 4. Verify that the signature from `SIGN_WITH_EXPORTED_ECDSA` cannot be verified by the CA
    //    cert paired with the "original_cdi".
    // 5. Verify signing of `SIGN_WITH_EXPORTED_ECDSA` with the CA cert signed by the "updated_cdi"
    //    to make sure that we can create valid signatures that map with the "update_cdi" CA cert.
    // 6. Double check that the certificate and export_cdi have changed between "original_cdi" and
    //    "update_cdi".
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT
            | DeriveContextFlags::ALLOW_RECURSIVE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(original_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let measurement_cmd = DeriveContextCmd {
        data: TciMeasurement([0xa; TCI_SIZE]),
        flags: DeriveContextFlags::RECURSIVE,
        tci_type: if model.subsystem_mode() {
            // MCU ROM stashes field_entropy_state as the last measurement,
            // making it the default context with tci_type 0.
            0
        } else {
            u32::from_le_bytes(*b"CCIV")
        },
        ..Default::default()
    };

    let _ = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&measurement_cmd),
        DpeResult::Success,
    );

    let mut cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: original_cdi_resp.header.exported_cdi,
    });
    cmd.populate_chksum().unwrap();

    match model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        cmd.as_bytes().unwrap(),
    ) {
        Ok(_) => (),
        Err(e) => panic!("REVOKE_EXPORTED_CDI_HANDLE failed with {:?}", e),
    }

    let Some(Response::DeriveContextExportedCdi(updated_cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: updated_cdi_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();

    // The original CDI was revoked.
    assert!(!check_certificate_signature(sign_resp, &original_cdi_resp));
    assert!(check_certificate_signature(sign_resp, &updated_cdi_resp));
    assert_ne!(original_cdi_resp, updated_cdi_resp);
    assert_ne!(
        original_cdi_resp.header.exported_cdi,
        updated_cdi_resp.header.exported_cdi
    );
    assert_ne!(
        original_cdi_resp.new_certificate,
        updated_cdi_resp.new_certificate
    );
}

#[test]
fn test_sign_with_revoked_exported_cdi() {
    // This tests the following sequence:
    // 1. Create an exported-cdi
    // 2. Check that we can create a valid signature with it.
    // 3. Revoke the exported-cdi.
    // 4. Verify that we can no longer sign with the exported-cdi and that `SIGN_WITH_EXPORTED_ECDSA`
    // returns `CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED`.
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut sign_cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    sign_cmd.populate_chksum().unwrap();

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .expect("SIGN_WITH_EXPORTED_ECDSA should not fail until the handle is revoked")
        .unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &cdi_resp));

    let mut revoke_cmd = MailboxReq::RevokeExportedCdiHandle(RevokeExportedCdiHandleReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.header.exported_cdi,
    });
    revoke_cmd.populate_chksum().unwrap();

    match model.mailbox_execute(
        CommandId::REVOKE_EXPORTED_CDI_HANDLE.into(),
        revoke_cmd.as_bytes().unwrap(),
    ) {
        Ok(_) => (),
        Err(e) => panic!("REVOKE_EXPORTED_CDI_HANDLE failed with {:?}", e),
    }

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        sign_cmd.as_bytes().unwrap(),
    );

    assert_error(
        &mut model,
        CaliptraError::RUNTIME_SIGN_WITH_EXPORTED_ECDSA_KEY_DERIVIATION_FAILED,
        result.err().unwrap(),
    );
}

#[test]
fn test_sign_with_disabled_attestation() {
    // This tests the following sequence:
    // 1. Create an exported-cdi
    // 2. Check that we can create a valid signature with it.
    // 3. Disable attestation
    // 4. Verify that the signature is no longer valid.
    let mut model = run_rt_test(RuntimeTestArgs::default());
    model.step_until(|m| {
        m.soc_ifc().cptra_boot_status().read() == u32::from(RtBootStatus::RtReadyForCommands)
    });

    let export_cdi_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
    };

    let Some(Response::DeriveContextExportedCdi(cdi_resp)) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::from(&export_cdi_cmd),
        DpeResult::Success,
    ) else {
        panic!("expected derive context resp!")
    };

    let mut sign_cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: cdi_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    sign_cmd.populate_chksum().unwrap();

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &cdi_resp));

    let payload = MailboxReqHeader {
        chksum: caliptra_common::checksum::calc_checksum(
            u32::from(CommandId::DISABLE_ATTESTATION),
            &[],
        ),
    };
    let resp = model
        .mailbox_execute(
            u32::from(CommandId::DISABLE_ATTESTATION),
            payload.as_bytes(),
        )
        .unwrap()
        .unwrap();
    let resp_hdr = MailboxRespHeader::read_from_bytes(resp.as_bytes()).unwrap();
    assert_eq!(
        resp_hdr.fips_status,
        MailboxRespHeader::FIPS_STATUS_APPROVED
    );

    let result = model
        .mailbox_execute(
            CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
            sign_cmd.as_bytes().unwrap(),
        )
        .unwrap()
        .unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(result.as_bytes()).unwrap();
    assert!(!check_certificate_signature(sign_resp, &cdi_resp));
}

#[test]
fn test_sign_with_exported_cdi_warm_reset() {
    // 1. Exports a CDI and then signs a well known hash.
    // 2. Verifies the signature using the CA certificate paired with the export-cdi, as well as the
    // public key returned by SIGN_WITH_EXPORTED_ECDSA.
    // 3. Performs a warm reset
    // 4. Checks that we can still create a valid signature.

    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
                .set_debug_locked(true),
        ),
        ..Default::default()
    });

    let derive_ctx_cmd = DeriveContextCmd {
        flags: DeriveContextFlags::EXPORT_CDI
            | DeriveContextFlags::CREATE_CERTIFICATE
            | DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));

    // Wait for command to finish
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    // Triggering a warm reset while a command is being processed will disable attestation.
    for _ in 0..1000 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));
}

#[test]
fn test_sign_with_exported_cdi_warm_reset_parent() {
    // 1. Exports a CDI that has children and then signs a well known hash.
    // 2. Verifies the signature using the CA certificate paired with the export-cdi, as well as the
    // public key returned by SIGN_WITH_EXPORTED_ECDSA.
    // 3. Performs a warm reset
    // 4. Checks that we can still create a valid signature. This implicitly checks that the root
    //    context was not destroyed, since we can still find it in the runtime.

    let mut model = run_rt_test(RuntimeTestArgs {
        security_state: Some(
            *SecurityState::default()
                .set_device_lifecycle(caliptra_hw_model::DeviceLifecycle::Production)
                .set_debug_locked(true),
        ),
        ..Default::default()
    });

    // Rotate out the default handle so we can make multiple descendants.
    let rotate_ctx_cmd = RotateCtxCmd {
        handle: ContextHandle::default(),
        flags: RotateCtxFlags::empty(),
    };

    let Some(Response::RotateCtx(NewHandleResp { handle, .. })) = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::RotateCtx(&rotate_ctx_cmd),
        DpeResult::Success,
    ) else {
        panic!("Failed to rotate context!");
    };

    // Derive a new context and retain the parent.
    // We will export the parent. We expect that the child prevents the dpe context chain from being destroyed.
    let derive_ctx_cmd = DeriveContextCmd {
        handle,
        flags: DeriveContextFlags::RETAIN_PARENT_CONTEXT,
        tci_type: 1,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let Some(Response::DeriveContext(DeriveContextResp { parent_handle, .. })) = resp else {
        panic!("expected derive context resp!");
    };

    // Export the parent context from the last derive command.
    let derive_ctx_cmd = DeriveContextCmd {
        handle: parent_handle,
        flags: DeriveContextFlags::EXPORT_CDI | DeriveContextFlags::CREATE_CERTIFICATE,
        tci_type: 2,
        ..Default::default()
    };
    let resp = execute_dpe_cmd(
        &mut model,
        CaliptraDpeProfile::Ecc384,
        &mut Command::DeriveContext(&derive_ctx_cmd),
        DpeResult::Success,
    );

    let derive_resp = match resp {
        Some(Response::DeriveContextExportedCdi(resp)) => resp,
        _ => panic!("expected derive context resp!"),
    };

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));

    // Wait for command to finish
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().mailbox_flow_done());

    // Triggering a warm reset while a command is being processed will disable attestation.
    for _ in 0..1000 {
        model.step();
    }

    model.warm_reset_flow().unwrap();

    // Wait for boot
    model.step_until(|m| m.soc_ifc().cptra_flow_status().read().ready_for_runtime());

    let mut cmd = MailboxReq::SignWithExportedEcdsa(SignWithExportedEcdsaReq {
        hdr: MailboxReqHeader { chksum: 0 },
        exported_cdi_handle: derive_resp.header.exported_cdi,
        tbs: TEST_DIGEST,
    });
    cmd.populate_chksum().unwrap();

    let result = model.mailbox_execute(
        CommandId::SIGN_WITH_EXPORTED_ECDSA.into(),
        cmd.as_bytes().unwrap(),
    );

    let response = result.unwrap().unwrap();
    let sign_resp = SignWithExportedEcdsaResp::ref_from_bytes(response.as_bytes()).unwrap();
    assert!(check_certificate_signature(sign_resp, &derive_resp));
}
