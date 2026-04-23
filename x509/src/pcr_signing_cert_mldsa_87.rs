/*++

Licensed under the Apache-2.0 license.

File Name:

    pcr_signing_cert_mldsa_87.rs

Abstract:

    MLDSA87 PCR Signing Certificate related code.

--*/

// Note: All the necessary code is auto generated
include! {"../build/pcr_signing_cert_tbs_ml_dsa_87.rs"}

#[cfg(all(test, target_family = "unix"))]
mod tests {
    use openssl::pkey_ctx::PkeyCtx;
    use openssl::pkey_ml_dsa::Variant;
    use openssl::signature::Signature;
    use openssl::x509::X509;

    use x509_parser::nom::Parser;
    use x509_parser::oid_registry::asn1_rs::oid;
    use x509_parser::oid_registry::Oid;
    use x509_parser::prelude::X509CertificateParser;
    use x509_parser::x509::X509Version;

    use super::*;
    use crate::test_util::tests::*;
    use crate::{MlDsa87CertBuilder, MlDsa87Signature, NotAfter, NotBefore};

    const TEST_UEID: &[u8] = &[0xABu8; PcrSigningCertTbsMlDsa87Params::UEID_LEN];

    fn make_test_cert(
        subject_key: &MlDsa87AsymKey,
        issuer_key: &MlDsa87AsymKey,
    ) -> PcrSigningCertTbsMlDsa87 {
        let params = PcrSigningCertTbsMlDsa87Params {
            serial_number: &[0xABu8; PcrSigningCertTbsMlDsa87Params::SERIAL_NUMBER_LEN],
            public_key: &subject_key.pub_key().try_into().unwrap(),
            subject_sn: &subject_key
                .hex_str()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
            issuer_sn: &issuer_key
                .hex_str()
                .into_bytes()
                .as_slice()
                .try_into()
                .unwrap(),
            ueid: TEST_UEID.try_into().unwrap(),
            subject_key_id: &subject_key.sha1(),
            authority_key_id: &issuer_key.sha1(),
            not_before: &NotBefore::default().value,
            not_after: &NotAfter::default().value,
        };

        PcrSigningCertTbsMlDsa87::new(&params)
    }

    #[test]
    fn test_cert_signing() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let mldsa_key = issuer_key.priv_key();
        let cert = make_test_cert(&subject_key, &issuer_key);

        let sig = cert
            .sign(|b| {
                let mut signature = vec![];
                let mut ctx = PkeyCtx::new(mldsa_key)?;
                let mut algo = Signature::for_ml_dsa(Variant::MlDsa87)?;
                ctx.sign_message_init(&mut algo)?;
                ctx.sign_to_vec(b, &mut signature)?;
                Ok::<Vec<u8>, openssl::error::ErrorStack>(signature)
            })
            .unwrap();

        assert_ne!(cert.tbs(), PcrSigningCertTbsMlDsa87::TBS_TEMPLATE);

        let mldsa_sig = MlDsa87Signature {
            sig: sig[..4627].try_into().unwrap(),
        };

        let builder = MlDsa87CertBuilder::new(cert.tbs(), &mldsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let cert: X509 = X509::from_der(&buf).unwrap();
        assert!(cert.verify(issuer_key.priv_key()).unwrap());
    }

    #[test]
    fn test_extensions() {
        let subject_key = MlDsa87AsymKey::default();
        let issuer_key = MlDsa87AsymKey::default();
        let mldsa_key = issuer_key.priv_key();
        let cert = make_test_cert(&subject_key, &issuer_key);

        let sig = cert
            .sign(|b| {
                let mut signature = vec![];
                let mut ctx = PkeyCtx::new(mldsa_key)?;
                let mut algo = Signature::for_ml_dsa(Variant::MlDsa87)?;
                ctx.sign_message_init(&mut algo)?;
                ctx.sign_to_vec(b, &mut signature)?;
                Ok::<Vec<u8>, openssl::error::ErrorStack>(signature)
            })
            .unwrap();

        let mldsa_sig = MlDsa87Signature {
            sig: sig[..4627].try_into().unwrap(),
        };

        let builder = MlDsa87CertBuilder::new(cert.tbs(), &mldsa_sig).unwrap();
        let mut buf = vec![0u8; builder.len()];
        builder.build(&mut buf).unwrap();

        let mut parser = X509CertificateParser::new().with_deep_parse_extensions(true);
        let parsed_cert = match parser.parse(&buf) {
            Ok((_, parsed_cert)) => parsed_cert,
            Err(e) => panic!("x509 parsing failed: {:?}", e),
        };

        assert_eq!(parsed_cert.version(), X509Version::V3);

        // PCR signing cert is a leaf: CA=false
        let basic_constraints = parsed_cert.basic_constraints().unwrap().unwrap();
        assert!(basic_constraints.critical);
        assert!(!basic_constraints.value.ca);

        // keyUsage: digitalSignature only
        let key_usage = parsed_cert.key_usage().unwrap().unwrap();
        assert!(key_usage.critical);
        assert!(key_usage.value.digital_signature());
        assert!(!key_usage.value.key_cert_sign());

        // Check TCG UEID extension is present
        let ext_map = parsed_cert.extensions_map().unwrap();
        const UEID_OID: Oid = oid!(2.23.133 .5 .4 .4);
        assert!(!ext_map[&UEID_OID].critical);
    }
}
