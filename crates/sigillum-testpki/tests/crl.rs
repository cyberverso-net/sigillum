//! The committed CRLs under `testdata/crl/` are what `generate crls`
//! produces, every file is listed in the manifest with its digest, and the
//! certificates of the test PKI link the current CRL of their issuer.

use std::collections::HashSet;
use std::path::PathBuf;

use const_oid::db::rfc5280::{ID_CE_AUTHORITY_KEY_IDENTIFIER, ID_CE_SUBJECT_KEY_IDENTIFIER};
use der::{Decode, DecodePem, Encode};
use sigillum_testpki::manifest::{Kind, Manifest};
use sigillum_testpki::pki::{self, crl, hierarchy};
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[test]
fn the_committed_crls_are_reproduced_byte_for_byte() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let files = crl::generate(manifest.header.validation_time)?;
    assert_eq!(files.len(), crl::CRLS.len());
    for file in &files {
        let committed = std::fs::read(testdata().join(&file.artefact.path))?;
        assert!(
            committed == file.contents,
            "{} differs from a fresh generation; run sigillum-testpki generate crls",
            file.artefact.path.display()
        );
        let entry = manifest
            .artefacts
            .iter()
            .find(|a| a.id == file.artefact.id)
            .ok_or_else(|| format!("{} is not in the manifest", file.artefact.id))?;
        assert_eq!(entry, &file.artefact);
    }
    Ok(())
}

#[test]
fn every_crl_file_is_in_the_manifest() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let listed: HashSet<PathBuf> = manifest
        .artefacts
        .iter()
        .filter(|a| a.kind == Kind::Crl)
        .map(|a| a.path.clone())
        .collect();
    let mut found = HashSet::new();
    for entry in std::fs::read_dir(testdata().join(crl::DIRECTORY))? {
        let path = PathBuf::from(format!(
            "{}/{}",
            crl::DIRECTORY,
            entry?.file_name().to_string_lossy()
        ));
        assert!(listed.contains(&path), "{} is not listed", path.display());
        found.insert(path);
    }
    assert_eq!(found, listed);
    Ok(())
}

/// Each committed CRL decodes, names the issuer and chain of its manifest
/// entry, and carries the key identifier of the issuer's certificate.
#[test]
fn each_crl_agrees_with_its_manifest_entry() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let entry = |id: &str| {
        manifest
            .artefacts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("{id} is not in the manifest"))
    };
    for artefact in manifest.artefacts.iter().filter(|a| a.kind == Kind::Crl) {
        let der = std::fs::read(testdata().join(&artefact.path))?;
        assert_eq!(pki::sha256_hex(&der), artefact.sha256);
        let list = CertificateList::from_der(&der)?;
        assert_eq!(list.to_der()?, der, "{} is not DER", artefact.id);
        let issuer_id = artefact.links.issuer.as_deref().ok_or("no issuer")?;
        let issuer =
            Certificate::from_pem(std::fs::read(testdata().join(&entry(issuer_id)?.path))?)?;
        let defective = artefact.id.ends_with("-wrong-issuer");
        assert_eq!(
            list.tbs_cert_list.issuer == issuer.tbs_certificate.subject,
            !defective,
            "{}",
            artefact.id
        );
        let issuer_spec = hierarchy::find(issuer_id.trim_start_matches("pki/")).ok_or("no spec")?;
        let mut chain = vec![issuer_id.to_owned()];
        chain.extend(
            hierarchy::chain(issuer_spec)?
                .iter()
                .map(|s| pki::certificate_id(s.name)),
        );
        assert_eq!(artefact.links.chain, chain);
        // The authority key identifier is the issuer's subject key identifier.
        let find = |extensions: Option<&Vec<x509_cert::ext::Extension>>, oid| {
            extensions
                .and_then(|e| e.iter().find(|e| e.extn_id == oid))
                .map(|e| e.extn_value.as_bytes().to_vec())
                .ok_or("missing extension")
        };
        let aki = AuthorityKeyIdentifier::from_der(&find(
            list.tbs_cert_list.crl_extensions.as_ref(),
            ID_CE_AUTHORITY_KEY_IDENTIFIER,
        )?)?;
        let ski = SubjectKeyIdentifier::from_der(&find(
            issuer.tbs_certificate.extensions.as_ref(),
            ID_CE_SUBJECT_KEY_IDENTIFIER,
        )?)?;
        assert_eq!(aki.key_identifier, Some(ski.0), "{}", artefact.id);
        let at = manifest.header.validation_time.unix_timestamp();
        let next = list
            .tbs_cert_list
            .next_update
            .ok_or("no nextUpdate")?
            .to_unix_duration()
            .as_secs();
        let this = list.tbs_cert_list.this_update.to_unix_duration().as_secs();
        let current = i64::try_from(this)? <= at && i64::try_from(next)? > at;
        assert_eq!(
            current,
            artefact.id != "crl/ca-ecdsa-expired",
            "{}",
            artefact.id
        );
    }
    Ok(())
}

/// Every certificate whose issuer has a current CRL links it in
/// `revocation`, and no other certificate links a CRL.
#[test]
fn certificates_link_the_current_crl_of_their_issuer() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    for spec in &hierarchy::CERTIFICATES {
        let id = pki::certificate_id(spec.name);
        let entry = manifest
            .artefacts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("{id} is not in the manifest"))?;
        let crls: Vec<&String> = entry
            .links
            .revocation
            .iter()
            .filter(|r| r.starts_with("crl/"))
            .collect();
        match crl::current_crl(spec) {
            Some(current) => assert_eq!(crls, [&crl::crl_id(current.name)], "{id}"),
            None => assert!(crls.is_empty(), "{id}"),
        }
    }
    Ok(())
}
