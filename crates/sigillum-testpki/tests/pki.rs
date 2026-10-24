//! The committed test PKI under `testdata/pki/` is what `generate pki`
//! produces, and every file is listed in the manifest with its digest.
//! The CRLs under `testdata/crl/` are checked in `crl.rs`.

use std::collections::HashSet;
use std::path::PathBuf;

use sigillum_testpki::manifest::{Kind, Manifest};
use sigillum_testpki::pki;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[test]
fn the_committed_pki_is_reproduced_byte_for_byte() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let files = pki::generate(manifest.header.validation_time)?;
    for file in &files {
        let committed = std::fs::read(testdata().join(&file.artefact.path))?;
        assert!(
            committed == file.contents,
            "{} differs from a fresh generation; run sigillum-testpki generate pki",
            file.artefact.path.display()
        );
        let entry = manifest
            .artefacts
            .iter()
            .find(|a| a.id == file.artefact.id)
            .ok_or_else(|| format!("{} is not in the manifest", file.artefact.id))?;
        // The revocation links belong to generate crls and later generators.
        let mut expected = file.artefact.clone();
        expected
            .links
            .revocation
            .clone_from(&entry.links.revocation);
        assert_eq!(entry, &expected);
    }
    Ok(())
}

#[test]
fn every_file_of_the_pki_is_in_the_manifest_with_its_digest() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let listed: HashSet<PathBuf> = manifest.artefacts.iter().map(|a| a.path.clone()).collect();
    for directory in ["pki", "pki/keys"] {
        for entry in std::fs::read_dir(testdata().join(directory))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() || entry.file_name() == "README.md" {
                continue;
            }
            let path = PathBuf::from(format!(
                "{directory}/{}",
                entry.file_name().to_string_lossy()
            ));
            assert!(listed.contains(&path), "{} is not listed", path.display());
        }
    }
    for artefact in &manifest.artefacts {
        let contents = std::fs::read(testdata().join(&artefact.path))?;
        assert_eq!(
            pki::sha256_hex(&contents),
            artefact.sha256,
            "{}",
            artefact.id
        );
        if artefact.kind == Kind::PrivateKey {
            let path = artefact.path.to_string_lossy();
            assert!(path.starts_with("pki/keys/") && path.ends_with(".test-key.pem"));
        }
    }
    Ok(())
}

#[test]
fn the_key_directory_says_the_keys_are_test_keys() -> TestResult {
    let readme = std::fs::read_to_string(testdata().join("pki/keys/README.md"))?;
    assert!(readme.contains("test keys with no value"));
    Ok(())
}
