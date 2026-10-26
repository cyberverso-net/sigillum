//! The committed signed corpus under `testdata/signed/` has one manifest
//! entry per planned signature, recording the file as committed. The
//! corpus itself is regenerated and compared byte for byte by the
//! signed-corpus workflow, which has Java and DSS.

use std::path::PathBuf;

use sigillum_testpki::manifest::Manifest;
use sigillum_testpki::pki::hierarchy;
use sigillum_testpki::pki::sha256_hex;
use sigillum_testpki::signed;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[test]
fn every_planned_signature_is_committed_with_its_entry() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    for fixture in signed::plan() {
        let contents = std::fs::read(testdata().join(fixture.path()))?;
        let entry = manifest
            .artefacts
            .iter()
            .find(|a| a.id == fixture.id())
            .ok_or_else(|| format!("{} is not in the manifest", fixture.id()))?;
        assert_eq!(entry, &fixture.artefact(&contents));
        assert_eq!(entry.sha256, sha256_hex(&contents));
    }
    Ok(())
}

#[test]
fn every_file_under_signed_is_planned() -> TestResult {
    let planned: Vec<PathBuf> = signed::plan().iter().map(|f| f.path()).collect();
    let mut count = 0;
    for entry in std::fs::read_dir(testdata().join(signed::DIRECTORY))? {
        let path = PathBuf::from(format!(
            "{}/{}",
            signed::DIRECTORY,
            entry?.file_name().to_string_lossy()
        ));
        assert!(planned.contains(&path), "{} is not planned", path.display());
        count += 1;
    }
    assert_eq!(count, planned.len());
    Ok(())
}

#[test]
fn the_jades_signatures_carry_x5c_in_their_protected_header() -> TestResult {
    // Implementing Regulation (EU) 2026/248, Annex I: x5c is always present.
    for fixture in signed::plan() {
        let path = fixture.path();
        if !path.to_string_lossy().contains("jades") {
            continue;
        }
        let text = std::fs::read_to_string(testdata().join(&path))?;
        let encoded = match text.find("\"protected\":\"") {
            Some(at) => {
                let rest = &text[at + 13..];
                rest[..rest.find('"').ok_or("unterminated")?].to_owned()
            }
            None => text[..text.find('.').ok_or("not compact")?].to_owned(),
        };
        let header = String::from_utf8(base64url(&encoded)?)?;
        assert!(header.contains("\"x5c\":["), "{}: {header}", path.display());
    }
    Ok(())
}

/// Decodes unpadded base64url (RFC 4648, section 5).
fn base64url(text: &str) -> Result<Vec<u8>, String> {
    let mut bits = 0u32;
    let mut count = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let value = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return Err(format!("not base64url: {c}")),
        };
        bits = (bits << 6) | u32::from(value);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push(u8::try_from((bits >> count) & 0xff).map_err(|e| e.to_string())?);
        }
    }
    Ok(out)
}

/// The identifiers of a certificate of the test PKI and of the chain above
/// it, up to the root.
fn chain_of(name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let spec = hierarchy::find(name).ok_or_else(|| format!("{name} is not in the test PKI"))?;
    let mut ids = vec![format!("pki/{name}")];
    for issuer in hierarchy::chain(spec)? {
        ids.push(format!("pki/{}", issuer.name));
    }
    Ok(ids)
}

/// Every certificate that a validation of a signed entry needs is linked:
/// the chain of the signer, and from B-T on the chain of the timestamping
/// authority, whose token holds its own certificate only.
#[test]
fn every_certificate_the_validation_needs_is_linked() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let mut checked = 0;
    for entry in manifest
        .artefacts
        .iter()
        .filter(|a| a.id.starts_with("signed/"))
    {
        let linked: Vec<&String> = entry
            .links
            .chain
            .iter()
            .chain(&entry.links.timestamp_chain)
            .collect();
        let issuer = entry.links.issuer.as_deref().ok_or("no issuer")?;
        let mut needed = chain_of(issuer.trim_start_matches("pki/"))?;
        if !entry.id.contains("-b-b-") {
            needed.extend(chain_of("tsa")?);
        }
        for id in &needed {
            assert!(linked.contains(&id), "{} does not link {id}", entry.id);
        }
        checked += 1;
    }
    assert_eq!(checked, signed::plan().len());
    Ok(())
}
