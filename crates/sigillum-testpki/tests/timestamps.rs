//! The committed timestamp tokens under `testdata/timestamps/` are what
//! `generate timestamps` produces, and each is listed in the manifest.

use std::path::PathBuf;

use sigillum_testpki::manifest::{Kind, Manifest};
use sigillum_testpki::timestamp;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[test]
fn the_committed_tokens_are_reproduced_byte_for_byte() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let files = timestamp::generate(manifest.header.validation_time)?;
    assert_eq!(files.len(), 5);
    for file in &files {
        let committed = std::fs::read(testdata().join(&file.artefact.path))?;
        assert!(
            committed == file.contents,
            "{} differs from a fresh generation; run sigillum-testpki generate timestamps",
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
fn every_file_under_timestamps_is_in_the_manifest() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let mut tokens = 0;
    for entry in std::fs::read_dir(testdata().join(timestamp::DIRECTORY))? {
        let entry = entry?;
        let path = PathBuf::from(format!(
            "{}/{}",
            timestamp::DIRECTORY,
            entry.file_name().to_string_lossy()
        ));
        let artefact = manifest
            .artefacts
            .iter()
            .find(|a| a.path == path)
            .ok_or_else(|| format!("{} is not listed", path.display()))?;
        if artefact.kind == Kind::TimestampToken {
            tokens += 1;
        }
    }
    assert_eq!(tokens, 4);
    Ok(())
}
