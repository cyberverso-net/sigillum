//! The committed malformed variants under `testdata/mutations/` are what
//! `generate mutations` derives from the committed signed corpus, byte for
//! byte, and each is listed in the manifest as the generator records it.

use std::path::PathBuf;

use sigillum_testpki::manifest::Manifest;
use sigillum_testpki::mutations::{self, MUTATIONS};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[test]
fn the_committed_variants_are_reproduced_byte_for_byte() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let files = mutations::generate(&testdata(), &manifest)?;
    assert_eq!(files.len(), MUTATIONS.len());
    for file in files {
        let committed = std::fs::read(testdata().join(&file.artefact.path))?;
        assert!(
            committed == file.contents,
            "{} differs from a fresh derivation; run sigillum-testpki generate mutations",
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
fn every_file_under_mutations_is_planned() -> TestResult {
    let planned: Vec<PathBuf> = MUTATIONS.iter().map(|m| m.path()).collect();
    let mut count = 0;
    for entry in std::fs::read_dir(testdata().join(mutations::DIRECTORY))? {
        let path = PathBuf::from(format!(
            "{}/{}",
            mutations::DIRECTORY,
            entry?.file_name().to_string_lossy()
        ));
        assert!(planned.contains(&path), "{} is not planned", path.display());
        count += 1;
    }
    assert_eq!(count, planned.len());
    Ok(())
}
