//! The committed base documents under `testdata/documents/` are what
//! `generate documents` produces, and each is listed in the manifest.

use std::path::PathBuf;

use sigillum_testpki::documents;
use sigillum_testpki::manifest::Manifest;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

#[test]
fn the_committed_documents_are_reproduced_byte_for_byte() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    for file in documents::generate() {
        let committed = std::fs::read(testdata().join(&file.artefact.path))?;
        assert!(
            committed == file.contents,
            "{} differs from a fresh generation; run sigillum-testpki generate documents",
            file.artefact.path.display()
        );
        let entry = manifest
            .artefacts
            .iter()
            .find(|a| a.id == file.artefact.id)
            .ok_or_else(|| format!("{} is not in the manifest", file.artefact.id))?;
        assert_eq!(entry, &file.artefact);
    }
    let listed = std::fs::read_dir(testdata().join(documents::DIRECTORY))?.count();
    assert_eq!(listed, 4);
    Ok(())
}
