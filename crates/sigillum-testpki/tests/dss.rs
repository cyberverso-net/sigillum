//! Integration tests of `sigillum-testpki verify --dss` with the real
//! `tools/dss-oracle`: part of the committed corpus, the same with a wrong
//! expected result for each validation mode, and a manifest that names
//! another DSS version.
//!
//! They need Java and the JAR of `tools/dss-oracle`, built by Maven. They
//! run when the environment variable `SIGILLUM_TESTPKI_DSS_ORACLE` names
//! the JAR, as the workflow `fixtures-dss.yml` sets it, and otherwise only
//! say that they did not run. `SIGILLUM_TESTPKI_JAVA` names the Java
//! launcher, `java` from the `PATH` by default. The tests of
//! `src/dss/tests.rs` cover the same logic on every platform, with an
//! oracle that stands in for the tool.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sigillum_testpki::manifest::{DssResult, Indication, Manifest};
use sigillum_testpki::openssl::covered_certificate;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The variable that names the JAR.
const VARIABLE: &str = "SIGILLUM_TESTPKI_DSS_ORACLE";

/// The variable that names the Java launcher.
const JAVA: &str = "SIGILLUM_TESTPKI_JAVA";

/// The variable that, set to `1`, makes a missing JAR a failure rather
/// than a reason not to run, as the workflow sets it.
const REQUIRED: &str = "SIGILLUM_TESTPKI_DSS_REQUIRED";

/// The JAR that the variables name: `Ok(None)` when it is not named and
/// not required, and an error when it is required but not named, or when
/// `required` is neither `0` nor `1`.
fn jar_from(jar: Option<String>, required: Option<String>) -> Result<Option<String>, String> {
    let required = match required.as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        Some(other) => return Err(format!("{REQUIRED} is {other:?}, not 0 or 1")),
    };
    match jar.filter(|j| !j.is_empty()) {
        Some(jar) => Ok(Some(jar)),
        None if required => Err(format!("{REQUIRED} is 1, but {VARIABLE} names no JAR")),
        None => Ok(None),
    }
}

/// The JAR to test with, or `None` after saying that the test does not
/// run.
fn oracle(test: &str) -> Result<Option<String>, String> {
    let jar = jar_from(std::env::var(VARIABLE).ok(), std::env::var(REQUIRED).ok())?;
    if jar.is_none() {
        eprintln!("{test}: {VARIABLE} is not set, so this test does not run DSS");
    }
    Ok(jar)
}

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn verify(jar: &str, manifest: &Path) -> std::io::Result<Output> {
    let java = std::env::var(JAVA).unwrap_or_else(|_| "java".to_owned());
    Command::new(env!("CARGO_BIN_EXE_sigillum-testpki"))
        .args(["verify", "--dss", "--java", &java, "--dss-oracle", jar])
        .arg("--manifest")
        .arg(manifest)
        .output()
}

/// The artefacts of the subset: one of each validation mode, a CRL, and a
/// recorded divergence.
const SUBSET: [&str; 5] = [
    "pki/signer-p256",
    "crl/ca-ecdsa",
    "pki/signer-expired",
    "timestamps/valid",
    "signed/cades-detached-b-t-p256",
];

/// The manifest of `ids` and of every artefact that they need, through
/// their links and covered certificates, in the order of `manifest`.
fn subset(manifest: &Manifest, ids: &[&str]) -> Manifest {
    let mut keep: BTreeSet<String> = BTreeSet::new();
    let mut queue: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    while let Some(id) = queue.pop() {
        if !keep.insert(id.clone()) {
            continue;
        }
        let Some(artefact) = manifest.artefacts.iter().find(|a| a.id == id) else {
            continue;
        };
        let links = &artefact.links;
        queue.extend(links.issuer.iter().cloned());
        queue.extend(links.chain.iter().cloned());
        queue.extend(links.revocation.iter().cloned());
        queue.extend(links.content.iter().cloned());
        queue.extend(links.timestamp_chain.iter().cloned());
        if let Some(covered) = artefact.notes.as_deref().and_then(covered_certificate) {
            queue.push(covered.to_owned());
        }
    }
    let mut part = manifest.clone();
    part.artefacts.retain(|a| keep.contains(&a.id));
    part
}

/// A fresh copy of the committed corpus, in a directory named after the
/// test, with `manifest` as its manifest. Returns the path of the manifest.
fn corpus_with(name: &str, manifest: &Manifest) -> std::io::Result<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&testdata(), &dir)?;
    let path = dir.join("manifest.toml");
    std::fs::write(&path, manifest.to_toml())?;
    Ok(path)
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn set_expected(manifest: &mut Manifest, id: &str, expected: DssResult) -> Result<(), String> {
    let artefact = manifest
        .artefacts
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or_else(|| format!("no {id}"))?;
    artefact.expected_dss = expected;
    Ok(())
}

fn failed(indication: Indication, sub: &str) -> DssResult {
    DssResult::Indication {
        indication,
        sub_indication: Some(sub.to_owned()),
    }
}

#[test]
fn the_required_variable_is_read() {
    assert_eq!(jar_from(None, None), Ok(None));
    assert_eq!(jar_from(Some(String::new()), Some("0".into())), Ok(None));
    assert_eq!(
        jar_from(Some("x.jar".into()), None),
        Ok(Some("x.jar".into()))
    );
    assert!(jar_from(None, Some("1".into())).is_err());
    assert!(jar_from(Some("x.jar".into()), Some("yes".into())).is_err());
}

#[test]
fn part_of_the_committed_corpus_matches_dss() -> TestResult {
    let Some(jar) = oracle("part_of_the_committed_corpus_matches_dss")? else {
        return Ok(());
    };
    let committed = Manifest::load(&testdata().join("manifest.toml"))?;
    let part = subset(&committed, &SUBSET);
    let path = corpus_with("part_of_the_committed_corpus_matches_dss", &part)?;
    let output = verify(&jar, &path)?;
    let stdout = text(&output.stdout);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{stdout}{}",
        text(&output.stderr)
    );
    let divergent = part
        .artefacts
        .iter()
        .filter(|a| a.dss_divergence.is_some())
        .count();
    assert!(divergent > 0);
    assert!(
        stdout.contains(&format!(
            "{} artefacts, {} as expected ({divergent} with a recorded divergence), 0 not as expected",
            part.artefacts.len(),
            part.artefacts.len()
        )),
        "{stdout}"
    );
    Ok(())
}

#[test]
fn a_wrong_expected_result_is_reported_for_each_mode() -> TestResult {
    let Some(jar) = oracle("a_wrong_expected_result_is_reported_for_each_mode")? else {
        return Ok(());
    };
    let committed = Manifest::load(&testdata().join("manifest.toml"))?;
    let mut part = subset(&committed, &SUBSET);
    let wrong = [
        (
            "pki/signer-p256",
            failed(Indication::Indeterminate, "REVOKED_NO_POE"),
        ),
        (
            "crl/ca-ecdsa",
            failed(Indication::Indeterminate, "TRY_LATER"),
        ),
        (
            "timestamps/valid",
            failed(Indication::Failed, "HASH_FAILURE"),
        ),
        (
            "signed/cades-detached-b-t-p256",
            failed(Indication::TotalFailed, "HASH_FAILURE"),
        ),
    ];
    for (id, expected) in &wrong {
        set_expected(&mut part, id, expected.clone())?;
    }
    let path = corpus_with("a_wrong_expected_result_is_reported_for_each_mode", &part)?;
    let output = verify(&jar, &path)?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    for (id, expected) in &wrong {
        assert!(
            stderr.contains(&format!("sigillum-testpki verify: {id}: DSS gives ")),
            "{id}: {stderr}"
        );
        assert!(
            stderr.contains(&format!("the check expects {expected}")),
            "{id}: {stderr}"
        );
    }
    let divergent = part
        .artefacts
        .iter()
        .filter(|a| a.dss_divergence.is_some())
        .count();
    assert_eq!(
        text(&output.stdout),
        format!(
            "sigillum-testpki verify --dss: DSS {}, {} artefacts, {} as expected ({divergent} with a recorded divergence), {} not as expected\n",
            part.header.dss_version,
            part.artefacts.len(),
            part.artefacts.len() - wrong.len(),
            wrong.len()
        )
    );
    Ok(())
}

#[test]
fn a_manifest_of_another_dss_version_is_refused() -> TestResult {
    let Some(jar) = oracle("a_manifest_of_another_dss_version_is_refused")? else {
        return Ok(());
    };
    let committed = Manifest::load(&testdata().join("manifest.toml"))?;
    let mut part = subset(&committed, &["pki/root-ca"]);
    let found = part.header.dss_version.clone();
    part.header.dss_version = "6.4.0".to_owned();
    let path = corpus_with("a_manifest_of_another_dss_version_is_refused", &part)?;
    let output = verify(&jar, &path)?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "the manifest records the results of DSS 6.4.0, but tools/dss-oracle is built against DSS {found}"
        )),
        "{stderr}"
    );
    Ok(())
}
