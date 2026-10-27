//! Differential tests with the real `tools/dss-oracle`, behind the feature
//! `dss`: the whole corpus of `testdata/`, run twice, and a validation
//! built with the typed API.
//!
//! They need Java and the JAR of `tools/dss-oracle`, built by Maven, as
//! `Dss::from_env` finds them. With the feature, a missing JAR fails the
//! tests, since the feature exists to run them. The workflow
//! `differential.yml` runs them on Linux without network.

#![cfg(feature = "dss")]

use std::fmt::Write as _;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use sigillum_oracle::dss::Dss;
use sigillum_oracle::{Expected, Validation, check, differing_runs, validate_corpus};
use sigillum_testpki::manifest::{Indication, Manifest};
use sigillum_testpki::openssl::Scratch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// The tool, checked against the DSS version of the manifest.
fn dss(manifest: &Manifest) -> Result<Dss, Box<dyn std::error::Error>> {
    let dss = Dss::from_env()?;
    dss.check_version(&manifest.header.dss_version)?;
    Ok(dss)
}

/// Acceptance criteria 3 and 4 of #39: every artefact of the corpus that
/// DSS processes gives the result that the manifest expects, or the result
/// of its recorded divergence, and two runs of the whole corpus give the
/// same summaries, byte for byte.
#[test]
fn the_corpus_gives_its_expected_results_and_the_same_summaries_twice() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let dss = dss(&manifest)?;
    let jobs = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    let (first, second) = (Scratch::create()?, Scratch::create()?);
    let runs = [
        validate_corpus(dss.oracle(), &manifest, &testdata(), first.path(), jobs),
        validate_corpus(dss.oracle(), &manifest, &testdata(), second.path(), jobs),
    ];
    let mut failures = differing_runs(&runs[0], &runs[1]).join("\n");
    let mut divergent = 0;
    for result in &runs[0] {
        let Ok(summary) = &result.summary else {
            continue;
        };
        let artefact = manifest
            .artefacts
            .iter()
            .find(|a| a.id == result.id)
            .ok_or_else(|| format!("{} is not in the manifest", result.id))?;
        let divergence = artefact
            .dss_divergence
            .as_ref()
            .map(|d| format!(" (the result of {})", d.entry))
            .unwrap_or_default();
        // A run without a summary is reported by differing_runs. A run
        // with one, of an artefact that the manifest expects DSS not to
        // process, is reported here, as verify --dss reports it.
        let Some(expected) = Expected::of_artefact(&manifest, artefact) else {
            write!(
                failures,
                "\n{}: the manifest expects not-applicable, but DSS processes a {}",
                result.id,
                artefact.kind.as_str()
            )?;
            continue;
        };
        if let Err(mismatch) = check(summary, &expected) {
            write!(failures, "\n{}{divergence}: {mismatch}", result.id)?;
        }
        // The result as verify --dss reads it, which also requires the
        // aligned policy.
        let result_of_dss = artefact
            .dss_divergence
            .as_ref()
            .map_or_else(|| artefact.expected_dss.clone(), |d| d.result());
        if summary.result() != Ok(result_of_dss.clone()) {
            write!(
                failures,
                "\n{}{divergence}: verify --dss would read {:?}, not {result_of_dss}",
                result.id,
                summary.result()
            )?;
        }
        if artefact.dss_divergence.is_some() {
            divergent += 1;
        }
    }
    assert!(failures.is_empty(), "{failures}");
    assert!(runs[0].len() > 100);
    let recorded = manifest
        .artefacts
        .iter()
        .filter(|a| a.dss_divergence.is_some())
        .count();
    assert_eq!(divergent, recorded, "every recorded divergence is run");
    eprintln!(
        "sigillum-oracle: {} artefacts as expected ({divergent} with a recorded divergence), identical over two runs",
        runs[0].len()
    );
    Ok(())
}

/// Acceptance criterion 1 of #39: a validation built from files, and a
/// readable difference when the expected result is not the one DSS gives.
#[test]
fn a_validation_built_from_files_gives_its_summary() -> TestResult {
    let manifest = Manifest::load(&testdata().join("manifest.toml"))?;
    let dss = dss(&manifest)?;
    let data = testdata();
    let validation = Validation::certificate(
        data.join("pki/signer-p256.pem"),
        manifest.header.validation_time,
    )?
    .with_certificate(data.join("pki/ca-ecdsa.pem"))
    .with_trust_anchor(data.join("pki/root-ca.pem"))
    .with_crl(data.join("crl/ca-ecdsa.crl"))
    .with_crl(data.join("crl/root-ca.crl"));
    let summary = dss.validate(&validation)?;
    check(&summary, &Expected::indication(Indication::Passed, None))?;
    let wrong = Expected::indication(Indication::Passed, None).member(
        "details",
        serde_json::json!({ "revocation": { "status": "REVOKED" } }),
    );
    let mismatch = check(&summary, &wrong).err().ok_or("no mismatch")?;
    assert_eq!(
        mismatch.to_string(),
        "summary.json differs in 1 member:\n  /details/revocation/status: expected \"REVOKED\", found \"GOOD\""
    );
    let token = Validation::timestamp(
        data.join("timestamps/valid.tst"),
        Some(&data.join("timestamps/content.txt")),
        manifest.header.validation_time,
    )?
    .with_certificate(data.join("pki/ca-ecdsa.pem"))
    .with_trust_anchor(data.join("pki/root-ca.pem"))
    .with_crl(data.join("crl/ca-ecdsa.crl"))
    .with_crl(data.join("crl/root-ca.crl"));
    check(
        &dss.validate(&token)?,
        &Expected::indication(Indication::Passed, None),
    )?;
    Ok(())
}
