//! Tests of the DSS checks, with an oracle that stands in for
//! `tools/dss-oracle`: the runs built for each kind of artefact, the
//! reading of `summary.json`, the version check, the recorded divergences
//! and the comparison with the manifest.

use std::collections::HashMap;
use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::*;
use crate::manifest::{Artefact, DssResult, Indication, Kind, Manifest};
use crate::openssl::{Output, RunError, Scratch};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TIME: &str = "2030-01-15T10:00:00Z";

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn committed() -> Result<Manifest, Box<dyn std::error::Error>> {
    Ok(Manifest::load(&testdata().join("manifest.toml"))?)
}

fn artefact_mut<'a>(manifest: &'a mut Manifest, id: &str) -> Result<&'a mut Artefact, String> {
    manifest
        .artefacts
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or_else(|| format!("no {id}"))
}

fn jobs(n: usize) -> NonZeroUsize {
    NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN)
}

fn output(success: bool, stdout: &str, stderr: &str) -> Output {
    Output {
        success,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    }
}

/// The `summary.json` of a validated run.
fn validated(mode: &str, indication: &str, sub_indication: Option<&str>) -> String {
    serde_json::json!({
        "format-version": 3,
        "oracle": {
            "tool-version": "0.0.0",
            "dss-version": "6.5.1",
            "pdf-backend": "dss-pades-pdfbox",
            "pdf-backend-version": "3.0.8"
        },
        "mode": mode,
        "validation-time": TIME,
        "policy": "aligned-1",
        "result": "validated",
        "indication": indication,
        "sub-indication": sub_indication,
        "details": {}
    })
    .to_string()
}

/// The `summary.json` of a rejected run.
fn rejected(mode: &str) -> String {
    serde_json::json!({
        "format-version": 3,
        "oracle": { "tool-version": "0.0.0", "dss-version": "6.5.1" },
        "mode": mode,
        "validation-time": TIME,
        "policy": "aligned-1",
        "result": "rejected",
        "input": "--ocsp",
        "file": "x.der",
        "message": "cannot be parsed"
    })
    .to_string()
}

/// The `summary.json` that gives `result`, as DSS writes it.
fn summary_of(mode: &str, result: &DssResult) -> String {
    match result {
        DssResult::Indication {
            indication,
            sub_indication,
        } => validated(
            mode,
            &indication.as_str().replace('-', "_"),
            sub_indication.as_deref(),
        ),
        DssResult::Rejected | DssResult::NotApplicable => rejected(mode),
    }
}

fn mode_of(kind: Kind) -> &'static str {
    match kind {
        Kind::TimestampToken => "validate-timestamp",
        Kind::SignedDocument => "validate-document",
        _ => "validate-certificate",
    }
}

/// An oracle that answers `--version` with `version`, and every
/// validation with the summary recorded for its artefact, found by the
/// output directory `dss-<index>`, numbered in the order of the manifest.
/// It records every call.
struct Fake {
    version: String,
    ids: Vec<String>,
    answers: HashMap<String, Result<String, Output>>,
    calls: Mutex<Vec<Vec<String>>>,
}

impl Fake {
    /// An oracle that gives every artefact of `manifest` its expected
    /// result, or the result of DSS for a recorded divergence.
    fn expected(manifest: &Manifest) -> Self {
        let mut answers = HashMap::new();
        for artefact in &manifest.artefacts {
            let result = DIVERGENCES
                .iter()
                .find(|d| d.id == artefact.id)
                .map_or_else(|| artefact.expected_dss.clone(), Divergence::result);
            answers.insert(
                artefact.id.clone(),
                Ok(summary_of(mode_of(artefact.kind), &result)),
            );
        }
        Self {
            version: "dss-oracle 0.0.0 (DSS 6.5.1)\n".to_owned(),
            ids: manifest.artefacts.iter().map(|a| a.id.clone()).collect(),
            answers,
            calls: Mutex::new(Vec::new()),
        }
    }

    fn answer(&mut self, id: &str, answer: Result<String, Output>) {
        self.answers.insert(id.to_owned(), answer);
    }

    fn calls(&self) -> Vec<Vec<String>> {
        self.calls
            .lock()
            .map(|calls| calls.clone())
            .unwrap_or_default()
    }

    /// The call that validates the file `path` of the corpus.
    fn call_for(&self, path: &str) -> Option<Vec<String>> {
        let corpus = std::path::absolute(testdata()).unwrap_or_else(|_| testdata());
        let file = corpus.join(path).to_string_lossy().into_owned();
        self.calls()
            .into_iter()
            .find(|call| call.get(2) == Some(&file))
    }
}

impl Oracle for Fake {
    fn run(&self, args: &[OsString]) -> Result<Output, RunError> {
        let args: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        if let Ok(mut calls) = self.calls.lock() {
            calls.push(args.clone());
        }
        if args == ["--version"] {
            return Ok(output(true, &self.version, ""));
        }
        let out = args
            .iter()
            .position(|a| a == "--out")
            .and_then(|i| args.get(i + 1))
            .ok_or_else(|| RunError::Io("no --out".to_owned()))?;
        let id = Path::new(out)
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("dss-"))
            .and_then(|index| index.parse::<usize>().ok())
            .and_then(|index| self.ids.get(index))
            .ok_or_else(|| RunError::Io(format!("no artefact for {out}")))?;
        match self.answers.get(id) {
            Some(Ok(summary)) => {
                std::fs::create_dir_all(out).map_err(|e| RunError::Io(e.to_string()))?;
                std::fs::write(Path::new(out).join("summary.json"), summary)
                    .map_err(|e| RunError::Io(e.to_string()))?;
                Ok(output(true, "", ""))
            }
            Some(Err(failure)) => Ok(failure.clone()),
            None => Err(RunError::Io(format!("no answer for {id}"))),
        }
    }
}

fn run(manifest: &Manifest, fake: &Fake, n: usize) -> Result<Report, DssError> {
    let scratch = Scratch::create().map_err(|e| DssError::Run(RunError::Io(e.to_string())))?;
    verify(manifest, &testdata(), scratch.path(), fake, jobs(n))
}

fn corpus_file(path: &str) -> String {
    let corpus = std::path::absolute(testdata()).unwrap_or_else(|_| testdata());
    corpus.join(path).to_string_lossy().into_owned()
}

/// The arguments of a call after the mode and before `--out`.
fn inputs(call: &[String]) -> Vec<String> {
    let end = call.iter().position(|a| a == "--out").unwrap_or(call.len());
    call[1..end].to_vec()
}

fn files(pairs: &[(&str, &str)]) -> Vec<String> {
    pairs
        .iter()
        .flat_map(|(option, path)| [(*option).to_owned(), corpus_file(path)])
        .collect()
}

fn time() -> Vec<String> {
    ["--validation-time", TIME, "--timeout", "120"]
        .map(str::to_owned)
        .to_vec()
}

// Acceptance criterion 4: the version of DSS.

#[test]
fn the_version_line_names_the_dss_version() {
    assert_eq!(
        parse_version("dss-oracle 0.0.0 (DSS 6.5.1)\n"),
        Ok("6.5.1".to_owned())
    );
    // On Windows, println ends the line with CR LF.
    assert_eq!(
        parse_version("dss-oracle 0.0.0 (DSS 6.5.1)\r\n"),
        Ok("6.5.1".to_owned())
    );
    assert_eq!(
        parse_version("dss-oracle 1.2.3 (DSS 6.6-RC1)"),
        Ok("6.6-RC1".to_owned())
    );
    for text in [
        "",
        "dss-oracle 0.0.0",
        "dss-oracle 0.0.0 (DSS )",
        "dss-oracle 0.0.0 (DSS 6.5.1",
        "dss-oracle 0.0.0 (DSS 6.5.1) more",
        "dss-oracle 0.0.0 (DSS 6.5.1)\r",
        "dss-oracle 0.0.0 (DSS 6.5.1)\n\n",
        "oracle 0.0.0 (DSS 6.5.1)",
        "dss-oracle  (DSS 6.5.1)",
        "dss-oracle 0.0.0 (DSS 6.5 .1)",
        "-jar x.jar --version",
    ] {
        assert!(
            matches!(parse_version(text), Err(DssError::UnknownVersion(_))),
            "{text:?}"
        );
    }
}

#[test]
fn another_dss_version_stops_the_checks_before_any_validation() -> TestResult {
    let manifest = committed()?;
    let mut fake = Fake::expected(&manifest);
    fake.version = "dss-oracle 0.0.0 (DSS 6.4.0)\n".to_owned();
    let error = run(&manifest, &fake, 1).err();
    assert_eq!(
        error,
        Some(DssError::VersionMismatch {
            found: "6.4.0".to_owned(),
            expected: "6.5.1".to_owned()
        })
    );
    assert_eq!(fake.calls(), vec![vec!["--version".to_owned()]]);
    let message = error.map(|e| e.to_string()).unwrap_or_default();
    assert!(message.contains("DSS 6.5.1"), "{message}");
    assert!(message.contains("DSS 6.4.0"), "{message}");
    Ok(())
}

#[test]
fn a_version_that_cannot_be_read_stops_the_checks() -> TestResult {
    let manifest = committed()?;
    let mut fake = Fake::expected(&manifest);
    fake.version = "Usage: java [options]\n".to_owned();
    assert!(matches!(
        run(&manifest, &fake, 1),
        Err(DssError::UnknownVersion(_))
    ));
    let failing = |_: &[OsString]| Ok(output(false, "", "Error: Unable to access jarfile x.jar\n"));
    let scratch = Scratch::create()?;
    let error = verify(&manifest, &testdata(), scratch.path(), &failing, jobs(1)).err();
    assert!(
        matches!(&error, Some(DssError::Failed(message)) if message.contains("Unable to access jarfile")),
        "{error:?}"
    );
    let unstarted = |_: &[OsString]| Err(RunError::Spawn("java: not found".to_owned()));
    let error = verify(&manifest, &testdata(), scratch.path(), &unstarted, jobs(1)).err();
    assert_eq!(
        error,
        Some(DssError::Run(RunError::Spawn("java: not found".to_owned())))
    );
    Ok(())
}

#[test]
fn every_summary_must_name_the_dss_version_of_the_manifest() {
    let summary = validated("validate-certificate", "PASSED", None)
        .replace("\"dss-version\":\"6.5.1\"", "\"dss-version\":\"6.4.0\"");
    let read = read_summary(&summary, Mode::Certificate, TIME, "6.5.1");
    assert!(
        matches!(&read, Err(message) if message.contains("DSS 6.4.0") && message.contains("DSS 6.5.1")),
        "{read:?}"
    );
}

// Acceptance criterion 1: the modes, their inputs, and the comparison.

#[test]
fn the_committed_corpus_matches_an_oracle_that_gives_the_expected_results() -> TestResult {
    let manifest = committed()?;
    let fake = Fake::expected(&manifest);
    let report = run(&manifest, &fake, 4)?;
    assert_eq!(report.version, "6.5.1");
    assert_eq!(report.findings.len(), manifest.artefacts.len());
    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    let expected: Vec<&str> = manifest.artefacts.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(ids, expected, "the findings keep the order of the manifest");
    let mismatches: Vec<&Finding> = report.mismatches().collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    let processed = manifest
        .artefacts
        .iter()
        .filter(|a| !matches!(a.kind, Kind::PrivateKey | Kind::Document))
        .count();
    assert_eq!(fake.calls().len(), 1 + processed);
    let mut outs: Vec<String> = fake
        .calls()
        .iter()
        .filter_map(|call| call.last().cloned())
        .filter(|out| out != "--version")
        .collect();
    outs.sort();
    outs.dedup();
    assert_eq!(
        outs.len(),
        processed,
        "each run has its own output directory"
    );
    Ok(())
}

#[test]
fn a_certificate_is_validated_with_its_chain_and_the_revocation_data_they_link() -> TestResult {
    let manifest = committed()?;
    let fake = Fake::expected(&manifest);
    run(&manifest, &fake, 1)?;
    let call = fake
        .call_for("pki/signer-p256.pem")
        .ok_or("pki/signer-p256 was not validated")?;
    assert_eq!(call[0], "validate-certificate");
    let mut expected = files(&[
        ("--certificate", "pki/signer-p256.pem"),
        ("--certificate", "pki/ca-ecdsa.pem"),
        ("--trust-anchor", "pki/root-ca.pem"),
        ("--crl", "crl/ca-ecdsa.crl"),
        ("--ocsp", "ocsp/signer-p256.der"),
        ("--crl", "crl/root-ca.crl"),
    ]);
    expected.extend(time());
    assert_eq!(inputs(&call), expected);
    // A trust anchor is its own anchor, with no revocation data.
    let call = fake
        .call_for("pki/root-ca.pem")
        .ok_or("pki/root-ca was not validated")?;
    let mut expected = files(&[
        ("--certificate", "pki/root-ca.pem"),
        ("--trust-anchor", "pki/root-ca.pem"),
    ]);
    expected.extend(time());
    assert_eq!(inputs(&call), expected);
    Ok(())
}

#[test]
fn a_crl_or_ocsp_response_is_validated_as_the_revocation_data_of_its_covered_certificate()
-> TestResult {
    let manifest = committed()?;
    let fake = Fake::expected(&manifest);
    run(&manifest, &fake, 1)?;
    for (path, option) in [
        ("crl/ca-ecdsa.crl", "--crl"),
        ("ocsp/signer-p256.der", "--ocsp"),
    ] {
        let call = fake
            .calls()
            .into_iter()
            .find(|call| {
                call.first().map(String::as_str) == Some("validate-certificate")
                    && call.get(2) == Some(&corpus_file("pki/signer-p256.pem"))
                    && call
                        .windows(2)
                        .any(|w| w[0] == option && w[1] == corpus_file(path))
                    && call
                        .iter()
                        .filter(|a| *a == "--crl" || *a == "--ocsp")
                        .count()
                        == 2
            })
            .ok_or(format!("{path} was not validated alone"))?;
        let mut expected = files(&[
            ("--certificate", "pki/signer-p256.pem"),
            ("--certificate", "pki/ca-ecdsa.pem"),
            ("--trust-anchor", "pki/root-ca.pem"),
            (option, path),
            ("--crl", "crl/root-ca.crl"),
        ]);
        expected.extend(time());
        assert_eq!(inputs(&call), expected, "{path}");
    }
    Ok(())
}

#[test]
fn a_timestamp_token_is_validated_with_its_data_the_chain_of_its_signer_and_their_crls()
-> TestResult {
    let manifest = committed()?;
    let fake = Fake::expected(&manifest);
    run(&manifest, &fake, 1)?;
    let call = fake
        .call_for("timestamps/valid.tst")
        .ok_or("timestamps/valid was not validated")?;
    assert_eq!(call[0], "validate-timestamp");
    let mut expected = files(&[
        ("--timestamp", "timestamps/valid.tst"),
        ("--data", "timestamps/content.txt"),
        ("--certificate", "pki/tsa.pem"),
        ("--certificate", "pki/ca-ecdsa.pem"),
        ("--trust-anchor", "pki/root-ca.pem"),
        ("--crl", "crl/ca-ecdsa.crl"),
        ("--crl", "crl/root-ca.crl"),
    ]);
    expected.extend(time());
    assert_eq!(inputs(&call), expected);
    Ok(())
}

#[test]
fn a_signed_document_is_validated_with_the_linked_files_only() -> TestResult {
    let manifest = committed()?;
    let fake = Fake::expected(&manifest);
    run(&manifest, &fake, 1)?;
    let call = fake
        .call_for("signed/cades-detached-b-t-p256.p7s")
        .ok_or("signed/cades-detached-b-t-p256 was not validated")?;
    assert_eq!(call[0], "validate-document");
    let mut expected = files(&[
        ("--document", "signed/cades-detached-b-t-p256.p7s"),
        ("--detached", "documents/text.txt"),
        ("--certificate", "pki/signer-p256.pem"),
        ("--certificate", "pki/ca-ecdsa.pem"),
        ("--certificate", "pki/tsa.pem"),
        ("--trust-anchor", "pki/root-ca.pem"),
        ("--ocsp", "ocsp/signer-p256.der"),
        ("--crl", "crl/root-ca.crl"),
        ("--ocsp", "ocsp/tsa.der"),
    ]);
    expected.extend(time());
    assert_eq!(inputs(&call), expected);
    // An enveloping signature has no detached content.
    let call = fake
        .call_for("signed/cades-enveloping-b-b-rsa.p7m")
        .ok_or("signed/cades-enveloping-b-b-rsa was not validated")?;
    assert!(!call.contains(&"--detached".to_owned()), "{call:?}");
    Ok(())
}

#[test]
fn keys_and_unsigned_documents_are_not_given_to_dss() -> TestResult {
    let manifest = committed()?;
    let fake = Fake::expected(&manifest);
    let report = run(&manifest, &fake, 1)?;
    for finding in &report.findings {
        let artefact = manifest
            .artefacts
            .iter()
            .find(|a| a.id == finding.id)
            .ok_or("no artefact")?;
        if matches!(artefact.kind, Kind::PrivateKey | Kind::Document) {
            assert_eq!(
                finding.actual,
                Ok(DssResult::NotApplicable),
                "{}",
                finding.id
            );
            assert!(
                fake.call_for(&artefact.path.to_string_lossy()).is_none(),
                "{}",
                finding.id
            );
        }
    }
    // A key that the manifest expects DSS to validate is a mismatch.
    let mut manifest = manifest;
    artefact_mut(&mut manifest, "pki/keys/signer-p256")?.expected_dss = DssResult::Rejected;
    let report = run(&manifest, &Fake::expected(&manifest), 1)?;
    let ids: Vec<&str> = report.mismatches().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["pki/keys/signer-p256"]);
    Ok(())
}

#[test]
fn a_result_that_differs_from_the_manifest_is_a_mismatch_for_each_mode() -> TestResult {
    let manifest = committed()?;
    let mut fake = Fake::expected(&manifest);
    fake.answer(
        "pki/signer-p256",
        Ok(validated(
            "validate-certificate",
            "INDETERMINATE",
            Some("REVOKED_NO_POE"),
        )),
    );
    fake.answer(
        "timestamps/valid",
        Ok(validated(
            "validate-timestamp",
            "FAILED",
            Some("HASH_FAILURE"),
        )),
    );
    fake.answer("signed/pades-b-t-p256", Ok(rejected("validate-document")));
    let report = run(&manifest, &fake, 3)?;
    let mismatches: Vec<(&str, &Result<DssResult, String>)> = report
        .mismatches()
        .map(|f| (f.id.as_str(), &f.actual))
        .collect();
    assert_eq!(
        mismatches,
        [
            (
                "pki/signer-p256",
                &Ok(DssResult::Indication {
                    indication: Indication::Indeterminate,
                    sub_indication: Some("REVOKED_NO_POE".to_owned())
                })
            ),
            (
                "timestamps/valid",
                &Ok(DssResult::Indication {
                    indication: Indication::Failed,
                    sub_indication: Some("HASH_FAILURE".to_owned())
                })
            ),
            ("signed/pades-b-t-p256", &Ok(DssResult::Rejected)),
        ]
    );
    let finding = report.mismatches().next().ok_or("no mismatch")?;
    assert!(
        finding.detail.contains("validate-certificate"),
        "{}",
        finding.detail
    );
    assert!(
        finding.detail.contains("REVOKED_NO_POE"),
        "{}",
        finding.detail
    );
    Ok(())
}

#[test]
fn a_run_that_fails_is_a_check_that_cannot_run() -> TestResult {
    let manifest = committed()?;
    let mut fake = Fake::expected(&manifest);
    fake.answer(
        "pki/signer-p256",
        Err(output(false, "", "dss-oracle: network access attempted\n")),
    );
    let report = run(&manifest, &fake, 1)?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "pki/signer-p256")
        .ok_or("no finding")?;
    assert!(
        matches!(&finding.actual, Err(reason) if reason.contains("network access attempted")),
        "{:?}",
        finding.actual
    );
    assert!(!finding.matches());
    // A run that writes no summary.
    fake.answer("pki/signer-p256", Err(output(true, "", "")));
    let report = run(&manifest, &fake, 1)?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "pki/signer-p256")
        .ok_or("no finding")?;
    assert!(
        matches!(&finding.actual, Err(reason) if reason.contains("summary.json")),
        "{:?}",
        finding.actual
    );
    Ok(())
}

#[test]
fn a_crl_without_a_covered_certificate_cannot_be_checked() -> TestResult {
    let mut manifest = committed()?;
    artefact_mut(&mut manifest, "crl/ca-ecdsa")?.notes = Some("No such sentence.".to_owned());
    let report = run(&manifest, &Fake::expected(&manifest), 1)?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "crl/ca-ecdsa")
        .ok_or("no finding")?;
    assert!(
        matches!(&finding.actual, Err(reason) if reason.contains("covered certificate")),
        "{:?}",
        finding.actual
    );
    Ok(())
}

// The divergences recorded in docs/design/divergences.md.

#[test]
fn the_recorded_divergences_name_artefacts_whose_prediction_differs() -> TestResult {
    let manifest = committed()?;
    for divergence in &DIVERGENCES {
        let artefact = manifest
            .artefacts
            .iter()
            .find(|a| a.id == divergence.id)
            .ok_or(format!("{} is not in the manifest", divergence.id))?;
        assert_ne!(
            artefact.expected_dss,
            divergence.result(),
            "{}",
            divergence.id
        );
        assert!(divergence.entry.starts_with("DIV-"), "{}", divergence.id);
    }
    let docs = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/design/divergences.md"),
    )?;
    for divergence in &DIVERGENCES {
        let row = docs
            .lines()
            .find(|line| line.starts_with(&format!("| {} |", divergence.entry)))
            .ok_or(format!("{} is not in divergences.md", divergence.entry))?;
        assert!(
            row.contains(&format!("`{}`", divergence.id)),
            "{} does not name {}",
            divergence.entry,
            divergence.id
        );
    }
    Ok(())
}

#[test]
fn a_divergent_artefact_must_give_the_result_recorded_for_dss() -> TestResult {
    let manifest = committed()?;
    let fake = Fake::expected(&manifest);
    let report = run(&manifest, &fake, 2)?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "pki/signer-expired")
        .ok_or("no finding")?;
    assert!(finding.matches());
    assert_eq!(finding.divergence.map(|d| d.entry), Some("DIV-5"));
    assert_eq!(report.divergent().count(), DIVERGENCES.len());
    // DSS giving the prediction is a mismatch: the divergence is stale.
    let mut fake = fake;
    fake.answer(
        "pki/signer-expired",
        Ok(validated(
            "validate-certificate",
            "INDETERMINATE",
            Some("OUT_OF_BOUNDS_NO_POE"),
        )),
    );
    let report = run(&manifest, &fake, 2)?;
    let ids: Vec<&str> = report.mismatches().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["pki/signer-expired"]);
    Ok(())
}

#[test]
fn a_manifest_that_predicts_a_recorded_divergence_stops_the_checks() -> TestResult {
    let mut manifest = committed()?;
    artefact_mut(&mut manifest, "pki/ca-expired")?.expected_dss = DssResult::Indication {
        indication: Indication::Indeterminate,
        sub_indication: Some("OUT_OF_BOUNDS_NOT_REVOKED".to_owned()),
    };
    let fake = Fake::expected(&manifest);
    let error = run(&manifest, &fake, 1).err();
    assert_eq!(
        error,
        Some(DssError::StaleDivergence {
            id: "pki/ca-expired".to_owned(),
            entry: "DIV-5"
        })
    );
    assert!(fake.calls().is_empty());
    Ok(())
}

// The reading of summary.json.

#[test]
fn a_summary_gives_the_result_with_hyphens() {
    assert_eq!(
        read_summary(
            &validated("validate-document", "TOTAL_PASSED", None),
            Mode::Document,
            TIME,
            "6.5.1"
        ),
        Ok(DssResult::Indication {
            indication: Indication::TotalPassed,
            sub_indication: None
        })
    );
    assert_eq!(
        read_summary(
            &validated(
                "validate-timestamp",
                "INDETERMINATE",
                Some("CHAIN_CONSTRAINTS_FAILURE")
            ),
            Mode::Timestamp,
            TIME,
            "6.5.1"
        ),
        Ok(DssResult::Indication {
            indication: Indication::Indeterminate,
            sub_indication: Some("CHAIN_CONSTRAINTS_FAILURE".to_owned())
        })
    );
    for (dss, indication) in [
        ("TOTAL_FAILED", Indication::TotalFailed),
        ("PASSED", Indication::Passed),
        ("FAILED", Indication::Failed),
    ] {
        assert_eq!(
            read_summary(
                &validated("validate-certificate", dss, None),
                Mode::Certificate,
                TIME,
                "6.5.1"
            ),
            Ok(DssResult::Indication {
                indication,
                sub_indication: None
            })
        );
    }
    assert_eq!(
        read_summary(
            &rejected("validate-certificate"),
            Mode::Certificate,
            TIME,
            "6.5.1"
        ),
        Ok(DssResult::Rejected)
    );
}

#[test]
fn a_summary_that_does_not_describe_the_run_is_refused() {
    let good = validated("validate-certificate", "PASSED", None);
    let cases = [
        ("not JSON", "summary".to_owned()),
        ("not an object", "[]".to_owned()),
        (
            "format",
            good.replace("\"format-version\":3", "\"format-version\":2"),
        ),
        (
            "mode",
            good.replace("validate-certificate", "validate-timestamp"),
        ),
        (
            "validation time",
            good.replace(TIME, "2030-01-15T10:00:01Z"),
        ),
        ("policy", good.replace("aligned-1", "default")),
        ("result", good.replace("\"validated\"", "\"unknown\"")),
        ("indication", good.replace("\"PASSED\"", "\"PASSED_OK\"")),
        ("indication type", good.replace("\"PASSED\"", "1")),
        (
            "sub-indication type",
            good.replace("\"sub-indication\":null", "\"sub-indication\":1"),
        ),
        ("no oracle", good.replace("\"oracle\"", "\"other\"")),
    ];
    for (what, summary) in cases {
        assert_ne!(summary, good, "{what}: the case changes nothing");
        assert!(
            read_summary(&summary, Mode::Certificate, TIME, "6.5.1").is_err(),
            "{what}: {summary}"
        );
    }
}

#[test]
fn a_document_without_exactly_one_signature_has_no_result() {
    let summary = validated("validate-document", "TOTAL_PASSED", None)
        .replace("\"indication\":\"TOTAL_PASSED\"", "\"indication\":null")
        .replace("\"details\":{}", "\"details\":{\"signatures\":[{},{}]}");
    let read = read_summary(&summary, Mode::Document, TIME, "6.5.1");
    assert!(
        matches!(&read, Err(message) if message.contains("2 signatures")),
        "{read:?}"
    );
}

#[test]
fn a_run_that_exceeds_a_resource_limit_has_no_result() {
    let summary = serde_json::json!({
        "format-version": 3,
        "oracle": { "dss-version": "6.5.1" },
        "mode": "validate-document",
        "validation-time": TIME,
        "policy": "aligned-1",
        "result": "resource-limit",
        "limit": "time",
        "message": "300 s"
    })
    .to_string();
    let read = read_summary(&summary, Mode::Document, TIME, "6.5.1");
    assert!(
        matches!(&read, Err(message) if message.contains("time limit")),
        "{read:?}"
    );
}

#[test]
fn a_finding_says_why_it_differs() -> TestResult {
    let manifest = committed()?;
    let mut fake = Fake::expected(&manifest);
    fake.answer(
        "pki/signer-expired",
        Ok(validated("validate-certificate", "PASSED", None)),
    );
    let report = run(&manifest, &fake, 1)?;
    let finding = report.mismatches().next().ok_or("no mismatch")?;
    assert_eq!(
        finding.expectation(),
        "INDETERMINATE with OUT_OF_BOUNDS_NOT_REVOKED, the result of DSS that DIV-5 records; the manifest predicts INDETERMINATE with OUT_OF_BOUNDS_NO_POE"
    );
    Ok(())
}

#[test]
fn the_launcher_runs_the_jar() {
    let oracle = crate::signed::JavaOracle::new("java".into(), "dss-oracle.jar".into());
    assert_eq!(
        launcher_arguments(&oracle, &["--version".into()]),
        [
            "-Xmx512m",
            "-XX:+UseSerialGC",
            "-jar",
            "dss-oracle.jar",
            "--version"
        ]
        .map(OsString::from)
        .to_vec()
    );
}

#[test]
fn a_summary_is_read_up_to_one_mebibyte() -> TestResult {
    let manifest = committed()?;
    let summary = validated("validate-certificate", "PASSED", None);
    let limit = 1024 * 1024;
    let mut fake = Fake::expected(&manifest);
    // A summary of exactly the limit, padded with white space, is read.
    fake.answer(
        "pki/signer-p256",
        Ok(format!("{summary}{}", " ".repeat(limit - summary.len()))),
    );
    let report = run(&manifest, &fake, 1)?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "pki/signer-p256")
        .ok_or("no finding")?;
    assert!(finding.matches(), "{:?}", finding.actual);
    // One byte more is refused before it is parsed.
    fake.answer(
        "pki/signer-p256",
        Ok(format!(
            "{summary}{}",
            " ".repeat(limit + 1 - summary.len())
        )),
    );
    let report = run(&manifest, &fake, 1)?;
    let finding = report
        .findings
        .iter()
        .find(|f| f.id == "pki/signer-p256")
        .ok_or("no finding")?;
    assert!(
        matches!(&finding.actual, Err(reason) if reason.contains("is larger than 1048576 bytes")),
        "{:?}",
        finding.actual
    );
    Ok(())
}
