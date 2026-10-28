//! Tests of the runs of the validation modes, with an oracle that stands
//! in for `tools/dss-oracle`.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::json;
use sigillum_testpki::manifest::{DssResult, Kind};
use sigillum_testpki::openssl::{Output, Scratch};
use time::macros::datetime;

use super::*;
use crate::compare::{Expected, check};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TIME: OffsetDateTime = datetime!(2030-01-15 10:00:00 UTC);

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn committed() -> Result<Manifest, Box<dyn std::error::Error>> {
    Ok(Manifest::load(&testdata().join("manifest.toml"))?)
}

fn absolute(path: &str) -> OsString {
    std::path::absolute(path)
        .unwrap_or_else(|_| PathBuf::from(path))
        .into_os_string()
}

fn strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

fn time_and_timeout() -> Vec<String> {
    [
        "--validation-time",
        "2030-01-15T10:00:00Z",
        "--timeout",
        "120",
    ]
    .map(str::to_owned)
    .to_vec()
}

#[test]
fn a_certificate_is_validated_with_the_files_given() -> TestResult {
    let validation = Validation::certificate("leaf.pem", TIME)?
        .with_certificate("ca.pem")
        .with_trust_anchor("root.pem")
        .with_crl("ca.crl")
        .with_ocsp("leaf.der");
    assert_eq!(validation.mode(), Mode::Certificate);
    let mut expected = vec!["validate-certificate".to_owned()];
    for (option, file) in [
        ("--certificate", "leaf.pem"),
        ("--certificate", "ca.pem"),
        ("--trust-anchor", "root.pem"),
        ("--crl", "ca.crl"),
        ("--ocsp", "leaf.der"),
    ] {
        expected.push(option.to_owned());
        expected.push(absolute(file).to_string_lossy().into_owned());
    }
    expected.extend(time_and_timeout());
    let mut found = strings(validation.arguments());
    // The time and the time limit come last.
    let time = found.splice(3..7, []).collect::<Vec<_>>();
    found.extend(time);
    assert_eq!(found, expected);
    Ok(())
}

#[test]
fn a_timestamp_and_a_document_name_their_content_when_given() -> TestResult {
    let token = Validation::timestamp("t.tst", Some(Path::new("data.txt")), TIME)?;
    assert_eq!(token.mode(), Mode::Timestamp);
    let args = strings(token.arguments());
    assert_eq!(
        args[..5],
        [
            "validate-timestamp".to_owned(),
            "--timestamp".to_owned(),
            absolute("t.tst").to_string_lossy().into_owned(),
            "--data".to_owned(),
            absolute("data.txt").to_string_lossy().into_owned(),
        ]
    );
    assert_eq!(args[5..], time_and_timeout());
    let bare = Validation::timestamp("t.tst", None, TIME)?;
    assert!(!strings(bare.arguments()).contains(&"--data".to_owned()));
    let document = Validation::document("s.p7s", Some(Path::new("text.txt")), TIME)?
        .with_trust_anchor("root.pem");
    assert_eq!(document.mode(), Mode::Document);
    let args = strings(document.arguments());
    assert_eq!(
        args[..5],
        [
            "validate-document".to_owned(),
            "--document".to_owned(),
            absolute("s.p7s").to_string_lossy().into_owned(),
            "--detached".to_owned(),
            absolute("text.txt").to_string_lossy().into_owned(),
        ]
    );
    assert_eq!(args[5..9], time_and_timeout());
    assert_eq!(
        args[9..],
        [
            "--trust-anchor".to_owned(),
            absolute("root.pem").to_string_lossy().into_owned(),
        ]
    );
    let bare = Validation::document("s.pdf", None, TIME)?;
    assert!(!strings(bare.arguments()).contains(&"--detached".to_owned()));
    Ok(())
}

fn time_of(validation: &Validation) -> Option<String> {
    let args = strings(validation.arguments());
    args.iter()
        .position(|a| a == "--validation-time")
        .and_then(|i| args.get(i + 1).cloned())
}

/// The validation time is given to the tool in UTC, in whole seconds, as
/// the manifest writes it.
#[test]
fn the_validation_time_is_written_in_utc_and_whole_seconds() -> TestResult {
    let time = datetime!(2029-12-16 11:30:05.75 +01:00);
    for validation in [
        Validation::certificate("c.pem", time)?,
        Validation::timestamp("t.tst", None, time)?,
        Validation::document("d.pdf", None, time)?,
    ] {
        assert_eq!(
            time_of(&validation).as_deref(),
            Some("2029-12-16T10:30:05Z")
        );
    }
    Ok(())
}

/// A time that the form `YYYY-MM-DDTHH:MM:SSZ` cannot express is refused
/// when the validation is built.
#[test]
fn a_time_without_that_form_is_refused_when_the_validation_is_built() -> TestResult {
    let time = time::Date::from_calendar_date(-1, time::Month::January, 1)?
        .midnight()
        .assume_utc();
    let error = TimeError { time };
    assert_eq!(
        Validation::certificate("c.pem", time).err(),
        Some(error.clone())
    );
    assert_eq!(
        Validation::timestamp("t.tst", None, time).err(),
        Some(error.clone())
    );
    assert_eq!(
        Validation::document("d.pdf", None, time).err(),
        Some(error.clone())
    );
    assert!(
        error
            .to_string()
            .starts_with("the validation time -0001-01-01 0:00:00.0 +00:00:00 cannot be written as YYYY-MM-DDTHH:MM:SSZ"),
        "{error}"
    );
    Ok(())
}

#[test]
fn a_corpus_artefact_is_run_as_verify_runs_it() -> TestResult {
    let manifest = committed()?;
    let mut runs = 0;
    for artefact in &manifest.artefacts {
        let validation = Validation::for_artefact(&manifest, &testdata(), artefact)?;
        let expected = validation_arguments(&manifest, &testdata(), artefact)?;
        match (validation, expected) {
            (Some(validation), Some((mode, args))) => {
                assert_eq!(validation.mode(), mode, "{}", artefact.id);
                assert_eq!(validation.arguments(), args, "{}", artefact.id);
                runs += 1;
            }
            (None, None) => {
                assert!(matches!(artefact.kind, Kind::PrivateKey | Kind::Document));
            }
            (validation, _) => {
                return Err(format!("{}: {validation:?}", artefact.id).into());
            }
        }
    }
    assert!(runs > 100, "{runs}");
    Ok(())
}

/// The `summary.json` that the stand-in writes for a run in `mode`.
fn summary_text(mode: &str, result: &DssResult) -> String {
    let mut summary = json!({
        "format-version": 3,
        "oracle": { "tool-version": "0.0.0", "dss-version": "6.5.1" },
        "mode": mode,
        "validation-time": "2030-01-15T10:00:00Z",
        "policy": "aligned-1",
    });
    let members = match result {
        DssResult::Indication {
            indication,
            sub_indication,
        } => json!({
            "result": "validated",
            "indication": indication.as_str().replace('-', "_"),
            "sub-indication": sub_indication,
            "details": {}
        }),
        _ => json!({ "result": "rejected", "input": "--ocsp", "file": "x", "message": "m" }),
    };
    if let (Some(summary), Some(members)) = (summary.as_object_mut(), members.as_object()) {
        summary.extend(members.clone());
    }
    format!("{summary:#}\n")
}

/// The output directory that `args` name.
fn out_of(args: &[OsString]) -> Option<PathBuf> {
    args.iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
}

fn success() -> Output {
    Output {
        success: true,
        stdout: String::new(),
        stderr: String::new(),
    }
}

/// A stand-in that writes `text` as the summary of every run.
fn writing(text: String) -> impl Fn(&[OsString]) -> Result<Output, RunError> + Sync {
    move |args: &[OsString]| {
        let out = out_of(args).ok_or_else(|| RunError::Io("no --out".into()))?;
        std::fs::create_dir_all(&out).map_err(|e| RunError::Io(e.to_string()))?;
        std::fs::write(out.join("summary.json"), &text).map_err(|e| RunError::Io(e.to_string()))?;
        Ok(success())
    }
}

#[test]
fn a_run_gives_the_summary_that_the_tool_writes() -> TestResult {
    let scratch = Scratch::create()?;
    let out = scratch.path().join("run");
    let text = summary_text("validate-certificate", &DssResult::Rejected);
    let calls = Mutex::new(Vec::new());
    let oracle = |args: &[OsString]| {
        if let Ok(mut calls) = calls.lock() {
            calls.push(args.to_vec());
        }
        writing(text.clone())(args)
    };
    let validation = Validation::certificate("c.pem", TIME)?.with_trust_anchor("r.pem");
    let summary = run(&oracle, &validation, &out)?;
    assert_eq!(summary.text(), text);
    assert_eq!(summary.result(), Ok(DssResult::Rejected));
    let calls = calls.into_inner().unwrap_or_default();
    let mut expected = validation.arguments().to_vec();
    expected.extend([OsString::from("--out"), out.into_os_string()]);
    assert_eq!(calls, [expected]);
    Ok(())
}

#[test]
fn a_run_without_a_summary_is_an_error() -> TestResult {
    let scratch = Scratch::create()?;
    let validation = Validation::certificate("c.pem", TIME)?;
    let failing = |_: &[OsString]| {
        Ok(Output {
            success: false,
            stdout: String::new(),
            stderr: "usage: dss-oracle\n".into(),
        })
    };
    assert_eq!(
        run(&failing, &validation, &scratch.path().join("a")),
        Err(OracleError::Failed("usage: dss-oracle".into()))
    );
    let timed_out = |_: &[OsString]| Err(RunError::TimedOut(Duration::from_secs(180)));
    assert_eq!(
        run(&timed_out, &validation, &scratch.path().join("b")),
        Err(OracleError::Run(RunError::TimedOut(Duration::from_secs(
            180
        ))))
    );
    let silent = |_: &[OsString]| Ok(success());
    assert!(matches!(
        run(&silent, &validation, &scratch.path().join("c")),
        Err(OracleError::Summary(SummaryError::Read(_)))
    ));
    let garbled = writing("not json".into());
    assert!(matches!(
        run(&garbled, &validation, &scratch.path().join("d")),
        Err(OracleError::Summary(SummaryError::Json(_)))
    ));
    Ok(())
}

#[test]
fn errors_are_described() {
    for (error, text) in [
        (
            OracleError::Inputs("the notes name no covered certificate".into()),
            "the run cannot be built: the notes name no covered certificate",
        ),
        (
            OracleError::Run(RunError::Spawn("no java".into())),
            "tools/dss-oracle cannot be started: no java",
        ),
        (
            OracleError::Failed("bad option".into()),
            "tools/dss-oracle failed: bad option",
        ),
        (
            OracleError::Summary(SummaryError::NotAnObject),
            "summary.json is not a JSON object",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
}

/// A stand-in that gives every artefact the result that the manifest
/// expects of DSS, recognised by its output directory, which the position
/// of the artefact in the manifest names.
fn expected_results(
    manifest: &Manifest,
) -> impl Fn(&[OsString]) -> Result<Output, RunError> + Sync + '_ {
    move |args: &[OsString]| {
        let mode = args
            .first()
            .map(|a| a.to_string_lossy().into_owned())
            .unwrap_or_default();
        let artefact = out_of(args)
            .and_then(|out| out.file_name()?.to_str()?.parse::<usize>().ok())
            .and_then(|index| manifest.artefacts.get(index))
            .ok_or_else(|| RunError::Io("no numbered --out".into()))?;
        let result = artefact
            .dss_divergence
            .as_ref()
            .map_or_else(|| artefact.expected_dss.clone(), |d| d.result());
        writing(summary_text(&mode, &result))(args)
    }
}

#[test]
fn the_corpus_is_run_in_the_order_of_the_manifest() -> TestResult {
    let manifest = committed()?;
    let scratch = Scratch::create()?;
    let oracle = expected_results(&manifest);
    let jobs = NonZeroUsize::new(4).ok_or("no jobs")?;
    let results = validate_corpus(&oracle, &manifest, &testdata(), scratch.path(), jobs);
    let processed: Vec<&str> = manifest
        .artefacts
        .iter()
        .filter(|a| !matches!(a.kind, Kind::PrivateKey | Kind::Document))
        .map(|a| a.id.as_str())
        .collect();
    let ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids, processed);
    let directories = std::fs::read_dir(scratch.path())?.count();
    assert_eq!(directories, processed.len(), "one directory per run");
    for result in &results {
        let summary = result
            .summary
            .as_ref()
            .map_err(|e| format!("{}: {e}", result.id))?;
        let artefact = manifest
            .artefacts
            .iter()
            .find(|a| a.id == result.id)
            .ok_or("no artefact")?;
        let expected = Expected::of_artefact(&manifest, artefact).ok_or("not applicable")?;
        check(summary, &expected).map_err(|e| format!("{}: {e}", result.id))?;
    }
    Ok(())
}

#[test]
fn an_artefact_whose_run_cannot_be_built_is_reported() -> TestResult {
    let mut manifest = committed()?;
    let crl = manifest
        .artefacts
        .iter_mut()
        .find(|a| a.id == "crl/ca-ecdsa")
        .ok_or("no crl/ca-ecdsa")?;
    crl.notes = None;
    let scratch = Scratch::create()?;
    let oracle = writing(summary_text("validate-certificate", &DssResult::Rejected));
    let results = validate_corpus(
        &oracle,
        &manifest,
        &testdata(),
        scratch.path(),
        NonZeroUsize::MIN,
    );
    let crl = results
        .iter()
        .find(|r| r.id == "crl/ca-ecdsa")
        .ok_or("no result")?;
    assert!(
        matches!(&crl.summary, Err(OracleError::Inputs(reason)) if reason.contains("covered certificate")),
        "{:?}",
        crl.summary
    );
    assert!(results.iter().filter(|r| r.summary.is_ok()).count() > 100);
    Ok(())
}

fn corpus_result(id: &str, text: &str) -> CorpusResult {
    CorpusResult {
        id: id.to_owned(),
        summary: Summary::parse(text).map_err(OracleError::Summary),
    }
}

/// Acceptance criterion 4 of #39: two runs of the corpus must give the same
/// summaries, byte for byte.
#[test]
fn two_runs_that_differ_are_reported_artefact_by_artefact() {
    let passed = summary_text(
        "validate-certificate",
        &DssResult::Indication {
            indication: sigillum_testpki::manifest::Indication::Passed,
            sub_indication: None,
        },
    );
    let rejected = summary_text("validate-certificate", &DssResult::Rejected);
    let first = [corpus_result("a", &passed), corpus_result("b", &passed)];
    assert!(differing_runs(&first, &first.clone()).is_empty());
    let second = [corpus_result("a", &passed), corpus_result("b", &rejected)];
    let report = differing_runs(&first, &second);
    assert_eq!(report.len(), 1, "{report:?}");
    assert!(
        report[0].starts_with("b: the two runs differ; summary.json differs in "),
        "{}",
        report[0]
    );
    assert!(
        report[0].contains("/result: expected \"validated\", found \"rejected\""),
        "{}",
        report[0]
    );
    let compact = [
        corpus_result("a", &passed),
        corpus_result("b", passed.trim_end()),
    ];
    assert_eq!(
        differing_runs(&first, &compact),
        ["b: the two runs give the same members in other bytes"]
    );
    let failed = [
        corpus_result("a", &passed),
        CorpusResult {
            id: "b".into(),
            summary: Err(OracleError::Failed("crash".into())),
        },
    ];
    assert_eq!(
        differing_runs(&first, &failed),
        ["b: the second run gave no summary: tools/dss-oracle failed: crash"]
    );
    assert_eq!(
        differing_runs(&failed, &first),
        ["b: the first run gave no summary: tools/dss-oracle failed: crash"]
    );
    assert_eq!(
        differing_runs(&first, &first[..1]),
        ["the first run has 2 artefacts and the second 1"]
    );
    let renamed = [corpus_result("a", &passed), corpus_result("c", &passed)];
    assert_eq!(
        differing_runs(&first, &renamed),
        ["b: the second run has c in its place"]
    );
}

/// The manifest does not tie `expected-dss` to the kind of an artefact. A
/// kind that DSS does not process, with an expected result of DSS, is
/// reported by its identifier, as `verify --dss` reports it.
#[test]
fn an_artefact_that_dss_does_not_process_but_that_expects_a_result_is_reported() -> TestResult {
    let mut manifest = committed()?;
    let text = manifest
        .artefacts
        .iter_mut()
        .find(|a| a.kind == Kind::Document)
        .ok_or("no document")?;
    text.expected_dss = DssResult::Rejected;
    let id = text.id.clone();
    let scratch = Scratch::create()?;
    let oracle = expected_results(&manifest);
    let results = validate_corpus(
        &oracle,
        &manifest,
        &testdata(),
        scratch.path(),
        NonZeroUsize::MIN,
    );
    let result = results
        .iter()
        .find(|r| r.id == id)
        .ok_or("the document is not reported")?;
    assert_eq!(
        result.summary,
        Err(OracleError::Inputs(
            "DSS does not process a document, but the manifest expects rejected".into()
        ))
    );
    // The other artefacts that DSS does not process are not reported.
    let unprocessed = results
        .iter()
        .filter(|r| {
            manifest
                .artefacts
                .iter()
                .any(|a| a.id == r.id && matches!(a.kind, Kind::PrivateKey | Kind::Document))
        })
        .count();
    assert_eq!(unprocessed, 1);
    Ok(())
}
