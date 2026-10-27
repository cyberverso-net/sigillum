//! Tests of the reading of `summary.json`.

use std::path::PathBuf;

use serde_json::json;
use sigillum_testpki::manifest::Indication;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A summary of a run in `mode` that gives `result`, with the members of
/// that result.
fn summary(mode: &str, result: Value) -> Value {
    let mut summary = json!({
        "format-version": 3,
        "oracle": {
            "tool-version": "0.0.0",
            "dss-version": "6.5.1",
            "pdf-backend": "dss-pades-pdfbox",
            "pdf-backend-version": "3.0.8"
        },
        "mode": mode,
        "validation-time": "2030-01-15T10:00:00Z",
        "policy": "aligned-1",
    });
    if let (Some(summary), Some(result)) = (summary.as_object_mut(), result.as_object()) {
        summary.extend(result.clone());
    }
    summary
}

fn validated(mode: &str, indication: &str, sub_indication: Option<&str>) -> String {
    summary(
        mode,
        json!({
            "result": "validated",
            "indication": indication,
            "sub-indication": sub_indication,
            "details": {}
        }),
    )
    .to_string()
}

/// The seeds of the fuzz target `dss_output` of `sigillum-testpki`, which
/// `tools/dss-oracle` wrote for the corpus.
fn seed(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../sigillum-testpki/fuzz/seeds/dss_output")
        .join(name)
}

#[test]
fn a_summary_of_each_mode_is_read() -> TestResult {
    for (name, mode) in [
        ("validate-certificate", Mode::Certificate),
        ("validate-timestamp", Mode::Timestamp),
        ("validate-document", Mode::Document),
    ] {
        let text = validated(name, "PASSED", None);
        let summary = Summary::parse(&text)?;
        assert_eq!(summary.mode(), mode);
        assert_eq!(summary.text(), text);
        assert_eq!(summary.json()["indication"], "PASSED");
    }
    Ok(())
}

#[test]
fn the_summaries_that_the_tool_wrote_are_read() -> TestResult {
    for (name, mode) in [
        ("certificate-crl.json", Mode::Certificate),
        ("timestamp-hash-failure.json", Mode::Timestamp),
        ("document-jades.json", Mode::Document),
        ("rejected-ocsp.json", Mode::Certificate),
        ("resource-limit.json", Mode::Document),
    ] {
        let summary = Summary::read(&seed(name))?;
        assert_eq!(summary.mode(), mode, "{name}");
    }
    Ok(())
}

#[test]
fn the_result_is_read_as_verify_reads_it() -> TestResult {
    let passed = Summary::parse(&validated("validate-document", "TOTAL_PASSED", None))?;
    assert_eq!(
        passed.result(),
        Ok(DssResult::Indication {
            indication: Indication::TotalPassed,
            sub_indication: None
        })
    );
    let revoked = Summary::parse(&validated(
        "validate-certificate",
        "INDETERMINATE",
        Some("REVOKED_NO_POE"),
    ))?;
    assert_eq!(
        revoked.result(),
        Ok(DssResult::Indication {
            indication: Indication::Indeterminate,
            sub_indication: Some("REVOKED_NO_POE".into())
        })
    );
    let rejected = Summary::read(&seed("rejected-ocsp.json"))?;
    assert_eq!(rejected.result(), Ok(DssResult::Rejected));
    let limit = Summary::read(&seed("resource-limit.json"))?;
    assert!(
        limit
            .result()
            .is_err_and(|reason| reason.contains("exceeded its time limit")),
        "{:?}",
        limit.result()
    );
    let two = summary(
        "validate-document",
        json!({ "result": "validated", "indication": null, "sub-indication": null,
                "details": { "signatures": [{}, {}] } }),
    );
    let two = Summary::parse(&two.to_string())?;
    assert!(
        two.result()
            .is_err_and(|reason| reason.contains("2 signatures"))
    );
    let mut default = summary("validate-timestamp", json!({ "result": "rejected" }));
    default["policy"] = json!("default");
    let default = Summary::parse(&default.to_string())?;
    assert!(
        default
            .result()
            .is_err_and(|reason| reason.contains("policy"))
    );
    Ok(())
}

#[test]
fn a_policy_file_is_a_policy() -> TestResult {
    let mut text = summary("validate-certificate", json!({ "result": "rejected" }));
    text["policy"] = json!({ "file": "p.xml", "sha256": "00" });
    Summary::parse(&text.to_string())?;
    Ok(())
}

#[test]
fn text_that_is_not_a_json_object_is_refused() {
    assert!(matches!(Summary::parse("{"), Err(SummaryError::Json(_))));
    assert!(matches!(Summary::parse(""), Err(SummaryError::Json(_))));
    for text in ["[]", "3", "\"summary\"", "null"] {
        assert_eq!(
            Summary::parse(text),
            Err(SummaryError::NotAnObject),
            "{text}"
        );
    }
}

/// Every member that every summary has, missing or with another value.
#[test]
fn a_summary_without_the_members_of_every_summary_is_refused() -> TestResult {
    let good = summary("validate-certificate", json!({ "result": "rejected" }));
    let cases: [(&str, &str, Option<Value>); 12] = [
        ("format-version", "/format-version", None),
        ("format-version", "/format-version", Some(json!(2))),
        ("format-version", "/format-version", Some(json!("3"))),
        ("mode", "/mode", None),
        ("mode", "/mode", Some(json!("sign"))),
        ("validation-time", "/validation-time", Some(json!(42))),
        ("oracle", "/oracle/dss-version", None),
        (
            "oracle",
            "/oracle/dss-version",
            Some(json!({ "tool-version": "0.0.0" })),
        ),
        ("policy", "/policy", None),
        ("policy", "/policy", Some(json!(3))),
        ("result", "/result", None),
        ("result", "/result", Some(json!("crashed"))),
    ];
    for (member, pointer, value) in cases {
        let mut text = good.clone();
        let object = text.as_object_mut().ok_or("not an object")?;
        match &value {
            Some(value) => {
                object.insert(member.to_owned(), value.clone());
            }
            None => {
                object.remove(member);
            }
        }
        let error = Summary::parse(&text.to_string()).err();
        let expected_found = match (member, &value) {
            ("oracle", Some(_)) | (_, None) => "null".to_owned(),
            (_, Some(value)) => value.to_string(),
        };
        assert_eq!(
            error,
            Some(SummaryError::Member {
                name: pointer,
                found: expected_found
            }),
            "{member} {value:?}"
        );
    }
    Summary::parse(&good.to_string())?;
    Ok(())
}

#[test]
fn a_file_that_cannot_be_read_is_reported() -> TestResult {
    let missing = Summary::read(&seed("no-such-summary.json"));
    assert!(
        matches!(&missing, Err(SummaryError::Read(message)) if message.contains("no-such-summary.json")),
        "{missing:?}"
    );
    Ok(())
}

/// `Summary::parse` refuses a text longer than `Summary::read` would read.
#[test]
fn a_text_of_the_limit_is_read_and_a_longer_one_is_refused() -> TestResult {
    let limit = usize::try_from(sigillum_testpki::dss::MAX_SUMMARY_LEN)?;
    let mut text = validated("validate-certificate", "PASSED", None);
    text.push_str(&" ".repeat(limit - text.len()));
    assert_eq!(text.len(), limit);
    Summary::parse(&text)?;
    text.push(' ');
    assert_eq!(
        Summary::parse(&text),
        Err(SummaryError::TooLarge { length: limit + 1 })
    );
    Ok(())
}

#[test]
fn errors_are_described() {
    for (error, text) in [
        (
            SummaryError::Read("x: gone".into()),
            "summary.json cannot be read: x: gone",
        ),
        (
            SummaryError::Json("EOF".into()),
            "summary.json is not JSON: EOF",
        ),
        (
            SummaryError::NotAnObject,
            "summary.json is not a JSON object",
        ),
        (
            SummaryError::TooLarge { length: 1_048_577 },
            "summary.json has 1048577 bytes, more than 1048576",
        ),
        (
            SummaryError::Member {
                name: "/mode",
                found: "\"sign\"".into(),
            },
            "summary.json gives /mode \"sign\", which this crate does not read",
        ),
    ] {
        assert_eq!(error.to_string(), text);
    }
}
