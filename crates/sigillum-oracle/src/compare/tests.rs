//! Tests of the comparison of summaries with their expected results, and
//! of the report of their differences.

use std::path::PathBuf;

use proptest::prelude::*;
use serde_json::json;
use sigillum_testpki::manifest::{Divergence, Kind, Links, Manifest, OpensslResult};

use crate::compare::{MAX_LISTED_BYTES, MAX_LISTED_DIFFERENCES};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn difference(path: &str, expected: Option<Value>, found: Option<Value>) -> Difference {
    Difference {
        path: path.to_owned(),
        expected,
        found,
    }
}

fn summary(json: &Value) -> Result<Summary, crate::summary::SummaryError> {
    Summary::parse(&json.to_string())
}

fn validated(indication: &str, sub_indication: Option<&str>) -> Value {
    json!({
        "format-version": 3,
        "oracle": { "tool-version": "0.0.0", "dss-version": "6.5.1" },
        "mode": "validate-certificate",
        "validation-time": "2030-01-15T10:00:00Z",
        "policy": "aligned-1",
        "result": "validated",
        "indication": indication,
        "sub-indication": sub_indication,
        "details": {
            "common-name": "signer",
            "revocation": { "status": "GOOD", "source": { "type": "CRL" } },
            "errors": [],
            "warnings": [{ "key": "W1", "message": "a warning" }]
        }
    })
}

#[test]
fn equal_values_have_no_differences() {
    let value = validated("PASSED", None);
    assert!(differences(&value, &value).is_empty());
    assert!(identical(&value, &value).is_empty());
    assert!(differences(&json!({}), &value).is_empty());
}

/// The members of an object are compared in the order of their names.
#[test]
fn a_different_scalar_is_reported_with_its_pointer() {
    let found = validated("INDETERMINATE", Some("NO_POE"));
    let expected = json!({
        "indication": "PASSED",
        "details": { "revocation": { "status": "REVOKED" } }
    });
    assert_eq!(
        differences(&expected, &found).differences,
        [
            difference(
                "/details/revocation/status",
                Some(json!("REVOKED")),
                Some(json!("GOOD"))
            ),
            difference(
                "/indication",
                Some(json!("PASSED")),
                Some(json!("INDETERMINATE"))
            ),
        ]
    );
}

#[test]
fn a_missing_member_is_found_as_nothing() {
    let found = validated("PASSED", None);
    let expected = json!({ "limit": "time", "details": { "simple-report": {} } });
    assert_eq!(
        differences(&expected, &found).differences,
        [
            difference("/details/simple-report", Some(json!({})), None),
            difference("/limit", Some(json!("time")), None),
        ]
    );
}

#[test]
fn values_of_another_type_differ_as_a_whole() {
    let expected = json!({ "a": { "b": 1 }, "c": [1], "d": null });
    let found = json!({ "a": [1], "c": { "b": 1 }, "d": 0 });
    assert_eq!(
        differences(&expected, &found).differences,
        [
            difference("/a", Some(json!({ "b": 1 })), Some(json!([1]))),
            difference("/c", Some(json!([1])), Some(json!({ "b": 1 }))),
            difference("/d", Some(json!(null)), Some(json!(0))),
        ]
    );
    assert_eq!(
        differences(&json!(1), &json!("1")).differences,
        [difference("", Some(json!(1)), Some(json!("1")))]
    );
}

#[test]
fn arrays_are_compared_element_by_element() {
    let expected = json!({ "list": [1, { "k": "a", "x": 0 }, 3] });
    let found = json!({ "list": [1, { "k": "b", "x": 0, "extra": true }] });
    assert_eq!(
        differences(&expected, &found).differences,
        [
            difference("/list/1/k", Some(json!("a")), Some(json!("b"))),
            difference("/list/2", Some(json!(3)), None),
        ]
    );
    assert_eq!(
        differences(&json!([1]), &json!([1, 2])).differences,
        [difference("/1", None, Some(json!(2)))]
    );
}

/// In a pointer, `~` is written `~0` and `/` is written `~1`, as
/// `serde_json::Value::pointer` reads them.
#[test]
fn pointers_escape_tilde_and_slash() {
    let expected = json!({ "a/b": { "c~d": 1 } });
    let found = json!({ "a/b": { "c~d": 2 } });
    let found_differences = differences(&expected, &found).differences;
    assert_eq!(found_differences[0].path, "/a~1b/c~0d");
    assert_eq!(found.pointer(&found_differences[0].path), Some(&json!(2)));
}

#[test]
fn members_that_only_the_found_value_has_differ_only_when_identical_is_required() {
    let first = json!({ "a": 1, "n": { "b": 2 } });
    let second = json!({ "a": 1, "n": { "b": 2, "c": 3 }, "z": [] });
    assert!(differences(&first, &second).is_empty());
    assert_eq!(
        identical(&first, &second).differences,
        [
            difference("/n/c", None, Some(json!(3))),
            difference("/z", None, Some(json!([]))),
        ]
    );
    assert_eq!(
        identical(&second, &first).differences,
        [
            difference("/n/c", Some(json!(3)), None),
            difference("/z", Some(json!([])), None),
        ]
    );
}

#[test]
fn a_difference_is_one_readable_line() {
    assert_eq!(
        difference(
            "/indication",
            Some(json!("PASSED")),
            Some(json!("INDETERMINATE"))
        )
        .to_string(),
        "/indication: expected \"PASSED\", found \"INDETERMINATE\""
    );
    assert_eq!(
        difference("/limit", Some(json!("time")), None).to_string(),
        "/limit: expected \"time\", found nothing"
    );
    assert_eq!(
        difference("/z", None, Some(json!([1, {"a": null}]))).to_string(),
        "/z: expected nothing, found [1,{\"a\":null}]"
    );
    assert_eq!(
        difference("", Some(json!(1)), Some(json!(2))).to_string(),
        "the document: expected 1, found 2"
    );
}

#[test]
fn a_mismatch_counts_and_lists_its_differences() {
    let one = Mismatch {
        differences: vec![difference("/a", Some(json!(1)), Some(json!(2)))],
        omitted: 0,
    };
    assert_eq!(
        one.to_string(),
        "summary.json differs in 1 member:\n  /a: expected 1, found 2"
    );
    let two = Mismatch {
        differences: vec![
            difference("/a", Some(json!(1)), Some(json!(2))),
            difference("/b", None, Some(json!(true))),
        ],
        omitted: 0,
    };
    assert_eq!(
        two.to_string(),
        "summary.json differs in 2 members:\n  /a: expected 1, found 2\n  /b: expected nothing, found true"
    );
}

#[test]
fn check_compares_a_summary_with_its_expected_result() -> TestResult {
    let found = summary(&validated("INDETERMINATE", Some("REVOKED_NO_POE")))?;
    check(
        &found,
        &Expected::indication(Indication::Indeterminate, Some("REVOKED_NO_POE")),
    )?;
    let error = check(&found, &Expected::indication(Indication::Passed, None))
        .err()
        .ok_or("no mismatch")?;
    assert_eq!(
        error.differences,
        [
            difference(
                "/indication",
                Some(json!("PASSED")),
                Some(json!("INDETERMINATE"))
            ),
            difference(
                "/sub-indication",
                Some(json!(null)),
                Some(json!("REVOKED_NO_POE"))
            ),
        ]
    );
    let detailed = Expected::indication(Indication::Indeterminate, Some("REVOKED_NO_POE"))
        .member("details", json!({ "revocation": { "status": "REVOKED" } }));
    let error = check(&found, &detailed).err().ok_or("no mismatch")?;
    assert_eq!(
        error.to_string(),
        "summary.json differs in 1 member:\n  /details/revocation/status: expected \"REVOKED\", found \"GOOD\""
    );
    check(&found, &Expected::new())?;
    Ok(())
}

#[test]
fn the_expected_results_of_the_manifest_are_written_as_dss_writes_them() {
    let object = |value: Value| value.as_object().cloned().unwrap_or_default();
    assert_eq!(
        Expected::indication(Indication::TotalPassed, None).members(),
        &object(
            json!({ "result": "validated", "indication": "TOTAL_PASSED", "sub-indication": null })
        )
    );
    assert_eq!(
        Expected::indication(Indication::TotalFailed, Some("HASH_FAILURE")).members(),
        &object(
            json!({ "result": "validated", "indication": "TOTAL_FAILED", "sub-indication": "HASH_FAILURE" })
        )
    );
    assert_eq!(
        Expected::rejected().members(),
        &object(json!({ "result": "rejected" }))
    );
    assert_eq!(
        Expected::result(&DssResult::Rejected),
        Some(Expected::rejected())
    );
    assert_eq!(Expected::result(&DssResult::NotApplicable), None);
    assert_eq!(
        Expected::result(&DssResult::Indication {
            indication: Indication::Failed,
            sub_indication: Some("REVOKED".into())
        }),
        Some(Expected::indication(Indication::Failed, Some("REVOKED")))
    );
    assert_eq!(
        Expected::from_object(object(json!({ "policy": "aligned-1" }))).members(),
        &object(json!({ "policy": "aligned-1" }))
    );
    let custom = Expected::from_object(object(json!({ "mode": "validate-document" })))
        .member("result", json!("validated"))
        .member("mode", json!("validate-timestamp"));
    assert_eq!(
        custom.members(),
        &object(json!({ "mode": "validate-timestamp", "result": "validated" }))
    );
}

fn committed() -> Result<Manifest, Box<dyn std::error::Error>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/manifest.toml");
    Ok(Manifest::load(&path)?)
}

/// The members that every summary of a run of the corpus must have, in
/// `mode`: those that `sigillum-testpki verify --dss` checks as well.
fn of_the_corpus(manifest: &Manifest, mode: &str, expected: Expected) -> Expected {
    expected
        .member("mode", json!(mode))
        .member("validation-time", json!("2030-01-15T10:00:00Z"))
        .member("policy", json!("aligned-1"))
        .member(
            "oracle",
            json!({ "dss-version": manifest.header.dss_version }),
        )
}

#[test]
fn an_artefact_expects_the_result_of_its_divergence_or_its_prediction() -> TestResult {
    let manifest = committed()?;
    let find = |id: &str| {
        manifest
            .artefacts
            .iter()
            .find(|a| a.id == id)
            .ok_or(format!("no {id}"))
    };
    let divergent = manifest
        .artefacts
        .iter()
        .find(|a| a.dss_divergence.is_some())
        .ok_or("no divergence in the manifest")?;
    let result = divergent
        .dss_divergence
        .as_ref()
        .map(Divergence::result)
        .ok_or("no divergence")?;
    let expected = Expected::of_artefact(&manifest, divergent);
    assert_ne!(
        Expected::result(&divergent.expected_dss),
        Expected::result(&result)
    );
    let mode = match divergent.kind {
        Kind::TimestampToken => "validate-timestamp",
        Kind::SignedDocument => "validate-document",
        _ => "validate-certificate",
    };
    assert_eq!(
        expected,
        Expected::result(&result).map(|e| of_the_corpus(&manifest, mode, e))
    );
    for (id, mode, result) in [
        (
            "pki/signer-p256",
            "validate-certificate",
            Expected::indication(Indication::Passed, None),
        ),
        (
            "crl/ca-ecdsa",
            "validate-certificate",
            Expected::indication(Indication::Passed, None),
        ),
        (
            "timestamps/valid",
            "validate-timestamp",
            Expected::indication(Indication::Passed, None),
        ),
        (
            "signed/cades-detached-b-b-p256",
            "validate-document",
            Expected::indication(Indication::TotalPassed, None),
        ),
    ] {
        assert_eq!(
            Expected::of_artefact(&manifest, find(id)?),
            Some(of_the_corpus(&manifest, mode, result)),
            "{id}"
        );
    }
    assert_eq!(
        Expected::of_artefact(&manifest, find("documents/text")?),
        None
    );
    let rejected_with_divergence = Artefact {
        id: "x/y".into(),
        path: "x/y".into(),
        sha256: String::new(),
        kind: Kind::OcspResponse,
        purpose: String::new(),
        expected_openssl: OpensslResult::Rejected,
        expected_dss: DssResult::Rejected,
        links: Links::default(),
        notes: None,
        attack_class: None,
        dss_divergence: Some(Divergence {
            entry: "DIV-9".into(),
            indication: Indication::Passed,
            sub_indication: None,
        }),
    };
    assert_eq!(
        Expected::of_artefact(&manifest, &rejected_with_divergence),
        Some(of_the_corpus(
            &manifest,
            "validate-certificate",
            Expected::indication(Indication::Passed, None)
        ))
    );
    Ok(())
}

/// The bytes that the listed differences take: pointers and values.
fn listed_bytes(mismatch: &Mismatch) -> usize {
    let value = |value: &Option<Value>| value.as_ref().map_or(0, |v| v.to_string().len());
    mismatch
        .differences
        .iter()
        .map(|d| d.path.len() + value(&d.expected) + value(&d.found))
        .sum()
}

/// A long member name above an array of many differing elements: each
/// pointer would repeat the name, so the differences are counted, not
/// listed.
#[test]
fn a_long_name_over_many_differing_elements_is_counted_not_copied() {
    let name = "n".repeat(512 * 1024);
    let mut expected = Map::new();
    expected.insert(name.clone(), json!(vec![0; 4096]));
    let mut found = Map::new();
    found.insert(name, json!(vec![1; 4096]));
    let (expected, found) = (Value::Object(expected), Value::Object(found));
    for mismatch in [differences(&expected, &found), identical(&expected, &found)] {
        assert_eq!(mismatch.len(), 4096);
        assert!(!mismatch.is_empty());
        assert!(mismatch.differences.is_empty());
        assert_eq!(mismatch.omitted, 4096);
        assert_eq!(
            mismatch.to_string(),
            "summary.json differs in 4096 members:\n  4096 more, not listed"
        );
    }
}

#[test]
fn the_list_is_bounded_in_count() {
    let expected = json!({ "a": vec![0; 1000] });
    let found = json!({ "a": vec![1; 1000] });
    let mismatch = differences(&expected, &found);
    assert_eq!(mismatch.differences.len(), MAX_LISTED_DIFFERENCES);
    assert_eq!(mismatch.omitted, 1000 - MAX_LISTED_DIFFERENCES);
    assert_eq!(mismatch.differences[0].path, "/a/0");
    assert_eq!(
        mismatch.differences[MAX_LISTED_DIFFERENCES - 1].path,
        format!("/a/{}", MAX_LISTED_DIFFERENCES - 1)
    );
}

#[test]
fn the_list_is_bounded_in_bytes() {
    let long = |c: char| Value::from(c.to_string().repeat(1024));
    let expected = Value::from(vec![long('a'); 100]);
    let found = Value::from(vec![long('b'); 100]);
    let mismatch = identical(&expected, &found);
    assert_eq!(mismatch.len(), 100);
    assert!(mismatch.omitted > 0);
    assert!(listed_bytes(&mismatch) <= MAX_LISTED_BYTES);
    // The first differences are listed, in order.
    for (index, difference) in mismatch.differences.iter().enumerate() {
        assert_eq!(difference.path, format!("/{index}"));
    }
}

#[test]
fn a_mismatch_says_how_many_differences_it_does_not_list() {
    let partial = Mismatch {
        differences: vec![difference("/a", Some(json!(1)), Some(json!(2)))],
        omitted: 2,
    };
    assert_eq!(partial.len(), 3);
    assert_eq!(
        partial.to_string(),
        "summary.json differs in 3 members:\n  /a: expected 1, found 2\n  2 more, not listed"
    );
    assert!(Mismatch::default().is_empty());
    assert_eq!(Mismatch::default().len(), 0);
}

/// Any JSON value, up to a small depth.
fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        "[a-z~/ ]{0,4}".prop_map(Value::from),
    ];
    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::from),
            proptest::collection::btree_map("[a-z~/]{0,3}", inner, 0..4)
                .prop_map(|map| Value::Object(map.into_iter().collect())),
        ]
    })
}

proptest! {
    /// A value is identical to itself, and contains itself.
    #[test]
    fn a_value_has_no_differences_from_itself(value in any_json()) {
        prop_assert!(identical(&value, &value).is_empty());
        prop_assert!(differences(&value, &value).is_empty());
    }

    /// Two values are identical exactly when they are equal, and every
    /// reported pointer leads to the values it reports.
    #[test]
    fn identical_reports_exactly_the_unequal_values(first in any_json(), second in any_json()) {
        let found = identical(&first, &second);
        prop_assert_eq!(found.is_empty(), first == second);
        for difference in &found.differences {
            prop_assert_eq!(first.pointer(&difference.path), difference.expected.as_ref());
            prop_assert_eq!(second.pointer(&difference.path), difference.found.as_ref());
        }
    }
}

/// A difference whose pointer and values take exactly the bytes left is
/// listed, and one byte more is only counted. The pointer `/a~0b/12` takes
/// 8 bytes, the escaped name and the index included.
#[test]
fn the_byte_bound_counts_the_escaped_pointer_exactly() {
    let at_size = |size: usize| {
        // The value "x...x" takes its length and two quotes, and 0 takes 1.
        let text = "x".repeat(size - 8 - 1 - 2);
        let mut elements = vec![json!(0); 13];
        elements[12] = json!(text);
        let expected = json!({ "a~b": elements });
        let found = json!({ "a~b": vec![0; 13] });
        differences(&expected, &found)
    };
    let fits = at_size(MAX_LISTED_BYTES);
    assert_eq!(fits.omitted, 0);
    assert_eq!(fits.differences.len(), 1);
    assert_eq!(fits.differences[0].path, "/a~0b/12");
    assert_eq!(listed_bytes(&fits), MAX_LISTED_BYTES);
    let over = at_size(MAX_LISTED_BYTES + 1);
    assert!(over.differences.is_empty());
    assert_eq!(over.omitted, 1);
}

/// The length that the budget counts for a segment is the length that the
/// pointer gets, for indices at each change of their number of digits.
#[test]
fn a_segment_counts_the_length_that_it_writes() {
    let mut indices = vec![0, usize::MAX];
    let mut power = 1usize;
    while let Some(next) = power.checked_mul(10) {
        indices.extend([power - 1, power, next - 1]);
        power = next;
    }
    for index in indices {
        let segment = Segment::Index(index);
        let mut path = String::new();
        segment.write(&mut path);
        assert_eq!(segment.length(), path.len(), "{index}");
        assert_eq!(decimal_digits(index), index.to_string().len(), "{index}");
    }
    for name in ["", "a", "a~b/c", "~~//", "é/"] {
        let segment = Segment::Name(name);
        let mut path = String::new();
        segment.write(&mut path);
        assert_eq!(segment.length(), path.len(), "{name}");
    }
}
