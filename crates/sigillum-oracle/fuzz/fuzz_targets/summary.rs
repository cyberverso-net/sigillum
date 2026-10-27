//! Fuzz target for the reader of `summary.json` and the comparisons of
//! `sigillum-oracle`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use sigillum_oracle::{
    Expected, Indication, MAX_LISTED_DIFFERENCES, Mismatch, Summary, check, differences, identical,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(summary) = Summary::parse(text) {
        let _ = summary.result();
        let expected = Expected::indication(Indication::Passed, None);
        if let Err(mismatch) = check(&summary, &expected) {
            assert!(!mismatch.is_empty());
            bounded(&mismatch);
            let _ = mismatch.to_string();
        }
        // A summary contains its own members, and is identical to itself.
        let object = summary.json().as_object().cloned().unwrap_or_default();
        assert!(check(&summary, &Expected::from_object(object)).is_ok());
        assert!(identical(summary.json(), summary.json()).is_empty());
    }
    // The two halves of the text as two JSON values: each reported pointer
    // leads to the values that it reports.
    let Some((left, right)) = text.split_at_checked(text.len() / 2) else {
        return;
    };
    if let (Ok(first), Ok(second)) = (
        serde_json::from_str::<Value>(left),
        serde_json::from_str::<Value>(right),
    ) {
        let found = identical(&first, &second);
        assert_eq!(found.is_empty(), first == second);
        for mismatch in [found, differences(&first, &second)] {
            bounded(&mismatch);
            for difference in &mismatch.differences {
                assert_eq!(
                    first.pointer(&difference.path),
                    difference.expected.as_ref()
                );
                assert_eq!(second.pointer(&difference.path), difference.found.as_ref());
            }
        }
    }
});

/// The list of a mismatch keeps within its bounds.
fn bounded(mismatch: &Mismatch) {
    assert!(mismatch.differences.len() <= MAX_LISTED_DIFFERENCES);
    let bytes: usize = mismatch
        .differences
        .iter()
        .map(|d| {
            let value =
                |v: &Option<serde_json::Value>| v.as_ref().map_or(0, |v| v.to_string().len());
            d.path.len() + value(&d.expected) + value(&d.found)
        })
        .sum();
    assert!(bytes <= sigillum_oracle::MAX_LISTED_BYTES);
}
