//! Construction and defaults of the shared context (ADR-0026, decisions 3
//! and 4) and of its times.

use sigillum_pki::{Context, ErrorKind, Limits, UnixTime};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// 2026-11-07T00:00:00Z.
const SIGNING: u64 = 1_794_009_600;
/// One hour later.
const VALIDATION: u64 = SIGNING + 3600;

#[test]
fn times_cover_the_range_of_generalized_time() -> TestResult {
    assert_eq!(UnixTime::from_seconds(0)?.seconds(), 0);
    assert_eq!(UnixTime::MAX_SECONDS, 253_402_300_799);
    assert_eq!(
        UnixTime::from_seconds(UnixTime::MAX_SECONDS)?.seconds(),
        UnixTime::MAX_SECONDS
    );
    let refused = UnixTime::from_seconds(UnixTime::MAX_SECONDS + 1);
    assert_eq!(
        refused.as_ref().err().map(|error| error.kind()),
        Some(ErrorKind::InvalidInput)
    );
    assert_eq!(
        refused.err().and_then(|error| error.location().cloned()),
        None
    );
    Ok(())
}

#[test]
fn times_are_ordered_by_their_seconds() -> TestResult {
    let earlier = UnixTime::from_seconds(SIGNING)?;
    let later = UnixTime::from_seconds(VALIDATION)?;
    assert!(earlier < later);
    assert_eq!(earlier, UnixTime::from_seconds(SIGNING)?);
    Ok(())
}

#[test]
fn a_signing_context_carries_both_times() -> TestResult {
    let signing = UnixTime::from_seconds(SIGNING)?;
    let validation = UnixTime::from_seconds(VALIDATION)?;
    let context = Context::for_signing(signing, validation);
    assert_eq!(context.signing_time(), Some(signing));
    assert_eq!(context.require_signing_time()?, signing);
    assert_eq!(context.validation_time(), validation);
    Ok(())
}

#[test]
fn a_validation_context_has_no_signing_time() -> TestResult {
    let validation = UnixTime::from_seconds(VALIDATION)?;
    let context = Context::for_validation(validation);
    assert_eq!(context.signing_time(), None);
    assert_eq!(context.validation_time(), validation);
    let refused = context.require_signing_time();
    assert_eq!(
        refused.as_ref().err().map(|error| error.kind()),
        Some(ErrorKind::InvalidInput)
    );
    assert_eq!(
        refused.err().and_then(|error| error.location().cloned()),
        None
    );
    Ok(())
}

#[test]
fn a_new_context_has_defaults_and_no_relaxation() -> TestResult {
    let time = UnixTime::from_seconds(SIGNING)?;
    for context in [
        Context::for_signing(time, time),
        Context::for_validation(time),
    ] {
        assert!(context.trust_anchors().is_empty());
        assert!(context.certificates().is_empty());
        assert!(context.crls().is_empty());
        assert!(context.ocsp_responses().is_empty());
        assert_eq!(context.limits(), &Limits::default());
        assert!(!context.allows_lower_level_on_unknown_revocation());
    }
    Ok(())
}

#[test]
fn supplied_material_is_kept_in_order() -> TestResult {
    let time = UnixTime::from_seconds(SIGNING)?;
    let context = Context::for_signing(time, time)
        .with_trust_anchor(vec![1])
        .with_trust_anchor(vec![2])
        .with_certificate(vec![3])
        .with_certificate(vec![4])
        .with_crl(vec![5])
        .with_ocsp_response(vec![6])
        .with_ocsp_response(vec![7]);
    assert_eq!(context.trust_anchors(), &[vec![1], vec![2]]);
    assert_eq!(context.certificates(), &[vec![3], vec![4]]);
    assert_eq!(context.crls(), &[vec![5]]);
    assert_eq!(context.ocsp_responses(), &[vec![6], vec![7]]);
    Ok(())
}

#[test]
fn limits_and_relaxations_are_set_explicitly() -> TestResult {
    let time = UnixTime::from_seconds(SIGNING)?;
    let limits = Limits::default().with_rounds(2)?.with_requests(5)?;
    let context = Context::for_signing(time, time)
        .with_limits(limits)
        .allow_lower_level_on_unknown_revocation();
    assert_eq!(context.limits(), &limits);
    assert!(context.allows_lower_level_on_unknown_revocation());
    Ok(())
}
