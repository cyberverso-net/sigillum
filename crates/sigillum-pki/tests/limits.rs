//! Defaults, maxima and refusals of the limits (ADR-0024, rule 1;
//! ADR-0026, decision 4; threat P2).

use sigillum_pki::{Error, ErrorKind, InputKind, Limits};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const KINDS: [InputKind; 7] = [
    InputKind::Document,
    InputKind::Certificate,
    InputKind::Crl,
    InputKind::OcspResponse,
    InputKind::TimestampToken,
    InputKind::JoseHeader,
    InputKind::State,
];

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;
const GIB: u64 = 1024 * MIB;

fn refused_kind<T>(result: Result<T, Error>) -> Option<ErrorKind> {
    result.err().map(|error| error.kind())
}

#[test]
fn defaults_are_the_documented_values() {
    let limits = Limits::default();
    assert_eq!(limits.depth(), Limits::DEFAULT_DEPTH);
    assert_eq!(limits.rounds(), Limits::DEFAULT_ROUNDS);
    assert_eq!(limits.requests(), Limits::DEFAULT_REQUESTS);
    assert_eq!(limits.response_size(), Limits::DEFAULT_RESPONSE_SIZE);
    for kind in KINDS {
        assert_eq!(limits.input_size(kind), kind.default_size(), "{kind:?}");
    }
    assert_eq!(Limits::new(), limits);
}

#[test]
fn documented_values_are_fixed() {
    assert_eq!((Limits::DEFAULT_DEPTH, Limits::MAXIMUM_DEPTH), (32, 64));
    assert_eq!((Limits::DEFAULT_ROUNDS, Limits::MAXIMUM_ROUNDS), (8, 32));
    assert_eq!(
        (Limits::DEFAULT_REQUESTS, Limits::MAXIMUM_REQUESTS),
        (32, 256)
    );
    assert_eq!(
        (Limits::DEFAULT_RESPONSE_SIZE, Limits::MAXIMUM_RESPONSE_SIZE),
        (16 * MIB, 256 * MIB)
    );
    let sizes = [
        (InputKind::Document, 64 * MIB, GIB),
        (InputKind::Certificate, 64 * KIB, MIB),
        (InputKind::Crl, 16 * MIB, 256 * MIB),
        (InputKind::OcspResponse, 64 * KIB, MIB),
        (InputKind::TimestampToken, 64 * KIB, MIB),
        (InputKind::JoseHeader, 64 * KIB, MIB),
        (InputKind::State, 32 * MIB, GIB),
    ];
    for (kind, default, maximum) in sizes {
        assert_eq!(kind.default_size(), default, "{kind:?}");
        assert_eq!(kind.maximum_size(), maximum, "{kind:?}");
    }
}

#[test]
fn every_default_is_within_its_maximum() -> TestResult {
    let mut limits = Limits::default()
        .with_depth(Limits::DEFAULT_DEPTH)?
        .with_rounds(Limits::DEFAULT_ROUNDS)?
        .with_requests(Limits::DEFAULT_REQUESTS)?
        .with_response_size(Limits::DEFAULT_RESPONSE_SIZE)?;
    for kind in KINDS {
        assert!(kind.default_size() <= kind.maximum_size(), "{kind:?}");
        limits = limits.with_input_size(kind, kind.default_size())?;
    }
    assert_eq!(limits, Limits::default());
    Ok(())
}

#[test]
fn maxima_are_accepted() -> TestResult {
    let mut limits = Limits::default()
        .with_depth(Limits::MAXIMUM_DEPTH)?
        .with_rounds(Limits::MAXIMUM_ROUNDS)?
        .with_requests(Limits::MAXIMUM_REQUESTS)?
        .with_response_size(Limits::MAXIMUM_RESPONSE_SIZE)?;
    for kind in KINDS {
        limits = limits.with_input_size(kind, kind.maximum_size())?;
    }
    assert_eq!(limits.depth(), Limits::MAXIMUM_DEPTH);
    assert_eq!(limits.rounds(), Limits::MAXIMUM_ROUNDS);
    assert_eq!(limits.requests(), Limits::MAXIMUM_REQUESTS);
    assert_eq!(limits.response_size(), Limits::MAXIMUM_RESPONSE_SIZE);
    for kind in KINDS {
        assert_eq!(limits.input_size(kind), kind.maximum_size(), "{kind:?}");
    }
    Ok(())
}

#[test]
fn zero_is_accepted() -> TestResult {
    let mut limits = Limits::default()
        .with_depth(0)?
        .with_rounds(0)?
        .with_requests(0)?
        .with_response_size(0)?;
    for kind in KINDS {
        limits = limits.with_input_size(kind, 0)?;
    }
    assert_eq!(
        (limits.depth(), limits.rounds(), limits.requests()),
        (0, 0, 0)
    );
    assert_eq!(limits.response_size(), 0);
    for kind in KINDS {
        assert_eq!(limits.input_size(kind), 0, "{kind:?}");
    }
    Ok(())
}

#[test]
fn values_above_the_maximum_are_refused() {
    let invalid = Some(ErrorKind::InvalidInput);
    let limits = Limits::default();
    assert_eq!(
        refused_kind(limits.with_depth(Limits::MAXIMUM_DEPTH + 1)),
        invalid
    );
    assert_eq!(
        refused_kind(limits.with_rounds(Limits::MAXIMUM_ROUNDS + 1)),
        invalid
    );
    assert_eq!(
        refused_kind(limits.with_requests(Limits::MAXIMUM_REQUESTS + 1)),
        invalid
    );
    assert_eq!(
        refused_kind(limits.with_response_size(Limits::MAXIMUM_RESPONSE_SIZE + 1)),
        invalid
    );
    assert_eq!(refused_kind(limits.with_depth(u32::MAX)), invalid);
    assert_eq!(refused_kind(limits.with_response_size(u64::MAX)), invalid);
    for kind in KINDS {
        assert_eq!(
            refused_kind(limits.with_input_size(kind, kind.maximum_size() + 1)),
            invalid,
            "{kind:?}"
        );
        assert_eq!(
            refused_kind(limits.with_input_size(kind, u64::MAX)),
            invalid,
            "{kind:?}"
        );
    }
}

#[test]
fn refusals_carry_no_location_and_distinct_messages() {
    let limits = Limits::default();
    let errors = [
        limits.with_depth(u32::MAX).err(),
        limits.with_rounds(u32::MAX).err(),
        limits.with_requests(u32::MAX).err(),
        limits.with_response_size(u64::MAX).err(),
        limits.with_input_size(InputKind::Document, u64::MAX).err(),
    ];
    let mut messages = Vec::new();
    for error in errors.iter().flatten() {
        assert_eq!(error.location(), None);
        messages.push(error.message());
    }
    assert_eq!(messages.len(), errors.len());
    messages.sort_unstable();
    messages.dedup();
    assert_eq!(messages.len(), errors.len());
}

#[test]
fn setting_one_limit_leaves_the_others() -> TestResult {
    let limits = Limits::default().with_input_size(InputKind::Crl, 1)?;
    assert_eq!(limits.input_size(InputKind::Crl), 1);
    for kind in KINDS.into_iter().filter(|kind| *kind != InputKind::Crl) {
        assert_eq!(limits.input_size(kind), kind.default_size(), "{kind:?}");
    }
    assert_eq!(limits.depth(), Limits::DEFAULT_DEPTH);
    assert_eq!(limits.response_size(), Limits::DEFAULT_RESPONSE_SIZE);
    Ok(())
}

#[test]
fn input_size_is_checked_against_the_limit() -> TestResult {
    let limits = Limits::default().with_input_size(InputKind::Certificate, 10)?;
    assert_eq!(limits.check_input_size(InputKind::Certificate, 0), Ok(()));
    assert_eq!(limits.check_input_size(InputKind::Certificate, 10), Ok(()));
    let refused = limits.check_input_size(InputKind::Certificate, 11);
    assert_eq!(
        refused.as_ref().err().map(Error::kind),
        Some(ErrorKind::LimitExceeded)
    );
    assert_eq!(
        refused.err().and_then(|error| error.location().cloned()),
        None
    );
    assert_eq!(
        refused_kind(limits.check_input_size(InputKind::Certificate, usize::MAX)),
        Some(ErrorKind::LimitExceeded)
    );
    assert_eq!(limits.check_input_size(InputKind::Document, 11), Ok(()));
    Ok(())
}

#[test]
fn a_zero_limit_refuses_every_non_empty_input() -> TestResult {
    let limits = Limits::default().with_input_size(InputKind::State, 0)?;
    assert_eq!(limits.check_input_size(InputKind::State, 0), Ok(()));
    assert_eq!(
        refused_kind(limits.check_input_size(InputKind::State, 1)),
        Some(ErrorKind::LimitExceeded)
    );
    Ok(())
}
