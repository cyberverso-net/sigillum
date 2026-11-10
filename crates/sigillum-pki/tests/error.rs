//! The shared error type (ADR-0026, decision 8; threat R3).

use std::collections::HashSet;
use std::sync::OnceLock;

use proptest::prelude::*;
use sigillum_pki::{
    Context, EncodingKind, Error, ErrorKind, InputKind, JsonPointer, Limits, Location, UnixTime,
};

const KINDS: [ErrorKind; 8] = [
    ErrorKind::Malformed,
    ErrorKind::LimitExceeded,
    ErrorKind::NotSupported,
    ErrorKind::InvalidInput,
    ErrorKind::StateMismatch,
    ErrorKind::SignatureMismatch,
    ErrorKind::EvidenceRejected,
    ErrorKind::EvidenceUnavailable,
];

/// Member names known to sigillum, as a decoder would record them.
const MEMBERS: [&str; 6] = ["sigD", "hashV", "x5t#S256", "etsiU", "a/b", "c~d"];

#[test]
fn an_error_carries_its_kind_message_and_no_location() {
    for kind in KINDS {
        let error = Error::new(kind, "the value is wrong");
        assert_eq!(error.kind(), kind);
        assert_eq!(error.message(), "the value is wrong");
        assert_eq!(error.location(), None);
    }
}

#[test]
fn a_location_is_added_where_one_applies() {
    let error =
        Error::new(ErrorKind::Malformed, "the length runs past the input").at(Location::Offset(17));
    assert_eq!(error.kind(), ErrorKind::Malformed);
    assert_eq!(error.location(), Some(&Location::Offset(17)));
    assert_eq!(
        error.to_string(),
        "malformed input: the length runs past the input, at offset 17"
    );
}

#[test]
fn every_kind_has_its_own_description() {
    let mut descriptions: Vec<String> = KINDS.iter().map(ToString::to_string).collect();
    assert_eq!(
        descriptions,
        [
            "malformed input",
            "limit exceeded",
            "not supported",
            "invalid input",
            "state mismatch",
            "signature mismatch",
            "evidence rejected",
            "evidence unavailable",
        ]
    );
    descriptions.sort_unstable();
    descriptions.dedup();
    assert_eq!(descriptions.len(), KINDS.len());
}

#[test]
fn an_error_without_location_shows_kind_and_message() {
    let error = Error::new(ErrorKind::NotSupported, "the algorithm is not supported");
    assert_eq!(
        error.to_string(),
        "not supported: the algorithm is not supported"
    );
}

#[test]
fn json_pointers_follow_rfc_6901() {
    assert_eq!(JsonPointer::root().to_string(), "");
    let pointer = JsonPointer::root().member("sigD").member("hashV").index(0);
    assert_eq!(pointer.to_string(), "/sigD/hashV/0");
    let escaped = JsonPointer::root().member("a/b").member("c~d");
    assert_eq!(escaped.to_string(), "/a~1b/c~0d");
    let error = Error::new(ErrorKind::Malformed, "the digest is not base64url")
        .at(Location::JsonPointer(pointer.clone()));
    assert_eq!(
        error.to_string(),
        "malformed input: the digest is not base64url, at JSON pointer /sigD/hashV/0"
    );
    assert_eq!(error.location(), Some(&Location::JsonPointer(pointer)));
}

#[test]
fn json_pointer_tokens_are_kept_in_order() {
    use sigillum_pki::JsonPointerToken;
    let pointer = JsonPointer::root().member("sigD").index(3).unknown_member();
    assert_eq!(
        pointer.tokens(),
        &[
            JsonPointerToken::Member("sigD"),
            JsonPointerToken::Index(3),
            JsonPointerToken::UnknownMember
        ]
    );
}

#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "the placeholder is not a member name")]
fn the_placeholder_is_refused_as_a_member_name() {
    let _ = JsonPointer::root().member("(unknown)");
}

#[test]
fn an_unknown_member_is_written_as_a_fixed_placeholder() {
    let pointer = JsonPointer::root()
        .member("etsiU")
        .unknown_member()
        .index(2);
    assert_eq!(pointer.to_string(), "/etsiU/(unknown)/2");
    let error = Error::new(
        ErrorKind::NotSupported,
        "the header parameter is not supported",
    )
    .at(Location::JsonPointer(pointer));
    assert_eq!(
        error.to_string(),
        "not supported: the header parameter is not supported, at JSON pointer /etsiU/(unknown)/2"
    );
}

#[test]
fn pdf_objects_show_number_and_generation() {
    let location = Location::PdfObject {
        number: 12,
        generation: 0,
    };
    assert_eq!(location.to_string(), "PDF object 12 0");
    let error = Error::new(ErrorKind::Malformed, "the object is not a dictionary").at(location);
    assert_eq!(
        error.to_string(),
        "malformed input: the object is not a dictionary, at PDF object 12 0"
    );
}

#[test]
fn errors_are_standard_errors() {
    let error: Box<dyn std::error::Error + Send + Sync> = Box::new(Error::new(
        ErrorKind::EvidenceUnavailable,
        "no source remains",
    ));
    assert_eq!(error.to_string(), "evidence unavailable: no source remains");
    assert!(error.source().is_none());
}

#[test]
fn the_helper_builds_errors_at_the_largest_choices() {
    // The generators allow any usize as the choice, so positions derived
    // from it must not overflow.
    for choice in [usize::MAX, usize::MAX - 1, usize::MAX - 2, usize::MAX - 3] {
        for kind in 0..KINDS.len() {
            let error = error_over(b"input", kind, choice);
            assert!(!formatted(&error).is_empty());
        }
    }
}

/// Returns every run of five consecutive bytes of `bytes`.
fn runs_of_five(bytes: &[u8]) -> HashSet<&[u8]> {
    bytes.windows(5).collect()
}

/// Whether `output` contains any run of more than four consecutive bytes
/// of `input`.
fn repeats_input(output: &[u8], input: &[u8]) -> bool {
    let runs = runs_of_five(output);
    input.windows(5).any(|window| runs.contains(window))
}

/// Builds an error from `input` as a decoder would: the kind, the location
/// and the numbers come from the input, the message is fixed.
fn error_over(input: &[u8], kind: usize, choice: usize) -> Error {
    let kind = KINDS[kind % KINDS.len()];
    let len = input.len().max(1);
    // Each position is reduced below the length before anything is added,
    // so that no choice can overflow; the input is at most a few kilobytes.
    let byte = |at: usize| input.get(at % len).copied().unwrap_or(0);
    let word = |at: usize| {
        let at = at % len;
        u32::from_be_bytes([byte(at), byte(at + 1), byte(at + 2), byte(at + 3)])
    };
    let error = Error::new(kind, "the value at this location is not accepted");
    match choice % 4 {
        0 => error,
        1 => error.at(Location::Offset(
            u64::try_from(choice % input.len().max(1)).unwrap_or(0),
        )),
        2 => error.at(Location::PdfObject {
            number: word(choice),
            generation: u16::from_be_bytes([byte(choice), byte(choice % len + 1)]),
        }),
        _ => {
            let mut pointer = JsonPointer::root();
            for (step, value) in input.iter().take(8).enumerate() {
                pointer = match value % 3 {
                    0 => pointer.member(MEMBERS[usize::from(*value / 3) % MEMBERS.len()]),
                    1 => pointer.unknown_member(),
                    _ => pointer.index(word(step)),
                };
            }
            error.at(Location::JsonPointer(pointer))
        }
    }
}

fn formatted(error: &Error) -> Vec<String> {
    let mut outputs = vec![
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#?}"),
        error.message().to_owned(),
        error.kind().to_string(),
    ];
    if let Some(location) = error.location() {
        outputs.push(location.to_string());
        outputs.push(format!("{location:?}"));
    }
    outputs
}

/// Returns every error that the library itself produces today: the
/// refusals of each setter of `Limits`, of `Limits::check_input_size`, of
/// `UnixTime::from_seconds` and of `Context::require_signing_time`.
fn library_errors() -> &'static [Error] {
    static ERRORS: OnceLock<Vec<Error>> = OnceLock::new();
    ERRORS.get_or_init(build_library_errors)
}

fn build_library_errors() -> Vec<Error> {
    let kinds = [
        InputKind::Document,
        InputKind::Certificate,
        InputKind::Crl,
        InputKind::OcspResponse,
        InputKind::TimestampToken,
        InputKind::JoseHeader,
        InputKind::State,
    ];
    let limits = Limits::default();
    let mut errors = vec![
        limits.with_depth(EncodingKind::Der, u32::MAX).err(),
        limits.with_depth(EncodingKind::Json, u32::MAX).err(),
        limits.with_rounds(u32::MAX).err(),
        limits.with_requests(u32::MAX).err(),
        limits.with_response_size(u64::MAX).err(),
        UnixTime::from_seconds(u64::MAX).err(),
        UnixTime::from_seconds(0)
            .ok()
            .map(Context::for_validation)
            .and_then(|context| context.require_signing_time().err()),
    ];
    for kind in kinds {
        errors.push(limits.with_input_size(kind, u64::MAX).err());
        errors.push(limits.check_input_size(kind, usize::MAX).err());
    }
    errors.into_iter().flatten().collect()
}

#[test]
fn every_refusal_of_the_library_is_collected() {
    assert_eq!(library_errors().len(), 7 + 2 * 7);
}

/// Checks that no formatted form of `error` reproduces more than four
/// consecutive bytes of `input` (threat R3).
///
/// Every decoder added to the library runs this same property over the
/// errors it produces from random input, and adds its fixed messages to
/// the errors of [`library_errors`].
fn assert_never_reproduces(error: &Error, input: &[u8]) -> Result<(), TestCaseError> {
    for output in formatted(error) {
        prop_assert!(!repeats_input(output.as_bytes(), input), "{output}");
    }
    Ok(())
}

/// The text that the library itself writes for every kind and every form
/// of location, with numbers set to zero. An input that happens to contain
/// a run of this text is excluded, because the output then contains that
/// run by construction, not because the input was copied.
fn own_text() -> &'static HashSet<&'static [u8]> {
    static TEXT: OnceLock<Vec<u8>> = OnceLock::new();
    static RUNS: OnceLock<HashSet<&'static [u8]>> = OnceLock::new();
    RUNS.get_or_init(|| runs_of_five(TEXT.get_or_init(build_own_text)))
}

/// Whether `input` contains a run of the library's own text.
fn meets_own_text(input: &[u8]) -> bool {
    let runs = own_text();
    input.windows(5).any(|window| runs.contains(window))
}

fn build_own_text() -> Vec<u8> {
    let mut pointer = JsonPointer::root();
    for first in MEMBERS {
        for second in MEMBERS {
            pointer = pointer
                .member(first)
                .member(second)
                .index(0)
                .unknown_member()
                .member(first);
        }
    }
    let locations = [
        Location::Offset(0),
        Location::PdfObject {
            number: 0,
            generation: 0,
        },
        Location::JsonPointer(pointer),
    ];
    let mut text = Vec::new();
    for error in library_errors() {
        for output in formatted(error) {
            text.extend_from_slice(output.as_bytes());
            text.push(0);
        }
    }
    for kind in KINDS {
        let error = Error::new(kind, "the value at this location is not accepted");
        for output in formatted(&error) {
            text.extend_from_slice(output.as_bytes());
            text.push(0);
        }
        for location in &locations {
            for output in formatted(&error.clone().at(location.clone())) {
                text.extend_from_slice(output.as_bytes());
                text.push(0);
            }
        }
    }
    text
}

proptest! {
    /// Formatting an error never reproduces more than four consecutive
    /// bytes of the input it was built over, nor does formatting any error
    /// that the library produces (threat R3).
    #[test]
    fn formatting_never_reproduces_the_input(
        input in proptest::collection::vec(any::<u8>(), 0..1024),
        kind in any::<usize>(),
        choice in any::<usize>(),
    ) {
        prop_assume!(!meets_own_text(&input));
        assert_never_reproduces(&error_over(&input, kind, choice), &input)?;
        for error in library_errors() {
            assert_never_reproduces(error, &input)?;
        }
    }

    /// The same over printable text without digits, which is close to the
    /// text of the messages. Without digits, the input cannot meet the
    /// numbers of a location by chance, so only copying could fail the test.
    #[test]
    fn formatting_never_reproduces_text_input(
        input in "[ -/:-~]{0,512}",
        kind in any::<usize>(),
        choice in any::<usize>(),
    ) {
        prop_assume!(!meets_own_text(input.as_bytes()));
        let input = input.as_bytes();
        assert_never_reproduces(&error_over(input, kind, choice), input)?;
        for error in library_errors() {
            assert_never_reproduces(error, input)?;
        }
    }
}
