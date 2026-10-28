//! The comparison of a `summary.json` with the result expected of it.

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};

use serde_json::{Map, Value};
use sigillum_testpki::dss::Mode;
use sigillum_testpki::manifest::{Artefact, DssResult, Indication, Kind, Manifest};
use time::format_description::well_known::Rfc3339;

use crate::summary::Summary;

/// The name that `summary.json` gives the aligned policy of ADR-0023 in
/// its version 1.
const ALIGNED_POLICY: &str = "aligned-1";

/// What a `summary.json` must contain: a JSON object whose members must
/// all be in the summary with the same values. Members that it does not
/// name may have any value, at any depth. Arrays must have the same
/// length, element by element.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Expected {
    members: Map<String, Value>,
}

impl Expected {
    /// An expectation that any summary meets, to which members are added
    /// with [`Expected::member`].
    pub fn new() -> Self {
        Self::default()
    }

    /// An expectation with the members of `object`.
    pub fn from_object(object: Map<String, Value>) -> Self {
        Self { members: object }
    }

    /// The summary of a validation that gives `indication` and
    /// `sub_indication`, written as in the manifest of the corpus, with
    /// hyphens. DSS writes indications with underscores, so the
    /// expectation does too. Without a sub-indication, the summary must
    /// give `null`.
    pub fn indication(indication: Indication, sub_indication: Option<&str>) -> Self {
        Self::new()
            .member("result", Value::from("validated"))
            .member(
                "indication",
                Value::from(indication.as_str().replace('-', "_")),
            )
            .member(
                "sub-indication",
                sub_indication.map_or(Value::Null, Value::from),
            )
    }

    /// The summary of a run that DSS rejected, because it cannot parse or
    /// use an input.
    pub fn rejected() -> Self {
        Self::new().member("result", Value::from("rejected"))
    }

    /// The summary of a run that gives `result`, as the manifest of the
    /// corpus writes it, or `None` for `not-applicable`, since DSS does not
    /// process such an artefact.
    pub fn result(result: &DssResult) -> Option<Self> {
        match result {
            DssResult::NotApplicable => None,
            DssResult::Rejected => Some(Self::rejected()),
            DssResult::Indication {
                indication,
                sub_indication,
            } => Some(Self::indication(*indication, sub_indication.as_deref())),
        }
    }

    /// The summary that DSS must give for `artefact` of `manifest`: the
    /// result of its `dss-divergence` when it has one, which
    /// `docs/design/divergences.md` records, and its `expected-dss`
    /// otherwise. As `sigillum-testpki verify --dss` requires, the summary
    /// must also name the mode of the artefact, the validation time and
    /// DSS version of the manifest, and the aligned policy of ADR-0023,
    /// `aligned-1`. `None` when DSS does not process the artefact, and for
    /// a manifest built by the caller whose validation time RFC 3339
    /// cannot write, which a parsed manifest never holds.
    pub fn of_artefact(manifest: &Manifest, artefact: &Artefact) -> Option<Self> {
        if artefact.expected_dss == DssResult::NotApplicable {
            return None;
        }
        let result = artefact
            .dss_divergence
            .as_ref()
            .map_or_else(|| artefact.expected_dss.clone(), |d| d.result());
        let mode = match artefact.kind {
            Kind::TimestampToken => Mode::Timestamp,
            Kind::SignedDocument => Mode::Document,
            _ => Mode::Certificate,
        };
        let header = &manifest.header;
        // A parsed manifest holds a validation time of the form
        // YYYY-MM-DDTHH:MM:SSZ, which RFC 3339 can always write; a manifest
        // built by the caller with a time it cannot write expects nothing.
        let time = header.validation_time.format(&Rfc3339).ok()?;
        Some(
            Self::result(&result)?
                .member("mode", Value::from(mode.name()))
                .member("validation-time", Value::from(time))
                .member("policy", Value::from(ALIGNED_POLICY))
                .member(
                    "oracle",
                    Value::Object(Map::from_iter([(
                        "dss-version".to_owned(),
                        Value::from(header.dss_version.as_str()),
                    )])),
                ),
        )
    }

    /// Adds the member `name` with `value`, or replaces it.
    #[must_use]
    pub fn member(mut self, name: &str, value: Value) -> Self {
        self.members.insert(name.to_owned(), value);
        self
    }

    /// The members that the summary must contain.
    pub fn members(&self) -> &Map<String, Value> {
        &self.members
    }
}

/// A member whose value differs between two JSON documents.
#[derive(Debug, Clone, PartialEq)]
pub struct Difference {
    /// Where the member is, as a JSON pointer that
    /// `serde_json::Value::pointer` reads, such as
    /// `/details/revocation/status`; empty for the whole document.
    pub path: String,
    /// The expected value, or `None` when no value was expected there.
    pub expected: Option<Value>,
    /// The value found, or `None` when the member is missing.
    pub found: Option<Value>,
}

/// One line: the pointer, the expected value and the value found, in
/// JSON, or `nothing` for a missing value.
impl fmt::Display for Difference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = |value: &Option<Value>| {
            value
                .as_ref()
                .map_or_else(|| "nothing".to_owned(), Value::to_string)
        };
        let path = if self.path.is_empty() {
            "the document"
        } else {
            &self.path
        };
        write!(
            f,
            "{path}: expected {}, found {}",
            value(&self.expected),
            value(&self.found)
        )
    }
}

/// The most differences that a [`Mismatch`] lists.
pub const MAX_LISTED_DIFFERENCES: usize = 256;

/// The most bytes that the differences of a [`Mismatch`] may take: their
/// pointers and their values written as JSON.
pub const MAX_LISTED_BYTES: usize = 64 * 1024;

/// The differences between two JSON documents, such as a summary and what
/// was expected of it.
///
/// The list is bounded, so that two documents of a few kilobytes cannot
/// make it large: it holds at most [`MAX_LISTED_DIFFERENCES`] differences
/// of at most [`MAX_LISTED_BYTES`] in all. The others are only counted.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Mismatch {
    /// The differences listed, the members of each object in the order of
    /// their names, and the elements of each array in their order.
    pub differences: Vec<Difference>,
    /// The number of further differences, counted but not listed.
    pub omitted: usize,
}

impl Mismatch {
    /// Reports whether the documents have no difference.
    pub fn is_empty(&self) -> bool {
        self.differences.is_empty() && self.omitted == 0
    }

    /// The number of differences, listed or not.
    pub fn len(&self) -> usize {
        self.differences.len() + self.omitted
    }
}

/// A first line that counts the members, then one indented line per
/// listed [`Difference`], and a last line that counts the others.
impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.len();
        let noun = if count == 1 { "member" } else { "members" };
        write!(f, "summary.json differs in {count} {noun}:")?;
        for difference in &self.differences {
            write!(f, "\n  {difference}")?;
        }
        if self.omitted > 0 {
            write!(f, "\n  {} more, not listed", self.omitted)?;
        }
        Ok(())
    }
}

impl std::error::Error for Mismatch {}

/// Checks that `summary` contains every member of `expected`.
///
/// # Errors
///
/// Returns a [`Mismatch`] with every member of `expected` that differs in
/// `summary` or is missing from it, listed within the bounds of
/// [`Mismatch`] and counted beyond them.
pub fn check(summary: &Summary, expected: &Expected) -> Result<(), Mismatch> {
    let differences = differences(&Value::Object(expected.members.clone()), summary.json());
    if differences.is_empty() {
        Ok(())
    } else {
        Err(differences)
    }
}

/// The members of `expected` that differ in `found`, or are missing from
/// it, at any depth. Members of `found` that `expected` does not name are
/// not differences. Arrays are compared element by element, and an
/// element only one of them has is a difference.
///
/// The comparison recurses into nested values without a bound of its own.
/// A parsed summary is at most 128 levels deep, the limit of `serde_json`;
/// a value built by the caller may be deeper.
pub fn differences(expected: &Value, found: &Value) -> Mismatch {
    Walk::new(false).run(expected, found)
}

/// Every member that differs between `first` and `second`, at any depth,
/// including members that only `second` has. The values of `first` are
/// reported as expected. Two runs of the same validation must give
/// identical summaries.
///
/// The comparison recurses into nested values without a bound of its own.
/// A parsed summary is at most 128 levels deep, the limit of `serde_json`;
/// a value built by the caller may be deeper.
pub fn identical(first: &Value, second: &Value) -> Mismatch {
    Walk::new(true).run(first, second)
}

/// A part of the pointer of the value under comparison.
enum Segment<'a> {
    /// A member name.
    Name(&'a str),
    /// An array index.
    Index(usize),
}

/// A comparison of two documents. The pointer of the value under
/// comparison is a stack of borrowed segments, written out only for a
/// difference that is listed, so that a long member name is not copied
/// for every value below it.
struct Walk<'a> {
    exact: bool,
    path: Vec<Segment<'a>>,
    /// The length of the pointer that `path` stands for.
    path_length: usize,
    bytes: usize,
    mismatch: Mismatch,
}

impl<'a> Walk<'a> {
    fn new(exact: bool) -> Self {
        Self {
            exact,
            path: Vec::new(),
            path_length: 0,
            bytes: 0,
            mismatch: Mismatch::default(),
        }
    }

    fn run(mut self, expected: &'a Value, found: &'a Value) -> Mismatch {
        self.compare(Some(expected), Some(found));
        self.mismatch
    }

    /// Compares the values at the current pointer, either of which may be
    /// missing. Members that only `found` has are differences when
    /// `exact`.
    fn compare(&mut self, expected: Option<&'a Value>, found: Option<&'a Value>) {
        match (expected, found) {
            (Some(Value::Object(expected)), Some(Value::Object(found))) => {
                let mut names: BTreeSet<&'a String> = expected.keys().collect();
                if self.exact {
                    names.extend(found.keys());
                }
                for name in names {
                    self.enter(Segment::Name(name));
                    self.compare(expected.get(name), found.get(name));
                    self.leave();
                }
            }
            (Some(Value::Array(expected)), Some(Value::Array(found))) => {
                for index in 0..expected.len().max(found.len()) {
                    self.enter(Segment::Index(index));
                    self.compare(expected.get(index), found.get(index));
                    self.leave();
                }
            }
            (expected, found) if expected != found => self.record(expected, found),
            _ => {}
        }
    }

    /// Moves the pointer down to `segment`.
    fn enter(&mut self, segment: Segment<'a>) {
        self.path_length = self.path_length.saturating_add(segment.length());
        self.path.push(segment);
    }

    /// Moves the pointer back up one segment.
    fn leave(&mut self) {
        if let Some(segment) = self.path.pop() {
            self.path_length = self.path_length.saturating_sub(segment.length());
        }
    }

    /// Lists the difference at the current pointer when the list has room
    /// for it, and counts it otherwise. Nothing is allocated for a
    /// difference that is only counted.
    fn record(&mut self, expected: Option<&Value>, found: Option<&Value>) {
        let list = &mut self.mismatch.differences;
        if list.len() >= MAX_LISTED_DIFFERENCES {
            self.mismatch.omitted += 1;
            return;
        }
        let path_length = self.path_length;
        let needed = path_length
            .saturating_add(json_length(expected))
            .saturating_add(json_length(found));
        if needed > MAX_LISTED_BYTES.saturating_sub(self.bytes) {
            self.mismatch.omitted += 1;
            return;
        }
        self.bytes += needed;
        let mut path = String::with_capacity(path_length);
        for segment in &self.path {
            segment.write(&mut path);
        }
        list.push(Difference {
            path,
            expected: expected.cloned(),
            found: found.cloned(),
        });
    }
}

impl Segment<'_> {
    /// The length of the segment in a pointer, with its `/`.
    fn length(&self) -> usize {
        match self {
            Self::Name(name) => 1 + name.len() + name.matches(['~', '/']).count(),
            Self::Index(index) => 1 + decimal_digits(*index),
        }
    }

    /// Adds `/` and the segment to `path`. In a name, `~` becomes `~0` and
    /// `/` becomes `~1`, as `serde_json::Value::pointer` reads them.
    fn write(&self, path: &mut String) {
        path.push('/');
        match self {
            Self::Name(name) => {
                for c in name.chars() {
                    match c {
                        '~' => path.push_str("~0"),
                        '/' => path.push_str("~1"),
                        c => path.push(c),
                    }
                }
            }
            Self::Index(index) => {
                // Writing to a String cannot fail.
                let _ = write!(path, "{index}");
            }
        }
    }
}

/// The number of decimal digits of `n`, counted without writing it.
fn decimal_digits(n: usize) -> usize {
    n.checked_ilog10().map_or(1, |log| log as usize + 1)
}

/// The length of `value` written as JSON, as `Difference` writes it,
/// counted without writing it; 0 for no value.
fn json_length(value: Option<&Value>) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(bytes.len());
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    if let Some(value) = value {
        // Writing to a counter cannot fail.
        let _ = serde_json::to_writer(&mut counter, value);
    }
    counter.0
}

#[cfg(test)]
mod tests;
