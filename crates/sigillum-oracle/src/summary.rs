//! The `summary.json` that a validation mode of `tools/dss-oracle` writes,
//! described under "summary.json" in the README of the tool.

use std::fmt;
use std::path::Path;

use serde_json::Value;
use sigillum_testpki::dss::{MAX_SUMMARY_LEN, Mode, read_limited, read_summary};
use sigillum_testpki::manifest::DssResult;

/// The format version of `summary.json` that this crate reads.
pub const FORMAT_VERSION: u64 = 3;

/// The modes that write a `summary.json`.
const MODES: [Mode; 3] = [Mode::Certificate, Mode::Timestamp, Mode::Document];

/// The results that a summary may give.
const RESULTS: [&str; 3] = ["validated", "rejected", "resource-limit"];

/// A `summary.json` of `tools/dss-oracle`, checked for the members that
/// every summary has.
#[derive(Debug, Clone, PartialEq)]
pub struct Summary {
    text: String,
    json: Value,
    mode: Mode,
}

/// Why a text is not a `summary.json` that this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SummaryError {
    /// The file cannot be read, is not UTF-8 or is larger than 1 MiB.
    Read(String),
    /// The text is not JSON.
    Json(String),
    /// The JSON value is not an object.
    NotAnObject,
    /// The text is longer than `sigillum_testpki::dss::MAX_SUMMARY_LEN`,
    /// 1 MiB, the most that [`Summary::read`] reads.
    TooLarge {
        /// The length of the text, in bytes.
        length: usize,
    },
    /// A member that every summary has is missing or has a value that this
    /// crate does not read.
    Member {
        /// The member, as a JSON pointer such as `/oracle/dss-version`.
        name: &'static str,
        /// The value found, in JSON, or `null` when it is missing.
        found: String,
    },
}

impl fmt::Display for SummaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(message) => write!(f, "summary.json cannot be read: {message}"),
            Self::Json(message) => write!(f, "summary.json is not JSON: {message}"),
            Self::NotAnObject => f.write_str("summary.json is not a JSON object"),
            Self::TooLarge { length } => write!(
                f,
                "summary.json has {length} bytes, more than {MAX_SUMMARY_LEN}"
            ),
            Self::Member { name, found } => write!(
                f,
                "summary.json gives {name} {found}, which this crate does not read"
            ),
        }
    }
}

impl std::error::Error for SummaryError {}

impl Summary {
    /// Parses a `summary.json` and checks the members that every summary
    /// has: `format-version` is [`FORMAT_VERSION`], `mode` names a
    /// validation mode, `validation-time` and `oracle/dss-version` are
    /// strings, `policy` is a string or an object, and `result` is `validated`,
    /// `rejected` or `resource-limit`.
    ///
    /// # Errors
    ///
    /// Returns a [`SummaryError`] when the text is not JSON, or lacks one
    /// of these members or gives it another value.
    pub fn parse(text: &str) -> Result<Self, SummaryError> {
        if u64::try_from(text.len()).map_or(true, |length| length > MAX_SUMMARY_LEN) {
            return Err(SummaryError::TooLarge { length: text.len() });
        }
        let json: Value =
            serde_json::from_str(text).map_err(|e| SummaryError::Json(e.to_string()))?;
        if !json.is_object() {
            return Err(SummaryError::NotAnObject);
        }
        let refused = |name: &'static str| SummaryError::Member {
            name,
            found: json.pointer(name).unwrap_or(&Value::Null).to_string(),
        };
        let member = |name: &'static str, accepted: &dyn Fn(&Value) -> bool| {
            let value = json.pointer(name).unwrap_or(&Value::Null);
            if accepted(value) {
                Ok(())
            } else {
                Err(refused(name))
            }
        };
        member("/format-version", &|v| v.as_u64() == Some(FORMAT_VERSION))?;
        let mode = MODES
            .into_iter()
            .find(|mode| json.pointer("/mode").and_then(Value::as_str) == Some(mode.name()))
            .ok_or_else(|| refused("/mode"))?;
        member("/validation-time", &Value::is_string)?;
        member("/oracle/dss-version", &Value::is_string)?;
        member("/policy", &|v| v.is_string() || v.is_object())?;
        member("/result", &|v| {
            v.as_str().is_some_and(|r| RESULTS.contains(&r))
        })?;
        Ok(Self {
            text: text.to_owned(),
            json,
            mode,
        })
    }

    /// Reads and parses the `summary.json` at `path`, of at most 1 MiB.
    ///
    /// # Errors
    ///
    /// Returns [`SummaryError::Read`] when the file cannot be read, and the
    /// errors of [`Summary::parse`] otherwise.
    pub fn read(path: &Path) -> Result<Self, SummaryError> {
        let text = read_limited(path).map_err(SummaryError::Read)?;
        Self::parse(&text)
    }

    /// The validation mode of the run.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The whole summary.
    pub fn json(&self) -> &Value {
        &self.json
    }

    /// The text of the summary, as the tool wrote it.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The result of the run as the manifest of the corpus writes it: an
    /// indication with hyphens and its sub-indication, or `rejected`. It is
    /// read as `sigillum-testpki verify --dss` reads it, so the summary must
    /// name the aligned policy of ADR-0023, `aligned-1`.
    ///
    /// # Errors
    ///
    /// Returns a message when the summary gives no such result: a run that
    /// exceeded a resource limit, a document without exactly one signature,
    /// or a run with another policy.
    pub fn result(&self) -> Result<DssResult, String> {
        let text_of = |pointer: &str| {
            self.json
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_default()
        };
        read_summary(
            &self.text,
            self.mode,
            text_of("/validation-time"),
            text_of("/oracle/dss-version"),
        )
    }
}

#[cfg(test)]
mod tests;
