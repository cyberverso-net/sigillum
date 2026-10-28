//! The runs of the validation modes of `tools/dss-oracle`.

use std::ffi::OsString;
use std::fmt;
use std::num::NonZeroUsize;
use std::path::Path;

use sigillum_testpki::dss::{Mode, Oracle, VALIDATION_TIMEOUT, validation_arguments};
use sigillum_testpki::manifest::{Artefact, DssResult, Manifest};
use sigillum_testpki::openssl::RunError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::compare::identical;
use crate::summary::{Summary, SummaryError};

/// One run of a validation mode of `tools/dss-oracle`: the mode and its
/// arguments, without `--out`.
///
/// Every run has the fixed validation time it is built with, the time
/// limit of the validation that `sigillum-testpki verify --dss` gives,
/// 120 seconds, and the aligned validation policy of ADR-0023, which the
/// tool uses when no `--policy` is given. DSS sees only the files named:
/// trust anchors, certificates, CRLs and OCSP responses. Paths are made
/// absolute against the current directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validation {
    mode: Mode,
    args: Vec<OsString>,
}

impl Validation {
    /// A run of `validate-certificate` for `certificate` at
    /// `validation_time`. The certificates added with
    /// [`Validation::with_certificate`] are its chain.
    pub fn certificate(
        certificate: impl AsRef<Path>,
        validation_time: OffsetDateTime,
    ) -> Result<Self, TimeError> {
        Self::start(Mode::Certificate)
            .with("--certificate", certificate.as_ref())
            .at(validation_time)
    }

    /// A run of `validate-timestamp` for the RFC 3161 timestamp token
    /// `token` at `validation_time`, with the data that it covers when
    /// `data` is given.
    pub fn timestamp(
        token: impl AsRef<Path>,
        data: Option<&Path>,
        validation_time: OffsetDateTime,
    ) -> Result<Self, TimeError> {
        let validation = Self::start(Mode::Timestamp).with("--timestamp", token.as_ref());
        match data {
            Some(data) => validation.with("--data", data),
            None => validation,
        }
        .at(validation_time)
    }

    /// A run of `validate-document` for the signed document `document` at
    /// `validation_time`, with the content of a detached signature when
    /// `detached` is given.
    pub fn document(
        document: impl AsRef<Path>,
        detached: Option<&Path>,
        validation_time: OffsetDateTime,
    ) -> Result<Self, TimeError> {
        let validation = Self::start(Mode::Document).with("--document", document.as_ref());
        match detached {
            Some(detached) => validation.with("--detached", detached),
            None => validation,
        }
        .at(validation_time)
    }

    /// A run in `mode`, without options.
    fn start(mode: Mode) -> Self {
        Self {
            mode,
            args: vec![mode.name().into()],
        }
    }

    /// Adds the validation time, in UTC and whole seconds, of the form
    /// `YYYY-MM-DDTHH:MM:SSZ` that the manifest uses, and the time limit of
    /// the validation.
    ///
    /// # Errors
    ///
    /// Returns a [`TimeError`] when the time cannot be written so.
    fn at(mut self, validation_time: OffsetDateTime) -> Result<Self, TimeError> {
        let error = || TimeError {
            time: validation_time,
        };
        let utc = validation_time
            .checked_to_offset(UtcOffset::UTC)
            .ok_or_else(error)?;
        let utc = utc.replace_nanosecond(0).map_err(|_| error())?;
        let time = utc.format(&Rfc3339).map_err(|_| error())?;
        self.args.extend([
            "--validation-time".into(),
            time.into(),
            "--timeout".into(),
            VALIDATION_TIMEOUT.into(),
        ]);
        Ok(self)
    }

    /// Adds a trust anchor.
    #[must_use]
    pub fn with_trust_anchor(self, path: impl AsRef<Path>) -> Self {
        self.with("--trust-anchor", path.as_ref())
    }

    /// Adds a certificate that DSS may use to build a chain.
    #[must_use]
    pub fn with_certificate(self, path: impl AsRef<Path>) -> Self {
        self.with("--certificate", path.as_ref())
    }

    /// Adds a CRL.
    #[must_use]
    pub fn with_crl(self, path: impl AsRef<Path>) -> Self {
        self.with("--crl", path.as_ref())
    }

    /// Adds an OCSP response, in DER.
    #[must_use]
    pub fn with_ocsp(self, path: impl AsRef<Path>) -> Self {
        self.with("--ocsp", path.as_ref())
    }

    /// Adds `option` with `path`, made absolute.
    fn with(mut self, option: &str, path: &Path) -> Self {
        let path = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf());
        self.args.push(option.into());
        self.args.push(path.into_os_string());
        self
    }

    /// The run with which `sigillum-testpki verify --dss` validates
    /// `artefact` of `manifest`, whose files are under `corpus`, as
    /// `testdata/README.md` describes under "Verification with DSS", or
    /// `None` for a kind that DSS does not process.
    ///
    /// # Errors
    ///
    /// Returns a message when the manifest lacks a link or a note that the
    /// run needs.
    pub fn for_artefact(
        manifest: &Manifest,
        corpus: &Path,
        artefact: &Artefact,
    ) -> Result<Option<Self>, String> {
        let arguments = validation_arguments(manifest, corpus, artefact)?;
        Ok(arguments.map(|(mode, args)| Self { mode, args }))
    }

    /// The validation mode.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The arguments of the tool, from the name of the mode, without
    /// `--out`.
    pub fn arguments(&self) -> &[OsString] {
        &self.args
    }
}

/// A validation time that cannot be written in the form of the manifest,
/// `YYYY-MM-DDTHH:MM:SSZ`, such as a time before the year 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeError {
    /// The time.
    pub time: OffsetDateTime,
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the validation time {} cannot be written as YYYY-MM-DDTHH:MM:SSZ",
            self.time
        )
    }
}

impl std::error::Error for TimeError {}

/// Why a run gave no summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleError {
    /// The manifest lacks what the run of an artefact needs, or expects a
    /// result of DSS for a kind of artefact that DSS does not process.
    Inputs(String),
    /// The tool cannot be run to the end.
    Run(RunError),
    /// The tool exited with another code than 0; its error output.
    Failed(String),
    /// The tool wrote no summary that this crate reads.
    Summary(SummaryError),
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inputs(reason) => write!(f, "the run cannot be built: {reason}"),
            Self::Run(error) => write!(f, "tools/dss-oracle {error}"),
            Self::Failed(stderr) => write!(f, "tools/dss-oracle failed: {stderr}"),
            Self::Summary(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for OracleError {}

/// Runs `validation` with `oracle`, which writes its reports to `out`, a
/// directory that must not exist or must be empty, and reads the summary.
///
/// # Errors
///
/// Returns an [`OracleError`] when the tool cannot be run, fails, or
/// writes no summary that this crate reads. A result of DSS, a rejection
/// included, is a summary, not an error.
pub fn run(
    oracle: &dyn Oracle,
    validation: &Validation,
    out: &Path,
) -> Result<Summary, OracleError> {
    let mut args = validation.args.clone();
    args.extend([OsString::from("--out"), out.as_os_str().to_owned()]);
    let output = oracle.run(&args).map_err(OracleError::Run)?;
    if !output.success {
        return Err(OracleError::Failed(output.stderr.trim().to_owned()));
    }
    Summary::read(&out.join("summary.json")).map_err(OracleError::Summary)
}

/// The run of one artefact of the corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct CorpusResult {
    /// The identifier of the artefact.
    pub id: String,
    /// Its summary, or why the run gave none.
    pub summary: Result<Summary, OracleError>,
}

/// Runs every artefact of `manifest` that DSS processes, whose files are
/// under `corpus`, with the run of [`Validation::for_artefact`]. An
/// artefact of another kind gives a result only when the manifest expects
/// a result of DSS for it, an [`OracleError::Inputs`]. Runs go up to
/// `jobs` at once. Each run writes its reports to a directory of its own
/// under `scratch`, which must exist: the directory named by the position
/// of the artefact in the manifest, counted from 0. The results keep the
/// order of the manifest.
pub fn validate_corpus(
    oracle: &dyn Oracle,
    manifest: &Manifest,
    corpus: &Path,
    scratch: &Path,
    jobs: NonZeroUsize,
) -> Vec<CorpusResult> {
    let runs: Vec<(usize, &Artefact, Result<Validation, String>)> = manifest
        .artefacts
        .iter()
        .enumerate()
        .filter_map(|(index, artefact)| {
            let validation = match Validation::for_artefact(manifest, corpus, artefact) {
                Ok(Some(validation)) => Ok(validation),
                Err(reason) => Err(reason),
                // The manifest does not tie the expected result to the
                // kind, so a kind that DSS does not process may still
                // expect a result of DSS, which is reported.
                Ok(None) if artefact.expected_dss != DssResult::NotApplicable => Err(format!(
                    "DSS does not process a {}, but the manifest expects {}",
                    artefact.kind.as_str(),
                    artefact.expected_dss
                )),
                Ok(None) => return None,
            };
            Some((index, artefact, validation))
        })
        .collect();
    let results = Mutex::new(vec![None; runs.len()]);
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs.get().min(runs.len()) {
            scope.spawn(|| {
                loop {
                    let position = next.fetch_add(1, Ordering::Relaxed);
                    let Some((index, artefact, validation)) = runs.get(position) else {
                        break;
                    };
                    let summary = match validation {
                        Ok(validation) => run(oracle, validation, &scratch.join(index.to_string())),
                        Err(reason) => Err(OracleError::Inputs(reason.clone())),
                    };
                    let result = CorpusResult {
                        id: artefact.id.clone(),
                        summary,
                    };
                    let mut results = results.lock().unwrap_or_else(PoisonError::into_inner);
                    if let Some(slot) = results.get_mut(position) {
                        *slot = Some(result);
                    }
                }
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
        .into_iter()
        .flatten()
        .collect()
}

/// Compares two runs of the corpus, artefact by artefact, and describes
/// each artefact whose summaries are not the same, byte for byte, or that
/// has no summary in either run. Runs that list other artefacts are
/// described as such. Two runs with the same inputs must give the same
/// summaries.
pub fn differing_runs(first: &[CorpusResult], second: &[CorpusResult]) -> Vec<String> {
    if first.len() != second.len() {
        return vec![format!(
            "the first run has {} artefacts and the second {}",
            first.len(),
            second.len()
        )];
    }
    let mut report = Vec::new();
    for (one, two) in first.iter().zip(second) {
        let id = &one.id;
        if two.id != *id {
            report.push(format!("{id}: the second run has {} in its place", two.id));
            continue;
        }
        let (one, two) = match (&one.summary, &two.summary) {
            (Err(error), _) => {
                report.push(format!("{id}: the first run gave no summary: {error}"));
                continue;
            }
            (_, Err(error)) => {
                report.push(format!("{id}: the second run gave no summary: {error}"));
                continue;
            }
            (Ok(one), Ok(two)) => (one, two),
        };
        if one.text() == two.text() {
            continue;
        }
        let mismatch = identical(one.json(), two.json());
        report.push(if mismatch.is_empty() {
            format!("{id}: the two runs give the same members in other bytes")
        } else {
            format!("{id}: the two runs differ; {mismatch}")
        });
    }
    report
}

#[cfg(test)]
mod tests;
