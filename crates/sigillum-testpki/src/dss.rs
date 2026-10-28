//! The DSS checks of `sigillum-testpki verify --dss`.
//!
//! ADR-0014 of the sigillum documentation has DSS check every PKI
//! artefact and every signed document of the corpus against the result
//! that its manifest entry expects, through the validation modes of
//! `tools/dss-oracle` (ADR-0013). The inputs of each mode and the way its
//! `summary.json` is read are described in `testdata/README.md`, under
//! "Verification with DSS".

use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;

use crate::manifest::{Artefact, Divergence, DssResult, Indication, Kind, Manifest};
use crate::openssl::{Output, RunError, Runner, covered_certificate};
use crate::signed::JavaOracle;

/// The time limit of a validation, in seconds, given to `tools/dss-oracle`
/// with `--timeout`, as its own continuous integration gives it.
pub const VALIDATION_TIMEOUT: &str = "120";

/// How long one run of `tools/dss-oracle` may take: the time limit of a
/// validation, with a minute more for the JVM to start and to write its
/// reports.
pub const TIMEOUT: Duration = Duration::from_secs(180);

/// The options of the JVM, which pin the heap limit and the garbage
/// collector, as the continuous integration of `tools/dss-oracle` does:
/// a run near a resource limit of the tool then has the same outcome on
/// every host with the same JVM (see "Resource limits" in its README).
pub const JVM_OPTIONS: [&str; 2] = ["-Xmx512m", "-XX:+UseSerialGC"];

/// Something that runs `tools/dss-oracle` with the given arguments.
///
/// [`JavaOracle`] runs the real tool. Tests substitute a closure. The
/// checks run several validations at once, so it must be [`Sync`].
pub trait Oracle: Sync {
    /// Runs the tool with `args`, which start with the mode or with
    /// `--version`.
    ///
    /// # Errors
    ///
    /// Returns a [`RunError`] when the tool cannot be run to the end.
    fn run(&self, args: &[OsString]) -> Result<Output, RunError>;
}

impl<F> Oracle for F
where
    F: Fn(&[OsString]) -> Result<Output, RunError> + Sync,
{
    fn run(&self, args: &[OsString]) -> Result<Output, RunError> {
        self(args)
    }
}

/// The arguments of the Java launcher that runs the JAR of `oracle` with
/// `args`, after [`JVM_OPTIONS`].
pub fn launcher_arguments(oracle: &JavaOracle, args: &[OsString]) -> Vec<OsString> {
    let mut argv: Vec<OsString> = JVM_OPTIONS.iter().map(OsString::from).collect();
    argv.extend([OsString::from("-jar"), oracle.jar.as_os_str().to_owned()]);
    argv.extend(args.iter().cloned());
    argv
}

/// Runs `java <JVM_OPTIONS> -jar <jar> ...` without a shell, within the limits of
/// [`JavaOracle::program`].
impl Oracle for JavaOracle {
    fn run(&self, args: &[OsString]) -> Result<Output, RunError> {
        self.program().run(&launcher_arguments(self, args))
    }
}

/// Why the DSS checks cannot start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DssError {
    /// `tools/dss-oracle --version` cannot be run.
    Run(RunError),
    /// `tools/dss-oracle --version` exited with another code than 0.
    Failed(String),
    /// `tools/dss-oracle --version` printed something other than its
    /// version line.
    UnknownVersion(String),
    /// The DSS version of the tool differs from the one the manifest names.
    VersionMismatch {
        /// The version that the tool reports.
        found: String,
        /// The version in the manifest header.
        expected: String,
    },
}

impl fmt::Display for DssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run(error) => write!(f, "tools/dss-oracle {error}"),
            Self::Failed(stderr) => write!(f, "tools/dss-oracle --version failed: {stderr}"),
            Self::UnknownVersion(output) => write!(
                f,
                "tools/dss-oracle --version printed {output:?}, which is not the version line of tools/dss-oracle"
            ),
            Self::VersionMismatch { found, expected } => write!(
                f,
                "the manifest records the results of DSS {expected}, but tools/dss-oracle is built against DSS {found}"
            ),
        }
    }
}

impl std::error::Error for DssError {}

/// Reads the DSS version from the output of `tools/dss-oracle --version`,
/// a line of the form `dss-oracle 0.0.0 (DSS 6.5.1)`, ended by LF or CR LF.
///
/// # Errors
///
/// Returns [`DssError::UnknownVersion`] when the output is not of that
/// form.
pub fn parse_version(output: &str) -> Result<String, DssError> {
    let unknown = || DssError::UnknownVersion(output.to_owned());
    // println ends the line with LF, or with CR LF on Windows.
    let line = output
        .strip_suffix("\r\n")
        .or_else(|| output.strip_suffix('\n'))
        .unwrap_or(output);
    let rest = line.strip_prefix("dss-oracle ").ok_or_else(unknown)?;
    let (tool, rest) = rest.split_once(" (DSS ").ok_or_else(unknown)?;
    let dss = rest.strip_suffix(')').ok_or_else(unknown)?;
    if is_version(tool) && is_version(dss) {
        Ok(dss.to_owned())
    } else {
        Err(unknown())
    }
}

/// A version such as `6.5.1` or `6.6-RC1`.
fn is_version(text: &str) -> bool {
    text.starts_with(|c: char| c.is_ascii_digit())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Runs `tools/dss-oracle --version` and checks that the tool is built
/// against the DSS version `expected`. Returns that version.
///
/// # Errors
///
/// Returns a [`DssError`] when the tool cannot be run, does not print its
/// version line, or is built against another version of DSS.
pub fn check_version(oracle: &dyn Oracle, expected: &str) -> Result<String, DssError> {
    let output = oracle
        .run(&[OsString::from("--version")])
        .map_err(DssError::Run)?;
    if !output.success {
        return Err(DssError::Failed(output.stderr.trim().to_owned()));
    }
    let found = parse_version(&output.stdout)?;
    if found == expected {
        Ok(found)
    } else {
        Err(DssError::VersionMismatch {
            found,
            expected: expected.to_owned(),
        })
    }
}

/// The validation mode of `tools/dss-oracle` that checks an artefact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `validate-certificate`, for certificates, CRLs and OCSP responses.
    Certificate,
    /// `validate-timestamp`, for timestamp tokens.
    Timestamp,
    /// `validate-document`, for signed documents.
    Document,
}

impl Mode {
    /// The name of the mode on the command line and in `summary.json`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Certificate => "validate-certificate",
            Self::Timestamp => "validate-timestamp",
            Self::Document => "validate-document",
        }
    }
}

/// The DSS check of one artefact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The identifier of the artefact.
    pub id: String,
    /// The result that the manifest expects.
    pub expected: DssResult,
    /// The recorded divergence of the artefact, from its `dss-divergence`
    /// in the manifest, whose result DSS must give in place of the expected
    /// one.
    pub divergence: Option<Divergence>,
    /// The result that DSS gave, or why the check could not run.
    pub actual: Result<DssResult, String>,
    /// The run that decided the result and its summary, empty when no run
    /// took place.
    pub detail: String,
}

impl Finding {
    /// Reports whether DSS gave the expected result, or the result of the
    /// recorded divergence.
    pub fn matches(&self) -> bool {
        match &self.divergence {
            Some(divergence) => self.actual.as_ref() == Ok(&divergence.result()),
            None => self.actual.as_ref() == Ok(&self.expected),
        }
    }

    /// The result that DSS must give, in words.
    pub fn expectation(&self) -> String {
        match &self.divergence {
            Some(divergence) => format!(
                "{}, the result of DSS that {} records; the manifest predicts {}",
                divergence.result(),
                divergence.entry,
                self.expected
            ),
            None => self.expected.to_string(),
        }
    }
}

/// The DSS checks of a whole manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The DSS version that ran the checks.
    pub version: String,
    /// One finding per artefact, in the order of the manifest.
    pub findings: Vec<Finding>,
}

impl Report {
    /// The findings whose result differs from the expected one.
    pub fn mismatches(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| !finding.matches())
    }

    /// The findings with a recorded divergence.
    pub fn divergent(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.divergence.is_some())
    }
}

/// Checks the DSS version, then every artefact of `manifest`, whose files
/// are under `corpus`, running up to `jobs` validations at once. Each
/// validation writes its reports to a directory of its own under
/// `scratch`, which must exist.
///
/// # Errors
///
/// Returns the errors of [`check_version`]. A failed check of an artefact
/// is a [`Finding`], not an error.
pub fn verify(
    manifest: &Manifest,
    corpus: &Path,
    scratch: &Path,
    oracle: &dyn Oracle,
    jobs: NonZeroUsize,
) -> Result<Report, DssError> {
    let version = check_version(oracle, &manifest.header.dss_version)?;
    let checker = Checker {
        inputs: Inputs::new(manifest, corpus),
        scratch: std::path::absolute(scratch).unwrap_or_else(|_| scratch.to_path_buf()),
        oracle,
    };
    let artefacts = &manifest.artefacts;
    let findings = Mutex::new(vec![None; artefacts.len()]);
    let next = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..jobs.get().min(artefacts.len()) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(artefact) = artefacts.get(index) else {
                        break;
                    };
                    let finding = checker.check(index, artefact);
                    let mut findings = findings
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    findings[index] = Some(finding);
                }
            });
        }
    });
    let findings = findings
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Ok(Report {
        version,
        findings: findings.into_iter().flatten().collect(),
    })
}

/// The largest `summary.json` that a check reads, in bytes. A summary is a
/// few kilobytes long.
pub const MAX_SUMMARY_LEN: u64 = 1024 * 1024;

/// The most lines of a summary that a finding keeps.
const EXCERPT_LINES: usize = 40;

/// The mode and the arguments of `tools/dss-oracle`, without `--out`, with
/// which `verify --dss` validates `artefact` of `manifest`, whose files are
/// under `corpus`: the inputs that `testdata/README.md` describes under
/// "Verification with DSS", the validation time of the manifest and the
/// time limit [`VALIDATION_TIMEOUT`]. Returns `None` for a kind that DSS
/// does not process.
///
/// # Errors
///
/// Returns a message when the manifest lacks a link or a note that the
/// validation needs.
pub fn validation_arguments(
    manifest: &Manifest,
    corpus: &Path,
    artefact: &Artefact,
) -> Result<Option<(Mode, Vec<OsString>)>, String> {
    Inputs::new(manifest, corpus).arguments(artefact)
}

/// The checks of one manifest.
struct Checker<'a> {
    inputs: Inputs<'a>,
    scratch: PathBuf,
    oracle: &'a dyn Oracle,
}

impl Checker<'_> {
    /// Checks one artefact against its expected result, with the output
    /// directory numbered `index`.
    fn check(&self, index: usize, artefact: &Artefact) -> Finding {
        let (actual, detail) = match self.inputs.arguments(artefact) {
            Ok(None) => (Ok(DssResult::NotApplicable), String::new()),
            Ok(Some((mode, args))) => self.validate(index, mode, args),
            Err(reason) => (Err(reason), String::new()),
        };
        Finding {
            id: artefact.id.clone(),
            expected: artefact.expected_dss.clone(),
            divergence: artefact.dss_divergence.clone(),
            actual,
            detail,
        }
    }

    /// Runs the validation `args` in `mode`, and reads its summary.
    fn validate(
        &self,
        index: usize,
        mode: Mode,
        mut args: Vec<OsString>,
    ) -> (Result<DssResult, String>, String) {
        let out = self.scratch.join(format!("dss-{index}"));
        args.extend([OsString::from("--out"), out.clone().into_os_string()]);
        let mut detail = format!(
            "tools/dss-oracle {}",
            args.iter()
                .map(|arg| arg.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        );
        let output = match self.oracle.run(&args) {
            Ok(output) => output,
            Err(error) => return (Err(format!("tools/dss-oracle {error}")), detail),
        };
        if !output.success {
            return (
                Err(format!("tools/dss-oracle failed: {}", output.stderr.trim())),
                detail,
            );
        }
        let text = match read_limited(&out.join("summary.json")) {
            Ok(text) => text,
            Err(reason) => return (Err(reason), detail),
        };
        for line in text.lines().take(EXCERPT_LINES) {
            detail.push('\n');
            detail.push_str(line);
        }
        let inputs = &self.inputs;
        let result = read_summary(
            &text,
            mode,
            &inputs.time,
            &inputs.manifest.header.dss_version,
        );
        (result, detail)
    }
}

/// The inputs of the validations of one manifest.
struct Inputs<'a> {
    manifest: &'a Manifest,
    corpus: PathBuf,
    time: String,
}

impl<'a> Inputs<'a> {
    /// The inputs of `manifest`, whose files are under `corpus`.
    fn new(manifest: &'a Manifest, corpus: &Path) -> Self {
        Self {
            manifest,
            corpus: std::path::absolute(corpus).unwrap_or_else(|_| corpus.to_path_buf()),
            time: manifest
                .header
                .validation_time
                .format(&Rfc3339)
                .unwrap_or_default(),
        }
    }

    /// The mode and arguments, without `--out`, that validate `artefact`,
    /// or `None` for a kind that DSS does not process.
    fn arguments(&self, artefact: &Artefact) -> Result<Option<(Mode, Vec<OsString>)>, String> {
        let run = match artefact.kind {
            Kind::PrivateKey | Kind::Document => return Ok(None),
            Kind::Certificate => {
                let revocation = self.all(&artefact.links.revocation)?;
                (
                    Mode::Certificate,
                    self.certificate_arguments(artefact, &revocation)?,
                )
            }
            Kind::Crl | Kind::OcspResponse => {
                let covered = artefact
                    .notes
                    .as_deref()
                    .and_then(covered_certificate)
                    .ok_or("the notes name no covered certificate")?;
                let covered = self.find(covered)?;
                (
                    Mode::Certificate,
                    self.certificate_arguments(covered, &[artefact])?,
                )
            }
            Kind::TimestampToken => (Mode::Timestamp, self.timestamp_arguments(artefact)?),
            Kind::SignedDocument => (Mode::Document, self.document_arguments(artefact)?),
        };
        Ok(Some(run))
    }

    /// `validate-certificate` for `certificate`, given `revocation` for it:
    /// the certificates of its chain but the trust anchor, the trust
    /// anchor, `revocation`, then the revocation data that the
    /// certificates between it and the trust anchor link.
    fn certificate_arguments(
        &self,
        certificate: &Artefact,
        revocation: &[&Artefact],
    ) -> Result<Vec<OsString>, String> {
        let chain = self.all(&certificate.links.chain)?;
        let (anchor, between) = match chain.split_last() {
            Some((anchor, between)) => (*anchor, between),
            None => (certificate, &[][..]),
        };
        let mut data = revocation.to_vec();
        for ca in between {
            data.extend(self.all(&ca.links.revocation)?);
        }
        let mut args = vec![Mode::Certificate.name().into()];
        self.push("--certificate", certificate, &mut args);
        for ca in between {
            self.push("--certificate", ca, &mut args);
        }
        self.push("--trust-anchor", anchor, &mut args);
        self.push_revocation(&data, &mut args)?;
        self.push_time(&mut args);
        Ok(args)
    }

    /// `validate-timestamp` for `token`, with the data it covers, the
    /// chain of its signer, and the CRLs that the certificates of that
    /// chain but the trust anchor link, with which the manifest predicts
    /// the results of the tokens.
    fn timestamp_arguments(&self, token: &Artefact) -> Result<Vec<OsString>, String> {
        let chain = self.all(&token.links.chain)?;
        let (anchor, between) = chain
            .split_last()
            .ok_or("the token links no chain of its signer")?;
        let mut args = vec![Mode::Timestamp.name().into()];
        self.push("--timestamp", token, &mut args);
        if let Some(content) = &token.links.content {
            self.push("--data", self.find(content)?, &mut args);
        }
        let mut data = Vec::new();
        for certificate in between {
            self.push("--certificate", certificate, &mut args);
            data.extend(
                self.all(&certificate.links.revocation)?
                    .into_iter()
                    .filter(|item| item.kind == Kind::Crl),
            );
        }
        self.push("--trust-anchor", anchor, &mut args);
        self.push_revocation(&data, &mut args)?;
        self.push_time(&mut args);
        Ok(args)
    }

    /// `validate-document` for `document`, with the linked files only: its
    /// content, the certificates of `chain` and `timestamp-chain` with the
    /// last of `chain` as trust anchor, and the revocation data of
    /// `revocation`.
    fn document_arguments(&self, document: &Artefact) -> Result<Vec<OsString>, String> {
        let chain = self.all(&document.links.chain)?;
        let anchor = *chain
            .last()
            .ok_or("the document links no chain of its signer")?;
        let mut args = vec![Mode::Document.name().into()];
        self.push("--document", document, &mut args);
        if let Some(content) = &document.links.content {
            self.push("--detached", self.find(content)?, &mut args);
        }
        let timestamp_chain = self.all(&document.links.timestamp_chain)?;
        let mut certificates: Vec<&Artefact> = Vec::new();
        for certificate in chain.iter().chain(&timestamp_chain) {
            if certificate.id != anchor.id && !certificates.iter().any(|c| c.id == certificate.id) {
                certificates.push(certificate);
            }
        }
        for certificate in certificates {
            self.push("--certificate", certificate, &mut args);
        }
        self.push("--trust-anchor", anchor, &mut args);
        self.push_revocation(&self.all(&document.links.revocation)?, &mut args)?;
        self.push_time(&mut args);
        Ok(args)
    }

    fn find(&self, id: &str) -> Result<&'a Artefact, String> {
        self.manifest
            .artefacts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| format!("{id} is not in the manifest"))
    }

    fn all(&self, ids: &[String]) -> Result<Vec<&'a Artefact>, String> {
        ids.iter().map(|id| self.find(id)).collect()
    }

    /// Adds `option` with the absolute path of `artefact`.
    fn push(&self, option: &str, artefact: &Artefact, args: &mut Vec<OsString>) {
        args.push(option.into());
        args.push(self.corpus.join(&artefact.path).into_os_string());
    }

    /// Adds each CRL with `--crl` and each OCSP response with `--ocsp`, once.
    fn push_revocation(&self, data: &[&Artefact], args: &mut Vec<OsString>) -> Result<(), String> {
        let mut seen: Vec<&str> = Vec::new();
        for item in data {
            if seen.contains(&item.id.as_str()) {
                continue;
            }
            seen.push(&item.id);
            let option = match item.kind {
                Kind::Crl => "--crl",
                Kind::OcspResponse => "--ocsp",
                _ => return Err(format!("{} is not revocation data", item.id)),
            };
            self.push(option, item, args);
        }
        Ok(())
    }

    /// Adds the validation time and the time limit of the validation.
    fn push_time(&self, args: &mut Vec<OsString>) {
        args.extend([
            OsString::from("--validation-time"),
            (&self.time).into(),
            "--timeout".into(),
            VALIDATION_TIMEOUT.into(),
        ]);
    }
}

/// Reads a file up to [`MAX_SUMMARY_LEN`] bytes, as UTF-8.
///
/// # Errors
///
/// Returns a message that names the file when it cannot be read, is not
/// UTF-8 or is larger than the limit.
pub fn read_limited(path: &Path) -> Result<String, String> {
    let name = path.display();
    let file = File::open(path).map_err(|e| format!("{name}: {e}"))?;
    let mut text = String::new();
    file.take(MAX_SUMMARY_LEN + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{name}: {e}"))?;
    if text.len() as u64 > MAX_SUMMARY_LEN {
        return Err(format!("{name} is larger than {MAX_SUMMARY_LEN} bytes"));
    }
    Ok(text)
}

/// The format version of `summary.json` that this module reads.
const SUMMARY_FORMAT_VERSION: u64 = 3;

/// The validation policy of the checks, the aligned policy of ADR-0023 in
/// its version 1.
const POLICY: &str = "aligned-1";

/// Reads the result of a run in `mode` from its `summary.json`, after
/// checking that the summary describes that run: its format version, the
/// DSS version `dss`, the mode, the validation time `time` and the aligned
/// policy. DSS writes indications with underscores, the manifest with
/// hyphens.
///
/// # Errors
///
/// Returns a message when the text is not a summary of that run, or gives
/// no result: a run that exceeded a resource limit, or a document without
/// exactly one signature.
pub fn read_summary(text: &str, mode: Mode, time: &str, dss: &str) -> Result<DssResult, String> {
    let summary: Value =
        serde_json::from_str(text).map_err(|e| format!("summary.json is not valid: {e}"))?;
    let field = |name: &str| summary.get(name).unwrap_or(&Value::Null);
    let text_of = |name: &str| field(name).as_str().unwrap_or_default().to_owned();
    if field("format-version").as_u64() != Some(SUMMARY_FORMAT_VERSION) {
        return Err(format!(
            "summary.json has the format version {}, not {SUMMARY_FORMAT_VERSION}",
            field("format-version")
        ));
    }
    let found = field("oracle")
        .get("dss-version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if found != dss {
        return Err(format!(
            "summary.json names DSS {found}, but the manifest records the results of DSS {dss}"
        ));
    }
    for (name, expected) in [
        ("mode", mode.name()),
        ("validation-time", time),
        ("policy", POLICY),
    ] {
        if field(name).as_str() != Some(expected) {
            return Err(format!(
                "summary.json gives {name} {}, not {expected}",
                field(name)
            ));
        }
    }
    match field("result").as_str() {
        Some("rejected") => Ok(DssResult::Rejected),
        Some("validated") => {
            let indication = match field("indication") {
                Value::String(indication) => read_indication(indication)?,
                Value::Null => {
                    let signatures = field("details")
                        .get("signatures")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len);
                    return Err(format!(
                        "DSS gives no single indication: the document has {signatures} signatures"
                    ));
                }
                other => return Err(format!("summary.json gives the indication {other}")),
            };
            let sub_indication = match field("sub-indication") {
                Value::Null => None,
                Value::String(sub) => Some(sub.clone()),
                other => return Err(format!("summary.json gives the sub-indication {other}")),
            };
            Ok(DssResult::Indication {
                indication,
                sub_indication,
            })
        }
        Some("resource-limit") => Err(format!(
            "DSS exceeded its {} limit: {}",
            text_of("limit"),
            text_of("message")
        )),
        _ => Err(format!("summary.json gives the result {}", field("result"))),
    }
}

/// The indication that DSS names `name`, with underscores.
fn read_indication(name: &str) -> Result<Indication, String> {
    [
        Indication::TotalPassed,
        Indication::TotalFailed,
        Indication::Indeterminate,
        Indication::Passed,
        Indication::Failed,
    ]
    .into_iter()
    .find(|indication| indication.as_str().replace('-', "_") == name)
    .ok_or_else(|| format!("DSS gives the indication {name}, which the manifest does not know"))
}

#[cfg(test)]
mod tests;
