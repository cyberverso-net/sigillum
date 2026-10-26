//! The OpenSSL checks of `sigillum-testpki verify --openssl`.
//!
//! ADR-0014 of the sigillum documentation has OpenSSL check every PKI
//! artefact of the corpus against the result that its manifest entry
//! expects. The commands and the way their output is read are described
//! in `testdata/README.md`, under "Verification with OpenSSL".

pub mod process;

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use der::pem::LineEnding;
use time::{OffsetDateTime, PrimitiveDateTime};

use crate::manifest::{Artefact, Kind, Manifest, OpensslResult};

/// What one run of `openssl` wrote, and whether it exited with 0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    /// Whether the program exited with 0.
    pub success: bool,
    /// Standard output, with invalid UTF-8 replaced.
    pub stdout: String,
    /// Standard error, with invalid UTF-8 replaced.
    pub stderr: String,
}

/// Why `openssl` could not be run to the end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunError {
    /// The program could not be started.
    Spawn(String),
    /// Its output could not be read, or it could not be waited for.
    Io(String),
    /// It wrote more than this many bytes to one of its outputs, and was
    /// stopped.
    OutputTooLarge(usize),
    /// It ran longer than this, and was stopped.
    TimedOut(Duration),
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(message) => write!(f, "cannot be started: {message}"),
            Self::Io(message) => write!(f, "cannot be run: {message}"),
            Self::OutputTooLarge(limit) => {
                write!(
                    f,
                    "wrote more than {limit} bytes to an output and was stopped"
                )
            }
            Self::TimedOut(limit) => {
                write!(
                    f,
                    "ran longer than {} s and was stopped",
                    limit.as_secs_f64()
                )
            }
        }
    }
}

impl std::error::Error for RunError {}

/// Something that runs `openssl` with the given arguments.
///
/// [`process::Program`] runs the real program. Tests substitute a closure.
pub trait Runner {
    /// Runs `openssl` with `args`, which start with the command name.
    ///
    /// # Errors
    ///
    /// Returns a [`RunError`] when the program cannot be run to the end.
    fn run(&self, args: &[OsString]) -> Result<Output, RunError>;
}

impl<F> Runner for F
where
    F: Fn(&[OsString]) -> Result<Output, RunError>,
{
    fn run(&self, args: &[OsString]) -> Result<Output, RunError> {
        self(args)
    }
}

/// Why the OpenSSL checks cannot start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpensslError {
    /// `openssl version` cannot be run.
    Run(RunError),
    /// `openssl version` printed something other than an OpenSSL version.
    UnknownVersion(String),
    /// The program and the library it uses have different versions.
    LibraryMismatch {
        /// The version of the program.
        program: String,
        /// The version of the library.
        library: String,
    },
    /// The version found differs from the one the manifest names.
    VersionMismatch {
        /// The version that `openssl version` reports.
        found: String,
        /// The version in the manifest header.
        expected: String,
    },
}

impl fmt::Display for OpensslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Run(error) => write!(f, "openssl {error}"),
            Self::UnknownVersion(output) => write!(
                f,
                "openssl version printed {output:?}, which is not the version of an OpenSSL release"
            ),
            Self::LibraryMismatch { program, library } => write!(
                f,
                "openssl is OpenSSL {program} but uses the library of OpenSSL {library}"
            ),
            Self::VersionMismatch { found, expected } => write!(
                f,
                "the manifest records the results of OpenSSL {expected}, but openssl is OpenSSL {found}; run the checks with OpenSSL {expected}, for example with --openssl-program"
            ),
        }
    }
}

impl std::error::Error for OpensslError {}

/// Reads the version of OpenSSL from the output of `openssl version`, for
/// example `3.5.9` from `OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL
/// 3.5.9 29 Sep 2026)`.
///
/// The output must be one line that starts with `OpenSSL` and the
/// version. A version starts with a digit and holds only ASCII letters,
/// digits, `.` and `-`. The line may name the library: the `openssl
/// version` of OpenSSL 3.0.13 and 3.5.9 always does, and that of OpenSSL
/// 1.1.1w did not when the two agree. When it names the library, the
/// library must be OpenSSL of the same version.
///
/// # Errors
///
/// Returns [`OpensslError::UnknownVersion`] when the output does not name
/// an OpenSSL version, and [`OpensslError::LibraryMismatch`] when the
/// library has another version than the program.
pub fn parse_version(output: &str) -> Result<String, OpensslError> {
    let unknown = || OpensslError::UnknownVersion(output.to_owned());
    let line = output
        .strip_suffix('\n')
        .map_or(output, |line| line.strip_suffix('\r').unwrap_or(line));
    if line.contains(['\n', '\r']) {
        return Err(unknown());
    }
    let rest = line.strip_prefix("OpenSSL ").ok_or_else(unknown)?;
    let (program, rest) = version_token(rest).ok_or_else(unknown)?;
    if let Some(start) = rest.find("(Library: ") {
        let library = rest[start + "(Library: ".len()..]
            .strip_prefix("OpenSSL ")
            .filter(|_| rest.ends_with(')'))
            .ok_or_else(unknown)?;
        let (library, _) = version_token(library).ok_or_else(unknown)?;
        if library != program {
            return Err(OpensslError::LibraryMismatch {
                program: program.to_owned(),
                library: library.to_owned(),
            });
        }
    }
    Ok(program.to_owned())
}

/// Splits a version, up to the next space, from the start of `text`.
fn version_token(text: &str) -> Option<(&str, &str)> {
    let (token, rest) = text.split_at(text.find(' ').unwrap_or(text.len()));
    is_version(token).then_some((token, rest))
}

/// Reports whether `text` has the form of an OpenSSL version: an ASCII
/// digit, then ASCII letters, digits, `.` and `-`.
pub fn is_version(text: &str) -> bool {
    text.starts_with(|c: char| c.is_ascii_digit())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Runs `openssl version` and checks that it reports `expected`.
///
/// # Errors
///
/// Returns the errors of [`parse_version`], [`OpensslError::Run`] when the
/// program cannot be run or fails, and [`OpensslError::VersionMismatch`]
/// when the version differs.
pub fn check_version(runner: &dyn Runner, expected: &str) -> Result<String, OpensslError> {
    let output = runner
        .run(&[OsString::from("version")])
        .map_err(OpensslError::Run)?;
    if !output.success {
        return Err(OpensslError::Run(RunError::Io(format!(
            "openssl version failed: {}",
            excerpt(&output.stderr)
        ))));
    }
    let found = parse_version(&output.stdout)?;
    if found == expected {
        Ok(found)
    } else {
        Err(OpensslError::VersionMismatch {
            found,
            expected: expected.to_owned(),
        })
    }
}

/// The identifier of the covered certificate that the notes of a CRL or
/// OCSP response entry name in their first sentence, of the form
/// `Covered certificate: pki/<name>.`
pub fn covered_certificate(notes: &str) -> Option<&str> {
    let rest = notes.strip_prefix("Covered certificate: ")?;
    let id = match rest.split_once(". ") {
        Some((id, _)) => id,
        None => rest.strip_suffix('.')?,
    };
    (!id.is_empty() && !id.contains(char::is_whitespace)).then_some(id)
}

/// The `thisUpdate` and `nextUpdate` that `openssl crl -lastupdate
/// -nextupdate` prints, each on a line of its own, such as
/// `lastUpdate=Jan 14 10:00:00 2030 GMT`. `None` when either is missing,
/// repeated or not a time, as for `nextUpdate=NONE`.
pub fn crl_times(stdout: &str) -> Option<(OffsetDateTime, OffsetDateTime)> {
    let field = |name: &str| {
        let mut values = stdout
            .lines()
            .filter_map(|line| line.strip_prefix(name)?.strip_prefix('='));
        let value = values.next()?;
        if values.next().is_some() {
            return None;
        }
        let format = time::format_description::parse_borrowed::<2>(OPENSSL_TIME).ok()?;
        PrimitiveDateTime::parse(value, &format)
            .ok()
            .map(PrimitiveDateTime::assume_utc)
    };
    Some((field("lastUpdate")?, field("nextUpdate")?))
}

/// The form in which OpenSSL prints a time, as `ASN1_TIME_print` does:
/// `Jan 14 10:00:00 2030 GMT`, with the day padded with a space.
const OPENSSL_TIME: &str =
    "[month repr:short] [day padding:space] [hour]:[minute]:[second] [year] GMT";

/// The certificate statuses of RFC 6960, section 2.2, as `openssl ocsp`
/// prints them.
const STATUSES: [&str; 3] = ["good", "revoked", "unknown"];

/// The status that `openssl ocsp` reports for the certificate given as
/// `cert` with `-cert`: `good`, `revoked` or `unknown`.
///
/// The status follows the line `<cert>: `, on the same line or, after the
/// warning `WARNING: Status times invalid.` and the errors that explain
/// it, on a line of its own.
pub fn ocsp_status<'a>(stdout: &'a str, cert: &str) -> Option<&'a str> {
    let prefix = format!("{cert}: ");
    let mut lines = stdout.lines();
    let first = lines.find_map(|line| line.strip_prefix(prefix.as_str()))?;
    let status = |text: &str| STATUSES.into_iter().find(|status| *status == text);
    if let Some(found) = status(first) {
        return Some(found);
    }
    if first != "WARNING: Status times invalid." {
        return None;
    }
    lines.find_map(status)
}

/// The OpenSSL check of one artefact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The identifier of the artefact.
    pub id: String,
    /// The result that the manifest expects.
    pub expected: OpensslResult,
    /// The result that OpenSSL gave, or why the check could not run.
    pub actual: Result<OpensslResult, String>,
    /// The commands that decided the result and what they printed, empty
    /// when no command ran.
    pub detail: String,
}

impl Finding {
    /// Reports whether OpenSSL gave the expected result.
    pub fn matches(&self) -> bool {
        self.actual == Ok(self.expected)
    }
}

/// The OpenSSL checks of a whole manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The OpenSSL version that ran the checks.
    pub version: String,
    /// One finding per artefact, in the order of the manifest.
    pub findings: Vec<Finding>,
}

impl Report {
    /// The findings whose result differs from the expected one.
    pub fn mismatches(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter().filter(|finding| !finding.matches())
    }
}

/// Checks the OpenSSL version, then every artefact of `manifest`, whose
/// files are under `corpus`. Bundles of certificates and CRLs are written
/// under `scratch`, which must exist.
///
/// The runner must run `openssl` in `scratch`: the artefacts are given by
/// absolute paths, and the bundles by their bare file names, such as
/// `bundle-1.pem`. `openssl ts` splits the file names of `-untrusted` at
/// commas and white space, which a bare name never holds, whatever the
/// path of the temporary directory.
///
/// # Errors
///
/// Returns the errors of [`check_version`]. A failed check of an artefact
/// is a [`Finding`], not an error.
pub fn verify(
    manifest: &Manifest,
    corpus: &Path,
    scratch: &Path,
    runner: &dyn Runner,
) -> Result<Report, OpensslError> {
    let version = check_version(runner, &manifest.header.openssl_version)?;
    let checker = Checker::new(manifest, corpus, scratch, runner);
    Ok(Report {
        version,
        findings: manifest
            .artefacts
            .iter()
            .map(|a| checker.check(a))
            .collect(),
    })
}

/// A temporary directory for the bundles of one run of the checks,
/// removed with its content when dropped.
#[derive(Debug)]
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Creates a new, empty directory under the temporary directory of the
    /// system.
    ///
    /// # Errors
    ///
    /// Returns the error of the file system when no directory can be
    /// created.
    pub fn create() -> std::io::Result<Self> {
        Self::create_in(&std::env::temp_dir())
    }

    /// Creates a new, empty directory under `base`, named by an absolute
    /// path even when `base` is relative, because OpenSSL runs in the
    /// directory of the corpus.
    ///
    /// # Errors
    ///
    /// Returns the error of the file system when no directory can be
    /// created.
    pub fn create_in(base: &Path) -> std::io::Result<Self> {
        let base = std::path::absolute(base)?;
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.subsec_nanos());
        for _ in 0..100 {
            let path = base.join(format!(
                "sigillum-testpki-openssl-{}-{nanos}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "no unused name for a temporary directory",
        ))
    }

    /// The path of the directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The largest corpus file that a bundle takes, in bytes. The artefacts
/// of the test PKI are a few kilobytes long.
const MAX_FILE_LEN: u64 = 1024 * 1024;

/// The most lines of each output of `openssl` that a finding keeps.
const EXCERPT_LINES: usize = 20;

/// The outcome of one command: whether it passed, and what it printed.
struct Step {
    passed: bool,
    detail: String,
}

/// The result of the check of one artefact, with its detail, or why the
/// check could not run.
type Checked = Result<(OpensslResult, String), String>;

/// The checks of one manifest.
struct Checker<'a> {
    manifest: &'a Manifest,
    by_id: HashMap<&'a str, &'a Artefact>,
    corpus: PathBuf,
    scratch: PathBuf,
    runner: &'a dyn Runner,
    attime: String,
    validation_time: OffsetDateTime,
    bundles: Cell<usize>,
}

impl<'a> Checker<'a> {
    fn new(manifest: &'a Manifest, corpus: &Path, scratch: &Path, runner: &'a dyn Runner) -> Self {
        Self {
            manifest,
            by_id: manifest
                .artefacts
                .iter()
                .map(|a| (a.id.as_str(), a))
                .collect(),
            corpus: std::path::absolute(corpus).unwrap_or_else(|_| corpus.to_path_buf()),
            scratch: scratch.to_path_buf(),
            runner,
            attime: manifest.header.validation_time.unix_timestamp().to_string(),
            validation_time: manifest.header.validation_time,
            bundles: Cell::new(0),
        }
    }

    /// Checks one artefact against its expected result.
    fn check(&self, artefact: &'a Artefact) -> Finding {
        let checked = match artefact.kind {
            Kind::Certificate => self
                .verify_certificate(artefact, &self.default_crls(artefact))
                .map(|step| step.result(OpensslResult::Verified)),
            Kind::PrivateKey => self.check_key(artefact),
            Kind::Crl => self.check_crl(artefact),
            Kind::OcspResponse => self.check_ocsp(artefact),
            Kind::TimestampToken => self.check_timestamp(artefact),
            Kind::Document => Ok((OpensslResult::NotApplicable, String::new())),
            Kind::SignedDocument => self.check_signed_document(artefact),
        };
        let (actual, detail) = match checked {
            Ok((result, detail)) => (Ok(result), detail),
            Err(reason) => (Err(reason), String::new()),
        };
        Finding {
            id: artefact.id.clone(),
            expected: artefact.expected_openssl,
            actual,
            detail,
        }
    }

    fn find(&self, id: &str) -> Result<&'a Artefact, String> {
        self.by_id
            .get(id)
            .copied()
            .ok_or_else(|| format!("{id} is not in the manifest"))
    }

    fn certificate(&self, id: &str) -> Result<&'a Artefact, String> {
        let artefact = self.find(id)?;
        if artefact.kind == Kind::Certificate {
            Ok(artefact)
        } else {
            Err(format!("{id} is not a certificate"))
        }
    }

    /// The certificates that the `chain` of `artefact` links, from its
    /// issuer up to the trust anchor.
    fn chain(&self, artefact: &Artefact) -> Result<Vec<&'a Artefact>, String> {
        artefact
            .links
            .chain
            .iter()
            .map(|id| self.certificate(id))
            .collect()
    }

    /// The CRLs that `certificate` links in `revocation`.
    fn crls_of(&self, certificate: &Artefact) -> Vec<&'a Artefact> {
        certificate
            .links
            .revocation
            .iter()
            .filter_map(|id| self.by_id.get(id.as_str()).copied())
            .filter(|a| a.kind == Kind::Crl)
            .collect()
    }

    /// The CRLs that the certificates of the chain of `certificate` link,
    /// in the order of the chain, each once.
    fn chain_crls(&self, certificate: &'a Artefact) -> Vec<&'a Artefact> {
        let chain = certificate
            .links
            .chain
            .iter()
            .filter_map(|id| self.by_id.get(id.as_str()).copied());
        unique(chain.flat_map(|above| self.crls_of(above)))
    }

    /// The CRLs that `certificate` links, then those of its chain, each
    /// once.
    fn default_crls(&self, certificate: &'a Artefact) -> Vec<&'a Artefact> {
        unique(
            self.crls_of(certificate)
                .into_iter()
                .chain(self.chain_crls(certificate)),
        )
    }

    /// Reads a file of the corpus, up to [`MAX_FILE_LEN`] bytes.
    fn read(&self, artefact: &Artefact) -> Result<Vec<u8>, String> {
        let name = artefact.path.display();
        let file =
            File::open(self.corpus.join(&artefact.path)).map_err(|e| format!("{name}: {e}"))?;
        let mut bytes = Vec::new();
        file.take(MAX_FILE_LEN + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("{name}: {e}"))?;
        if bytes.len() as u64 > MAX_FILE_LEN {
            return Err(format!("{name} is larger than {MAX_FILE_LEN} bytes"));
        }
        Ok(bytes)
    }

    /// The absolute path of an artefact. Being absolute, it never starts
    /// with `-`, so `openssl` cannot read it as an option.
    fn path_arg(&self, artefact: &Artefact) -> OsString {
        self.corpus.join(&artefact.path).into_os_string()
    }

    /// The path of an input file of a command, after checking that it can
    /// be read. A missing or unreadable file would make OpenSSL fail, which
    /// must not pass for a rejection, so it stops the check instead.
    fn input(&self, artefact: &Artefact) -> Result<OsString, String> {
        self.read(artefact)?;
        Ok(self.path_arg(artefact))
    }

    /// Whether the file of `artefact` is in PEM form rather than DER.
    fn is_pem(&self, artefact: &Artefact) -> Result<bool, String> {
        Ok(self.read(artefact)?.starts_with(b"-----BEGIN "))
    }

    /// The PEM form of a certificate or CRL, ending with a line ending.
    fn pem(&self, artefact: &Artefact) -> Result<String, String> {
        let bytes = self.read(artefact)?;
        let mut text = if bytes.starts_with(b"-----BEGIN ") {
            String::from_utf8(bytes)
                .map_err(|_| format!("{} is not UTF-8", artefact.path.display()))?
        } else {
            let label = if artefact.kind == Kind::Crl {
                "X509 CRL"
            } else {
                "CERTIFICATE"
            };
            der::pem::encode_string(label, LineEnding::LF, &bytes)
                .map_err(|e| format!("{}: {e}", artefact.path.display()))?
        };
        if !text.ends_with('\n') {
            text.push('\n');
        }
        Ok(text)
    }

    /// Writes the PEM forms of `members` to a new file of the scratch
    /// directory, and returns its bare file name, which holds no comma or
    /// white space. `openssl` runs in the scratch directory.
    fn bundle(&self, members: &[&Artefact]) -> Result<OsString, String> {
        let number = self.bundles.get() + 1;
        self.bundles.set(number);
        let name = format!("bundle-{number}.pem");
        let path = self.scratch.join(&name);
        let mut text = String::new();
        for member in members {
            text.push_str(&self.pem(member)?);
        }
        std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(OsString::from(name))
    }

    fn run(&self, args: &[OsString]) -> Result<Output, String> {
        self.runner
            .run(args)
            .map_err(|error| format!("{}: openssl {error}", command_line(args)))
    }

    /// The arguments of `openssl verify` for `certificate`, at the
    /// validation time, with its chain and, when there are any, `crls`
    /// and `-crl_check_all`.
    fn certificate_args(
        &self,
        certificate: &Artefact,
        crls: &[&Artefact],
    ) -> Result<Vec<OsString>, String> {
        let chain = self.chain(certificate)?;
        let (anchor, intermediates) = match chain.split_last() {
            Some((anchor, intermediates)) => (*anchor, intermediates),
            None => (certificate, &[][..]),
        };
        let mut args = os(&["verify", "-attime", &self.attime]);
        args.extend(os(&["-no-CApath", "-no-CAstore", "-CAfile"]));
        args.push(self.bundle(&[anchor])?);
        if !intermediates.is_empty() {
            args.push("-untrusted".into());
            args.push(self.bundle(intermediates)?);
        }
        if !crls.is_empty() {
            args.push("-crl_check_all".into());
            for crl in crls {
                args.push("-CRLfile".into());
                args.push(self.input(crl)?);
            }
        }
        args.push(self.input(certificate)?);
        Ok(args)
    }

    fn verify_certificate(
        &self,
        certificate: &Artefact,
        crls: &[&Artefact],
    ) -> Result<Step, String> {
        let args = self.certificate_args(certificate, crls)?;
        let output = self.run(&args)?;
        let ok = format!("{}: OK", self.path_arg(certificate).to_string_lossy());
        Ok(Step {
            passed: output.success && output.stdout.lines().any(|line| line == ok),
            detail: describe(&args, &output),
        })
    }

    fn key_args(&self, key: &Artefact) -> Result<Vec<OsString>, String> {
        let mut args = os(&["pkey"]);
        if !self.is_pem(key)? {
            args.extend(os(&["-inform", "DER"]));
        }
        args.push("-in".into());
        args.push(self.input(key)?);
        args.push("-noout".into());
        Ok(args)
    }

    fn check_key(&self, key: &Artefact) -> Checked {
        let args = self.key_args(key)?;
        let output = self.run(&args)?;
        let result = if output.success {
            OpensslResult::Parsed
        } else {
            OpensslResult::Rejected
        };
        Ok((result, describe(&args, &output)))
    }

    fn issuer_link<'b>(&self, artefact: &'b Artefact) -> Result<&'b str, String> {
        artefact
            .links
            .issuer
            .as_deref()
            .ok_or_else(|| format!("{} has no issuer link", artefact.id))
    }

    /// The arguments of `openssl crl -verify`, which checks the signature
    /// of `crl` with the key of its issuer.
    fn crl_args(&self, crl: &Artefact) -> Result<Vec<OsString>, String> {
        let issuer = self.certificate(self.issuer_link(crl)?)?;
        let mut args = os(&["crl"]);
        if !self.is_pem(crl)? {
            args.extend(os(&["-inform", "DER"]));
        }
        args.push("-in".into());
        args.push(self.input(crl)?);
        args.extend(os(&[
            "-noout",
            "-lastupdate",
            "-nextupdate",
            "-verify",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
        ]));
        args.push(self.bundle(&[issuer])?);
        Ok(args)
    }

    /// A CRL verifies when `openssl crl -verify` says `verify OK`, its
    /// `thisUpdate` is at or before the validation time and its
    /// `nextUpdate` after it, and each certificate of its issuer that is
    /// expected to verify still verifies with this CRL in place of the one
    /// it links. A CRL without `nextUpdate` is rejected. Times that cannot
    /// be read after a verified signature stop the check.
    ///
    /// RFC 5280, section 5.1.2.4, makes `thisUpdate` the issue date of the
    /// CRL, and section 5.1.2.5 makes `nextUpdate` the date by which the
    /// next CRL will be issued and requires conforming issuers to include
    /// it. The RFC fixes no boundary for a comparison with a validation
    /// time. The boundaries here are those of OpenSSL's own CRL time check
    /// with `X509_cmp_time`: a `thisUpdate` equal to the validation time is
    /// current, and a `nextUpdate` equal to it is not.
    fn check_crl(&self, crl: &'a Artefact) -> Checked {
        let args = self.crl_args(crl)?;
        let output = self.run(&args)?;
        // The vanilla build of OpenSSL 3.0.13 exits with 0 even when the
        // signature does not verify, so the message decides.
        let signed = output.success && output.stderr.lines().any(|line| line == "verify OK");
        let passed = signed
            && !output.stdout.lines().any(|line| line == "nextUpdate=NONE")
            && match crl_times(&output.stdout) {
                Some((this_update, next_update)) => {
                    this_update <= self.validation_time && self.validation_time < next_update
                }
                None => {
                    return Err(format!(
                        "{}: cannot read thisUpdate and nextUpdate from the output: {}",
                        command_line(&args),
                        excerpt(&output.stdout)
                    ));
                }
            };
        let mut detail = describe(&args, &output);
        if !passed {
            return Ok((OpensslResult::Rejected, detail));
        }
        let issuer = crl.links.issuer.as_deref();
        for certificate in self.manifest.artefacts.iter().filter(|a| {
            a.kind == Kind::Certificate
                && a.links.issuer.as_deref() == issuer
                && a.expected_openssl == OpensslResult::Verified
        }) {
            let crls = unique(std::iter::once(crl).chain(self.chain_crls(certificate)));
            let step = self.verify_certificate(certificate, &crls)?;
            detail.push_str(&step.detail);
            if !step.passed {
                return Ok((OpensslResult::Rejected, step.detail));
            }
        }
        Ok((OpensslResult::Verified, detail))
    }

    /// The arguments of `openssl ocsp` for `response`, and the certificate
    /// argument whose status it prints.
    fn ocsp_args(&self, response: &Artefact) -> Result<(Vec<OsString>, String), String> {
        let covered =
            covered_certificate(response.notes.as_deref().unwrap_or("")).ok_or_else(|| {
                format!(
                    "the notes of {} do not name the covered certificate",
                    response.id
                )
            })?;
        let covered = self.certificate(covered)?;
        let issuer = self.certificate(covered.links.issuer.as_deref().ok_or_else(|| {
            format!("the covered certificate {} has no issuer link", covered.id)
        })?)?;
        let chain = self.chain(covered)?;
        // Every certificate of the chain but the trust anchor helps to
        // build the path of the signer, so that a chain with several
        // intermediate CAs verifies.
        let (anchor, intermediates) = match chain.split_last() {
            Some((anchor, intermediates)) if !intermediates.is_empty() => {
                (*anchor, intermediates.to_vec())
            }
            Some((anchor, _)) => (*anchor, vec![issuer]),
            None => (issuer, vec![issuer]),
        };
        // The responder that the entry links, with its chain but the trust
        // anchor, for a response without the certs field, which RFC 6960,
        // section 4.2.1, makes optional.
        let responder = match self.chain(response)?.split_last() {
            Some((_, above)) if !above.is_empty() => above.to_vec(),
            _ => match response.links.issuer.as_deref() {
                Some(id) => vec![self.certificate(id)?],
                None => Vec::new(),
            },
        };
        let intermediates = unique(intermediates.into_iter().chain(responder));
        let cert = self.input(covered)?;
        let mut args = os(&["ocsp", "-respin"]);
        args.push(self.input(response)?);
        args.extend(os(&["-no_nonce", "-issuer"]));
        args.push(self.input(issuer)?);
        args.push("-cert".into());
        args.push(cert.clone());
        args.extend(os(&["-no-CApath", "-no-CAstore", "-CAfile"]));
        args.push(self.bundle(&[anchor])?);
        args.push("-verify_other".into());
        args.push(self.bundle(&intermediates)?);
        args.extend(os(&["-attime", &self.attime]));
        Ok((args, cert.to_string_lossy().into_owned()))
    }

    /// A response verifies when `openssl ocsp` exits with 0, says
    /// `Response verify OK` and gives a status for the covered certificate.
    fn check_ocsp(&self, response: &Artefact) -> Checked {
        let (args, cert) = self.ocsp_args(response)?;
        let output = self.run(&args)?;
        let verified = output
            .stderr
            .lines()
            .chain(output.stdout.lines())
            .any(|line| line == "Response verify OK");
        let passed = output.success && verified && ocsp_status(&output.stdout, &cert).is_some();
        Ok((Step {
            passed,
            detail: describe(&args, &output),
        })
        .result(OpensslResult::Verified))
    }

    /// The arguments of `openssl ts -verify` for `token`, with the data it
    /// covers. `openssl ts` has no `-CRLfile`, so the CRLs that the chain
    /// links go into the file of trusted certificates.
    fn timestamp_args(&self, token: &Artefact) -> Result<Vec<OsString>, String> {
        let signer = self.certificate(self.issuer_link(token)?)?;
        let content = self.find(
            token
                .links
                .content
                .as_deref()
                .ok_or_else(|| format!("{} has no content link", token.id))?,
        )?;
        let mut chain = self.chain(token)?;
        if chain.is_empty() {
            chain.push(signer);
        }
        // The signer is always among the untrusted certificates, even when
        // it is the trust anchor: a token has no certificates when its
        // request did not set certReq (RFC 3161, section 2.4.1), and
        // OpenSSL looks for the signer only there and in the token.
        let (anchor, rest) = match chain.split_last() {
            Some((anchor, rest)) => (*anchor, rest),
            None => (signer, &[][..]),
        };
        let untrusted = unique(std::iter::once(signer).chain(rest.iter().copied()));
        let crls = unique(chain.iter().flat_map(|c| self.crls_of(c)));
        let mut trusted = vec![anchor];
        trusted.extend(crls.iter().copied());
        let mut args = os(&["ts", "-verify", "-in"]);
        args.push(self.input(token)?);
        args.extend(os(&["-token_in", "-data"]));
        args.push(self.input(content)?);
        args.push("-CAfile".into());
        args.push(self.bundle(&trusted)?);
        args.push("-untrusted".into());
        args.push(self.bundle(&untrusted)?);
        if !crls.is_empty() {
            args.push("-crl_check_all".into());
        }
        args.extend(os(&["-attime", &self.attime]));
        Ok(args)
    }

    /// Whether the file of `artefact` is a CMS `SignedData`, as a CAdES
    /// signature is, by [`is_cms_signed_data`].
    fn is_cms_file(&self, artefact: &Artefact) -> Result<bool, String> {
        Ok(is_cms_signed_data(&self.read(artefact)?))
    }

    /// A signed document in CMS, a CAdES signature, is checked with
    /// `openssl cms -verify`. Other signed documents, such as PAdES and
    /// JAdES, are not processed by OpenSSL. A CMS signature cannot be
    /// declared `not-applicable`, so that no CAdES entry escapes the check,
    /// and another document cannot expect a result from OpenSSL.
    fn check_signed_document(&self, artefact: &Artefact) -> Checked {
        let cms = self.is_cms_file(artefact)?;
        match (cms, artefact.expected_openssl) {
            (false, OpensslResult::NotApplicable) => {
                Ok((OpensslResult::NotApplicable, String::new()))
            }
            (false, _) => Err(format!(
                "{} is not a CMS SignedData, which OpenSSL does not check",
                artefact.path.display()
            )),
            (true, OpensslResult::NotApplicable) => Err(format!(
                "{} is a CMS SignedData, which openssl cms -verify checks, so not-applicable is refused",
                artefact.path.display()
            )),
            (true, _) => {
                let args = self.cms_args(artefact)?;
                let output = self.run(&args)?;
                Ok((Step {
                    passed: output.success
                        && output
                            .stderr
                            .lines()
                            .any(|line| line == "CMS Verification successful"),
                    detail: describe(&args, &output),
                })
                .result(OpensslResult::Verified))
            }
        }
    }

    /// The arguments of `openssl cms -verify` for a CMS signature, at the
    /// validation time, with its trust anchor as the only trusted
    /// certificate, the certificates of its chain between the signer and
    /// the anchor as untrusted, and its content when it is detached. The
    /// signed content is written to a file of the scratch directory.
    /// Revocation is not checked: the signatures link OCSP responses,
    /// which `openssl cms` does not take.
    fn cms_args(&self, signature: &Artefact) -> Result<Vec<OsString>, String> {
        let chain = self.chain(signature)?;
        let (anchor, rest) = match chain.split_last() {
            Some((anchor, rest)) => (*anchor, rest),
            None => return Err(format!("{} links no chain", signature.id)),
        };
        let issuer = signature.links.issuer.as_deref();
        let intermediates: Vec<&Artefact> = rest
            .iter()
            .copied()
            .filter(|c| Some(c.id.as_str()) != issuer)
            .collect();
        let mut args = os(&["cms", "-verify", "-binary", "-inform", "DER", "-in"]);
        args.push(self.input(signature)?);
        if let Some(content) = signature.links.content.as_deref() {
            args.push("-content".into());
            args.push(self.input(self.find(content)?)?);
        }
        args.extend(os(&["-no-CApath", "-no-CAstore", "-CAfile"]));
        args.push(self.bundle(&[anchor])?);
        if !intermediates.is_empty() {
            args.push("-certfile".into());
            args.push(self.bundle(&intermediates)?);
        }
        args.extend(os(&["-attime", &self.attime, "-out", "cms-content.bin"]));
        Ok(args)
    }

    /// A token verifies when `openssl ts -verify` exits with 0 and says
    /// `Verification: OK`.
    fn check_timestamp(&self, token: &Artefact) -> Checked {
        let args = self.timestamp_args(token)?;
        let output = self.run(&args)?;
        Ok((Step {
            passed: output.success && output.stdout.lines().any(|line| line == "Verification: OK"),
            detail: describe(&args, &output),
        })
        .result(OpensslResult::Verified))
    }
}

impl Step {
    /// `passed` when the step passed, and `rejected` otherwise.
    fn result(self, passed: OpensslResult) -> (OpensslResult, String) {
        let result = if self.passed {
            passed
        } else {
            OpensslResult::Rejected
        };
        (result, self.detail)
    }
}

/// The content octets of the object identifier id-signedData,
/// 1.2.840.113549.1.7.2 (RFC 5652, section 5.1).
const ID_SIGNED_DATA: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];

/// Reads the length octets at `at` (ITU-T X.690 (02/2021), clause 8.1.3)
/// and returns the definite length, `None` for the indefinite form, and the
/// position after them; or `None` when they are malformed: 0xFF is
/// reserved (clause 8.1.3.5 c)), and this reader takes at most four
/// subsequent octets in the long form, far more than a file it reads holds.
fn length_at(bytes: &[u8], at: usize) -> Option<(Option<usize>, usize)> {
    let first = *bytes.get(at)?;
    match first {
        0x00..=0x7f => Some((Some(usize::from(first)), at + 1)),
        0x80 => Some((None, at + 1)),
        _ => {
            // The reserved 0xFF announces 127 subsequent octets, beyond the limit.
            let count = usize::from(first & 0x7f);
            if count > 4 {
                return None;
            }
            let octets = bytes.get(at + 1..at + 1 + count)?;
            let length = octets
                .iter()
                .fold(0usize, |length, octet| (length << 8) | usize::from(*octet));
            Some((Some(length), at + 1 + count))
        }
    }
}

/// Whether `bytes` start as a CMS `ContentInfo` of type `SignedData`
/// (RFC 5652, sections 3 and 5.1): a SEQUENCE, of definite or indefinite
/// length, so BER as well as DER (ITU-T X.690 (02/2021), clauses 8.1.3
/// and 8.9), whose first element is the OBJECT IDENTIFIER id-signedData.
/// Only these headers are read: nothing is decoded further and nothing is
/// allocated, whatever lengths the input declares.
pub fn is_cms_signed_data(bytes: &[u8]) -> bool {
    // The SEQUENCE tag: universal, constructed, number 16 (clauses 8.1.2 and 8.9.1).
    if bytes.first() != Some(&0x30) {
        return false;
    }
    let Some((_, at)) = length_at(bytes, 1) else {
        return false;
    };
    // The OBJECT IDENTIFIER tag, universal, primitive, number 6 (clause 8.19).
    if bytes.get(at) != Some(&0x06) {
        return false;
    }
    let Some((Some(length), start)) = length_at(bytes, at + 1) else {
        return false;
    };
    bytes.get(start..start.saturating_add(length)) == Some(&ID_SIGNED_DATA[..])
}

/// The artefacts of `artefacts`, each once, in their first order.
fn unique<'a>(artefacts: impl IntoIterator<Item = &'a Artefact>) -> Vec<&'a Artefact> {
    let mut seen = HashSet::new();
    artefacts
        .into_iter()
        .filter(|a| seen.insert(a.id.as_str()))
        .collect()
}

fn os(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

fn command_line(args: &[OsString]) -> String {
    let mut line = String::from("openssl");
    for arg in args {
        line.push(' ');
        line.push_str(&arg.to_string_lossy());
    }
    line
}

/// The command and the start of what it printed.
fn describe(args: &[OsString], output: &Output) -> String {
    let mut detail = command_line(args);
    detail.push('\n');
    for text in [&output.stdout, &output.stderr] {
        let excerpt = excerpt(text);
        if !excerpt.is_empty() {
            detail.push_str(&excerpt);
            detail.push('\n');
        }
    }
    detail
}

/// The first [`EXCERPT_LINES`] lines of `text`.
fn excerpt(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut excerpt = lines
        .iter()
        .take(EXCERPT_LINES)
        .copied()
        .collect::<Vec<_>>()
        .join("\n");
    if lines.len() > EXCERPT_LINES {
        excerpt.push_str("\n[...]");
    }
    excerpt
}

#[cfg(test)]
mod tests;
