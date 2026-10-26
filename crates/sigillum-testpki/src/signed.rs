//! The signed corpus under `signed/`: CAdES, PAdES and JAdES baseline
//! signatures created by DSS through the `sign` mode of `tools/dss-oracle`
//! (ADR-0013, ADR-0014), with the keys of the test PKI, the base documents
//! of [`crate::documents`] and the planned signing time.
//!
//! At B-T and B-LT, `tools/dss-oracle` runs this program's `tsa`
//! subcommand for the signature timestamp, at the planned signing time. At
//! B-LT, DSS embeds the OCSP responses of the signer and of `pki/tsa` and
//! the CRL of the root CA, which it checks at the validation time. No
//! clock is read, and the signatures are deterministic, so the corpus is
//! reproduced byte for byte with the same DSS version.

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::documents;
use crate::manifest::{Artefact, DssResult, Indication, Kind, Links, Manifest, OpensslResult};
use crate::openssl::Runner;
use crate::openssl::process::Program;
use crate::pki::hierarchy::PLANNED_SIGNING_TIME;
use crate::pki::{self, GenerateError, GeneratedFile, Summary, certificate_id, sha256_hex};

/// The directory of the signed corpus, relative to the manifest.
pub const DIRECTORY: &str = "signed";

/// A kind of signature of the corpus: a format with its packaging or
/// serialisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Variant {
    /// CAdES with the signed content inside the SignedData.
    CadesEnveloping,
    /// CAdES without the signed content.
    CadesDetached,
    /// PAdES, an invisible signature added by an incremental update.
    Pades,
    /// JAdES in the JWS compact serialisation (RFC 7515, section 7.1).
    JadesCompact,
    /// JAdES in the flattened JWS JSON serialisation (RFC 7515, section 7.2.2).
    JadesFlattened,
    /// JAdES in the general JWS JSON serialisation (RFC 7515, section 7.2.1).
    JadesGeneral,
}

/// The variants, in the order of the corpus.
const VARIANTS: [Variant; 6] = [
    Variant::CadesEnveloping,
    Variant::CadesDetached,
    Variant::Pades,
    Variant::JadesCompact,
    Variant::JadesFlattened,
    Variant::JadesGeneral,
];

impl Variant {
    /// The name in identifiers.
    fn name(self) -> &'static str {
        match self {
            Self::CadesEnveloping => "cades-enveloping",
            Self::CadesDetached => "cades-detached",
            Self::Pades => "pades",
            Self::JadesCompact => "jades-compact",
            Self::JadesFlattened => "jades-flattened",
            Self::JadesGeneral => "jades-general",
        }
    }

    /// The value of `--format`.
    fn format(self) -> &'static str {
        match self {
            Self::CadesEnveloping | Self::CadesDetached => "cades",
            Self::Pades => "pades",
            Self::JadesCompact | Self::JadesFlattened | Self::JadesGeneral => "jades",
        }
    }

    /// The extension of the file.
    fn extension(self) -> &'static str {
        match self {
            Self::CadesEnveloping => "p7m",
            Self::CadesDetached => "p7s",
            Self::Pades => "pdf",
            Self::JadesCompact => "jws",
            Self::JadesFlattened | Self::JadesGeneral => "json",
        }
    }

    /// The base document that is signed.
    fn document(self) -> &'static str {
        match self {
            Self::CadesEnveloping | Self::CadesDetached => documents::TEXT_ID,
            Self::Pades => documents::SIMPLE_PDF_ID,
            Self::JadesCompact | Self::JadesFlattened | Self::JadesGeneral => documents::JSON_ID,
        }
    }

    /// The description in purposes.
    fn description(self) -> &'static str {
        match self {
            Self::CadesEnveloping => "CAdES baseline signature, enveloping",
            Self::CadesDetached => "CAdES baseline signature, detached",
            Self::Pades => "PAdES baseline signature, invisible",
            Self::JadesCompact => "JAdES baseline signature in the JWS compact serialisation",
            Self::JadesFlattened => {
                "JAdES baseline signature in the flattened JWS JSON serialisation"
            }
            Self::JadesGeneral => "JAdES baseline signature in the general JWS JSON serialisation",
        }
    }

    /// The options that select the packaging or the serialisation.
    fn options(self) -> &'static [&'static str] {
        match self {
            Self::CadesEnveloping => &["--packaging", "enveloping"],
            Self::CadesDetached => &["--packaging", "detached"],
            Self::Pades => &[],
            Self::JadesCompact => &["--serialisation", "compact"],
            Self::JadesFlattened => &["--serialisation", "flattened"],
            Self::JadesGeneral => &["--serialisation", "general"],
        }
    }

    fn is_cades(self) -> bool {
        matches!(self, Self::CadesEnveloping | Self::CadesDetached)
    }

    fn is_jades(self) -> bool {
        matches!(
            self,
            Self::JadesCompact | Self::JadesFlattened | Self::JadesGeneral
        )
    }
}

/// A baseline level of ETSI EN 319 122-1 V1.3.1, EN 319 142-1 V1.2.1 and
/// TS 119 182-1 V1.2.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// B-B.
    B,
    /// B-T, with a signature timestamp.
    T,
    /// B-LT, with the validation data embedded.
    Lt,
}

const LEVELS: [Level; 3] = [Level::B, Level::T, Level::Lt];

impl Level {
    /// The value of `--level`.
    fn name(self) -> &'static str {
        match self {
            Self::B => "B-B",
            Self::T => "B-T",
            Self::Lt => "B-LT",
        }
    }
}

/// A signer of the corpus: an end entity of the test PKI with its CA.
#[derive(Debug, PartialEq, Eq)]
pub struct Signer {
    /// The name in identifiers.
    pub label: &'static str,
    /// The certificate name under `pki/`.
    pub name: &'static str,
    /// The issuing CA under `pki/`.
    pub ca: &'static str,
    /// The DSS signature algorithm to request, when the key type alone does
    /// not select it.
    pub algorithm: Option<&'static str>,
    /// The algorithm in purposes.
    pub description: &'static str,
}

/// The signers, one per signature family of the story.
pub const SIGNERS: [Signer; 4] = [
    Signer {
        label: "rsa",
        name: "signer-rsa-2048",
        ca: "ca-rsa",
        algorithm: None,
        description: "RSA PKCS#1 v1.5 and SHA-256",
    },
    Signer {
        label: "rsa-pss",
        name: "signer-rsa-pss-sha256",
        ca: "ca-rsa-pss",
        algorithm: Some("RSA_SSA_PSS_SHA256_MGF1"),
        description: "RSASSA-PSS and SHA-256",
    },
    Signer {
        label: "p256",
        name: "signer-p256",
        ca: "ca-ecdsa",
        algorithm: None,
        description: "ECDSA on P-256 and SHA-256",
    },
    Signer {
        label: "ed25519",
        name: "signer-ed25519",
        ca: "ca-ed25519",
        algorithm: None,
        description: "Ed25519",
    },
];

/// The timestamping authority of B-T and B-LT, and its issuing CA.
const TSA: &str = "tsa";
const TSA_CA: &str = "ca-ecdsa";
const ROOT: &str = "root-ca";

/// One signature of the corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixture {
    /// The format with its packaging or serialisation.
    pub variant: Variant,
    /// The baseline level.
    pub level: Level,
    /// The signer.
    pub signer: &'static Signer,
}

/// The signatures of the corpus: every variant at every level, except the
/// compact serialisation of JAdES, which is created at B-B only, for every
/// signer.
pub fn plan() -> Vec<Fixture> {
    let mut fixtures = Vec::new();
    for variant in VARIANTS {
        for level in LEVELS {
            if variant == Variant::JadesCompact && level != Level::B {
                // RFC 7515, section 7.1: no unprotected header for the unsigned properties.
                continue;
            }
            for signer in &SIGNERS {
                fixtures.push(Fixture {
                    variant,
                    level,
                    signer,
                });
            }
        }
    }
    fixtures
}

fn path_of(id: &str) -> Result<&'static str, SignedError> {
    // The base documents are the only artefacts given by identifier whose
    // extension is not fixed by their directory.
    match id {
        documents::TEXT_ID => Ok("documents/text.txt"),
        documents::SIMPLE_PDF_ID => Ok("documents/simple.pdf"),
        documents::JSON_ID => Ok("documents/payload.json"),
        _ => Err(SignedError::NotInManifest(id.to_owned())),
    }
}

fn format_time(time: OffsetDateTime) -> Result<String, SignedError> {
    time.format(&Rfc3339).map_err(|_| SignedError::Time)
}

impl Fixture {
    /// The identifier, such as `signed/cades-enveloping-b-b-rsa`.
    pub fn id(&self) -> String {
        format!(
            "{DIRECTORY}/{}-{}-{}",
            self.variant.name(),
            self.level.name().to_ascii_lowercase(),
            self.signer.label
        )
    }

    /// The path, relative to the manifest.
    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("{}.{}", self.id(), self.variant.extension()))
    }

    /// The options of the `sign` mode of `tools/dss-oracle` that create
    /// this signature from the corpus under `root`, with `tsa_program` as
    /// `sigillum-testpki`, into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`SignedError::Time`] if the signing time is out of range.
    pub fn arguments(
        &self,
        root: &Path,
        tsa_program: &Path,
        validation_time: OffsetDateTime,
        out: &Path,
    ) -> Result<Vec<OsString>, SignedError> {
        let corpus = |path: &str| root.join(path).into_os_string();
        let signing_time = format_time(
            PLANNED_SIGNING_TIME
                .from(validation_time)
                .map_err(|_| SignedError::Time)?,
        )?;
        let name = self.signer.name;
        let mut arguments: Vec<OsString> = vec![
            "--format".into(),
            self.variant.format().into(),
            "--level".into(),
            self.level.name().into(),
            "--key".into(),
            corpus(&format!("pki/keys/{name}{}", pki::KEY_SUFFIX)),
            "--certificate".into(),
            corpus(&format!("pki/{name}.pem")),
            "--chain".into(),
            corpus(&format!("pki/{}.pem", self.signer.ca)),
            "--chain".into(),
            corpus(&format!("pki/{ROOT}.pem")),
            "--signing-time".into(),
            signing_time.clone().into(),
            "--document".into(),
            corpus(path_of(self.variant.document())?),
        ];
        if let Some(algorithm) = self.signer.algorithm {
            arguments.extend(["--signature-algorithm".into(), algorithm.into()]);
        }
        arguments.extend(self.variant.options().iter().map(OsString::from));
        if self.level != Level::B {
            arguments.extend([
                "--tsa-program".into(),
                tsa_program.as_os_str().to_owned(),
                "--tsa-key".into(),
                corpus(&format!("pki/keys/{TSA}{}", pki::KEY_SUFFIX)),
                "--tsa-cert".into(),
                corpus(&format!("pki/{TSA}.pem")),
                "--timestamp-time".into(),
                signing_time.into(),
            ]);
        }
        if self.level == Level::Lt {
            arguments.extend([
                // The issuer of pki/tsa, so that DSS collects the validation data of its chain.
                "--tsa-chain".into(),
                corpus(&format!("pki/{TSA_CA}.pem")),
                "--trust-anchor".into(),
                corpus(&format!("pki/{ROOT}.pem")),
                "--ocsp".into(),
                corpus(&format!("ocsp/{name}.der")),
                "--ocsp".into(),
                corpus(&format!("ocsp/{TSA}.der")),
                "--crl".into(),
                corpus(&format!("crl/{ROOT}.crl")),
                "--validation-time".into(),
                format_time(validation_time)?.into(),
            ]);
        }
        arguments.extend(["--out".into(), out.as_os_str().to_owned()]);
        Ok(arguments)
    }

    /// The manifest entry of this signature, whose file holds `contents`.
    pub fn artefact(&self, contents: &[u8]) -> Artefact {
        let signer = certificate_id(self.signer.name);
        let mut revocation = Vec::new();
        if self.level != Level::Lt {
            revocation.push(format!("ocsp/{}", self.signer.name));
            revocation.push(format!("crl/{ROOT}"));
        }
        if self.level == Level::T {
            revocation.push(format!("ocsp/{TSA}"));
        }
        Artefact {
            id: self.id(),
            path: self.path(),
            sha256: sha256_hex(contents),
            kind: Kind::SignedDocument,
            purpose: format!(
                "{}, at {}, over {}, by {} with {}, created by DSS.",
                self.variant.description(),
                self.level.name(),
                self.variant.document(),
                signer,
                self.signer.description
            ),
            // openssl cms -verify checks CMS signatures only (ADR-0014).
            expected_openssl: if self.variant.is_cades() {
                OpensslResult::Verified
            } else {
                OpensslResult::NotApplicable
            },
            expected_dss: DssResult::Indication {
                indication: Indication::TotalPassed,
                sub_indication: None,
            },
            links: Links {
                issuer: Some(signer.clone()),
                chain: vec![signer, certificate_id(self.signer.ca), certificate_id(ROOT)],
                revocation,
                content: (self.variant == Variant::CadesDetached)
                    .then(|| self.variant.document().to_owned()),
                // The token holds the certificate of pki/tsa only, so the validation needs its chain.
                timestamp_chain: if self.level == Level::B {
                    Vec::new()
                } else {
                    vec![
                        certificate_id(TSA),
                        certificate_id(TSA_CA),
                        certificate_id(ROOT),
                    ]
                },
            },
            notes: Some(self.notes()),
        }
    }

    fn notes(&self) -> String {
        let mut notes = String::from(
            "The DSS result is a prediction from ETSI EN 319 102-1 V1.4.1, which DSS 6.5.1 gives in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only. The signature value and the signed attributes verify (clause 5.2.7), the chain builds to pki/root-ca (clause 5.2.6), and no certificate of the chain is revoked (clause 5.2.6.4, step 4).",
        );
        match self.level {
            Level::B => notes.push_str(
                " The revocation data linked cover the signer and its CA.",
            ),
            Level::T => notes.push_str(
                " The signature timestamp is from pki/tsa, at the signing time. The token holds pki/tsa only; timestamp-chain links pki/tsa and the chain above it, and the revocation data linked cover the signer, pki/tsa and the CAs, so with the linked files, the signature timestamp passes the time-stamp validation building block (clause 5.4).",
            ),
            Level::Lt => notes.push_str(
                " The signature timestamp is from pki/tsa, at the signing time. DSS embedded the OCSP responses of the signer and of pki/tsa and crl/root-ca, selected at the validation time, with the certificates of both chains, so the validation needs no revocation data linked; timestamp-chain still links the chain of pki/tsa.",
            ),
        }
        if self.variant.is_jades() {
            notes.push_str(" The protected header carries x5c, as Implementing Regulation (EU) 2026/248, Annex I, requires.");
            notes.push_str(if self.level == Level::Lt {
                " At B-LT, x5c holds the signing certificate and the chain below the trust anchor: DSS leaves pki/root-ca, given as trust anchor, out of it, and holds it in the validation data of etsiU."
            } else {
                " x5c holds the signing certificate and the chain up to pki/root-ca."
            });
        }
        if self.variant == Variant::JadesCompact {
            notes.push_str(" The compact serialisation has no unprotected header for unsigned properties (RFC 7515, section 7.1), so it is created at B-B only.");
        }
        if self.signer.label == "ed25519" {
            notes.push_str(" Under its default validation policy, DSS 6.5.1 reports INDETERMINATE with CRYPTO_CONSTRAINTS_FAILURE_NO_POE instead, because that policy does not authorise EdDSA; the aligned policy does.");
        }
        notes
    }
}

/// Runs the `sign` mode of `tools/dss-oracle`.
pub trait Oracle {
    /// Runs the mode with `arguments`, the options after the mode name.
    ///
    /// # Errors
    ///
    /// Returns a message when the mode cannot run or does not succeed.
    fn sign(&self, arguments: &[OsString]) -> Result<(), String>;
}

/// `tools/dss-oracle` run as `java <options> -jar <jar> sign ...`, without a shell,
/// for at most [`JavaOracle::timeout`] per signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaOracle {
    /// The Java launcher.
    pub java: PathBuf,
    /// The executable JAR of `tools/dss-oracle`.
    pub jar: PathBuf,
    /// How long one signature may take.
    pub timeout: Duration,
}

impl JavaOracle {
    /// The time that one signature may take by default, far above the
    /// few seconds that one takes.
    pub const TIMEOUT: Duration = Duration::from_secs(300);

    /// An oracle with the default time limit.
    pub fn new(java: PathBuf, jar: PathBuf) -> Self {
        Self {
            java,
            jar,
            timeout: Self::TIMEOUT,
        }
    }
}

/// The most output that `tools/dss-oracle` may write to each of its outputs.
const MAX_OUTPUT: usize = 1024 * 1024;

impl JavaOracle {
    /// The launcher as a bounded program, run in the current directory:
    /// one deadline covers the run and the reading of its outputs, both
    /// outputs are limited to 1 MiB each, and on Unix its
    /// process group, with every process it started, is killed at the
    /// deadline ([`crate::openssl::process::Program`]).
    pub fn program(&self) -> Program {
        Program::new(&self.java, ".").with_limits(self.timeout, MAX_OUTPUT)
    }
}

/// Options of the Java launcher that make every identity hash code 1.
///
/// DSS 6.5.1 keeps the validation data that it embeds at B-LT in hash
/// sets, and the hash code of each token includes the hash code of an
/// enumeration constant, which is its identity hash code. The order in
/// which the data are embedded then depends on the JVM. With constant
/// identity hash codes, it depends only on the data, so the corpus is
/// reproducible on any JVM that accepts the option, as HotSpot from
/// Java 21 to 27 does.
const JVM_OPTIONS: [&str; 2] = ["-XX:+UnlockExperimentalVMOptions", "-XX:hashCode=2"];

impl JavaOracle {
    /// The arguments of the launcher for the `sign` mode with `arguments`.
    pub(crate) fn arguments(&self, arguments: &[OsString]) -> Vec<OsString> {
        let mut argv: Vec<OsString> = JVM_OPTIONS.iter().map(OsString::from).collect();
        argv.extend([
            "-jar".into(),
            self.jar.as_os_str().to_owned(),
            "sign".into(),
        ]);
        argv.extend(arguments.iter().cloned());
        argv
    }
}

impl Oracle for JavaOracle {
    fn sign(&self, arguments: &[OsString]) -> Result<(), String> {
        run_oracle(&self.program(), &self.arguments(arguments))
    }
}

/// Runs `program` with `arguments`, and returns its error output as the
/// message when it does not succeed.
///
/// # Errors
///
/// Returns a message when the program cannot be run to the end, runs past
/// its deadline, writes too much, or exits with another code than 0.
pub(crate) fn run_oracle(program: &Program, arguments: &[OsString]) -> Result<(), String> {
    let output = program.run(arguments).map_err(|error| error.to_string())?;
    if output.success {
        Ok(())
    } else {
        Err(format!("failed: {}", output.stderr.trim()))
    }
}

/// An error found while generating the signed corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignedError {
    /// The manifest does not list an artefact that a signature uses.
    NotInManifest(String),
    /// `tools/dss-oracle` did not create a signature.
    Oracle {
        /// The identifier of the signature.
        id: String,
        /// What went wrong.
        message: String,
    },
    /// A file cannot be read or written.
    Io(String),
    /// The signing time is out of range.
    Time,
}

impl fmt::Display for SignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInManifest(id) => write!(
                f,
                "the manifest does not list {id}, which the signed corpus needs"
            ),
            Self::Oracle { id, message } => {
                write!(f, "tools/dss-oracle cannot sign {id}: {message}")
            }
            Self::Io(message) => write!(
                f,
                "a file of the signed corpus cannot be read or written: {message}"
            ),
            Self::Time => f.write_str("the signing time is out of range"),
        }
    }
}

impl std::error::Error for SignedError {}

/// A directory of its own for the outputs of one run, removed when dropped.
struct WorkDirectory(PathBuf);

impl WorkDirectory {
    fn create() -> Result<Self, SignedError> {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "sigillum-testpki-signed-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path)
            .map_err(|error| SignedError::Io(format!("{}: {error}", path.display())))?;
        Ok(Self(path))
    }
}

impl Drop for WorkDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Creates every signature of [`plan`] with `oracle`, from the corpus under
/// `root`, and returns the files with their manifest entries.
///
/// # Errors
///
/// Returns a [`SignedError`] if a signature cannot be created or read.
pub fn generate(
    root: &Path,
    validation_time: OffsetDateTime,
    oracle: &dyn Oracle,
    tsa_program: &Path,
) -> Result<Vec<GeneratedFile>, SignedError> {
    let work = WorkDirectory::create()?;
    let mut files = Vec::new();
    for fixture in plan() {
        let id = fixture.id();
        let out = work.0.join(id.replace('/', "-"));
        let arguments = fixture.arguments(root, tsa_program, validation_time, &out)?;
        oracle
            .sign(&arguments)
            .map_err(|message| SignedError::Oracle {
                id: id.clone(),
                message,
            })?;
        let contents = std::fs::read(&out)
            .map_err(|error| SignedError::Io(format!("{id}: {}: {error}", out.display())))?;
        files.push(GeneratedFile {
            artefact: fixture.artefact(&contents),
            contents,
        });
    }
    Ok(files)
}

/// The identifiers of the artefacts that the signatures read or link.
fn required_ids() -> Vec<String> {
    let mut ids = Vec::new();
    for signer in &SIGNERS {
        ids.push(certificate_id(signer.name));
        ids.push(pki::key_id(signer.name));
        ids.push(certificate_id(signer.ca));
        ids.push(format!("ocsp/{}", signer.name));
    }
    ids.extend([
        certificate_id(ROOT),
        certificate_id(TSA),
        pki::key_id(TSA),
        certificate_id(TSA_CA),
        format!("ocsp/{TSA}"),
        format!("crl/{ROOT}"),
        documents::TEXT_ID.to_owned(),
        documents::SIMPLE_PDF_ID.to_owned(),
        documents::JSON_ID.to_owned(),
    ]);
    ids
}

/// Checks that the manifest lists every artefact that the signatures read
/// or link, before any signature is created.
fn check_listed(manifest: &Manifest) -> Result<(), SignedError> {
    for id in required_ids() {
        if !manifest.artefacts.iter().any(|artefact| artefact.id == id) {
            return Err(SignedError::NotInManifest(id));
        }
    }
    Ok(())
}

/// Reports whether an entry belongs to what `generate signed` produces:
/// any entry whose identifier is under [`DIRECTORY`].
fn generated_here(artefact: &Artefact) -> bool {
    artefact.id.starts_with(&format!("{DIRECTORY}/"))
}

/// Creates the signed corpus with the validation time of the manifest at
/// `manifest_path`, writes each signature under the manifest's directory,
/// and records each in the manifest, following the regeneration rules of
/// [`pki::write_into_corpus`]. Every entry under [`DIRECTORY`] belongs to
/// this generator. The manifest must already list the test PKI, its CRLs
/// and OCSP responses, and the base documents; otherwise nothing is
/// written.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the manifest cannot be read, does not
/// list what the signatures need or cannot be updated, a signature cannot
/// be created, or a file cannot be written.
pub fn write_into_corpus(
    manifest_path: &Path,
    oracle: &dyn Oracle,
    tsa_program: &Path,
) -> Result<Summary, GenerateError> {
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    pki::write_generated(
        manifest_path,
        DIRECTORY,
        generated_here,
        |manifest| {
            check_listed(manifest).map_err(GenerateError::Signed)?;
            generate(root, manifest.header.validation_time, oracle, tsa_program)
                .map_err(GenerateError::Signed)
        },
        |_, _| {},
    )
}

#[cfg(test)]
mod tests;
