//! The manifest of the test corpus, `testdata/manifest.toml`.
//!
//! The format is described in `testdata/README.md`. Parsing rejects unknown
//! fields, unsupported format versions, validation times of another form,
//! empty text fields, duplicate identifiers, paths that are not portable
//! relative paths or that name the corpus's own files, paths that conflict
//! ignoring letter case, malformed digests, sub-indications that do not
//! belong to the indication, and links to unknown artefacts, to the artefact
//! itself, to artefacts of the wrong kind or repeated in a list.
//!
//! [`Manifest::to_toml`] writes a manifest back in the same format, so that
//! the generator can record the artefacts it writes.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;

use serde::Deserialize;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// The manifest format version this crate reads.
pub const FORMAT_VERSION: u32 = 1;

/// The sub-indications that may accompany TOTAL-FAILED (ETSI EN 319 102-1
/// V1.4.1, clause 5.1.3, Table 6). The project also uses them with FAILED,
/// the result of a building block such as certificate validation.
pub const FAILED_SUB_INDICATIONS: [&str; 6] = [
    "FORMAT_FAILURE",
    "HASH_FAILURE",
    "SIG_CRYPTO_FAILURE",
    "REVOKED",
    "EXPIRED",
    "NOT_YET_VALID",
];

/// The sub-indications that may accompany INDETERMINATE (ETSI EN 319 102-1
/// V1.4.1, clause 5.1.3, Table 6), for the main result and for building blocks.
pub const INDETERMINATE_SUB_INDICATIONS: [&str; 20] = [
    "SIG_CONSTRAINTS_FAILURE",
    "CHAIN_CONSTRAINTS_FAILURE",
    "CERTIFICATE_CHAIN_GENERAL_FAILURE",
    "CRYPTO_CONSTRAINTS_FAILURE",
    "CRYPTO_CONSTRAINTS_FAILURE_NO_POE",
    "POLICY_PROCESSING_ERROR",
    "SIGNATURE_POLICY_NOT_AVAILABLE",
    "TIMESTAMP_ORDER_FAILURE",
    "NO_SIGNING_CERTIFICATE_FOUND",
    "NO_CERTIFICATE_CHAIN_FOUND",
    "NO_CERTIFICATE_CHAIN_FOUND_NO_POE",
    "REVOKED_NO_POE",
    "REVOKED_CA_NO_POE",
    "OUT_OF_BOUNDS_NO_POE",
    "OUT_OF_BOUNDS_NOT_REVOKED",
    "REVOCATION_OUT_OF_BOUNDS_NO_POE",
    "NO_POE",
    "TRY_LATER",
    "SIGNED_DATA_NOT_FOUND",
    "CUSTOM",
];

/// The parsed manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Values that apply to the whole corpus.
    pub header: Header,
    /// One entry per artefact.
    pub artefacts: Vec<Artefact>,
}

/// Values that apply to the whole corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The version of the manifest format.
    pub format_version: u32,
    /// The fixed validation time to which every time field is tied.
    pub validation_time: OffsetDateTime,
    /// The OpenSSL version whose results the manifest records.
    pub openssl_version: String,
    /// The DSS version whose results the manifest records.
    pub dss_version: String,
}

/// One artefact of the corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artefact {
    /// Unique identifier.
    pub id: String,
    /// Path relative to the directory that contains the manifest.
    pub path: PathBuf,
    /// SHA-256 digest of the file, as 64 lower-case hexadecimal digits.
    pub sha256: String,
    /// What the artefact is.
    pub kind: Kind,
    /// Why the artefact exists.
    pub purpose: String,
    /// The result expected from OpenSSL.
    pub expected_openssl: OpensslResult,
    /// The result expected from DSS.
    pub expected_dss: DssResult,
    /// Other artefacts needed to check this one.
    pub links: Links,
    /// Free-form remarks.
    pub notes: Option<String>,
}

/// Other artefacts needed to check an artefact, by identifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Links {
    /// The certificate of the issuer.
    pub issuer: Option<String>,
    /// The certification path above the artefact, from its issuer up to the
    /// trust anchor, without repetition.
    pub chain: Vec<String>,
    /// CRLs and OCSP responses for the artefact.
    pub revocation: Vec<String>,
    /// The signed content of a detached signature, or the data a timestamp covers.
    pub content: Option<String>,
    /// For a signed document with a signature timestamp: the certificate of
    /// the timestamping authority and the chain above it, up to the trust
    /// anchor, without repetition.
    pub timestamp_chain: Vec<String>,
}

/// The kind of an artefact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// An X.509 certificate.
    Certificate,
    /// A private key of the test PKI.
    PrivateKey,
    /// A certificate revocation list.
    Crl,
    /// An OCSP response.
    OcspResponse,
    /// An RFC 3161 timestamp token.
    TimestampToken,
    /// A signed document or detached signature.
    SignedDocument,
    /// An unsigned document used as input to signing.
    Document,
}

impl Kind {
    /// The kind as written in the manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::PrivateKey => "private-key",
            Self::Crl => "crl",
            Self::OcspResponse => "ocsp-response",
            Self::TimestampToken => "timestamp-token",
            Self::SignedDocument => "signed-document",
            Self::Document => "document",
        }
    }
}

/// The result expected from OpenSSL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OpensslResult {
    /// Parsed and verified.
    Verified,
    /// Parsed; verification is not applicable or depends on the current time.
    Parsed,
    /// Rejected.
    Rejected,
    /// OpenSSL does not process this kind of artefact.
    NotApplicable,
}

impl OpensslResult {
    /// The result as written in the manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Parsed => "parsed",
            Self::Rejected => "rejected",
            Self::NotApplicable => "not-applicable",
        }
    }
}

/// The result expected from DSS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DssResult {
    /// DSS cannot parse the artefact.
    Rejected,
    /// DSS does not process this kind of artefact.
    NotApplicable,
    /// DSS parses the artefact and returns this indication and, optionally,
    /// this sub-indication.
    Indication {
        /// The indication.
        indication: Indication,
        /// The sub-indication, as written in ETSI EN 319 102-1.
        sub_indication: Option<String>,
    },
}

/// The result in words: `rejected`, `not-applicable`, an indication, or an
/// indication with its sub-indication, such as `INDETERMINATE with
/// REVOKED_NO_POE`.
impl fmt::Display for DssResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected => f.write_str("rejected"),
            Self::NotApplicable => f.write_str("not-applicable"),
            Self::Indication {
                indication,
                sub_indication: None,
            } => f.write_str(indication.as_str()),
            Self::Indication {
                indication,
                sub_indication: Some(sub),
            } => write!(f, "{} with {sub}", indication.as_str()),
        }
    }
}

/// An indication of ETSI EN 319 102-1 V1.4.1, clause 5.1.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum Indication {
    /// TOTAL-PASSED.
    #[serde(rename = "TOTAL-PASSED")]
    TotalPassed,
    /// TOTAL-FAILED.
    #[serde(rename = "TOTAL-FAILED")]
    TotalFailed,
    /// INDETERMINATE.
    #[serde(rename = "INDETERMINATE")]
    Indeterminate,
    /// PASSED, the result of a building block such as certificate validation.
    #[serde(rename = "PASSED")]
    Passed,
    /// FAILED, the result of a building block such as certificate validation.
    #[serde(rename = "FAILED")]
    Failed,
}

impl Indication {
    /// The indication as written in the manifest.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TotalPassed => "TOTAL-PASSED",
            Self::TotalFailed => "TOTAL-FAILED",
            Self::Indeterminate => "INDETERMINATE",
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
        }
    }

    /// The sub-indications allowed with this indication.
    pub fn sub_indications(self) -> &'static [&'static str] {
        match self {
            Self::TotalPassed | Self::Passed => &[],
            Self::TotalFailed | Self::Failed => &FAILED_SUB_INDICATIONS,
            Self::Indeterminate => &INDETERMINATE_SUB_INDICATIONS,
        }
    }
}

/// An error found while reading the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// The text is not valid TOML or does not match the manifest structure.
    Syntax(String),
    /// The manifest declares a format version this crate does not read.
    UnsupportedFormatVersion(u32),
    /// The validation time is not of the form `YYYY-MM-DDTHH:MM:SSZ`.
    ValidationTime(String),
    /// A required text field is empty.
    EmptyField {
        /// The artefact identifier, or empty for the header.
        id: String,
        /// The field name, as written in the manifest.
        field: &'static str,
    },
    /// An identifier uses characters or a form that is not allowed.
    InvalidIdentifier(String),
    /// Two artefacts have the same identifier.
    DuplicateIdentifier(String),
    /// An artefact path is not a portable relative path.
    InvalidPath {
        /// The artefact identifier.
        id: String,
        /// The path as written in the manifest.
        path: String,
    },
    /// Two artefacts name the same file, ignoring letter case.
    DuplicatePath {
        /// The identifier of the second artefact.
        id: String,
        /// The path as written in the manifest.
        path: String,
    },
    /// The digest is not 64 lower-case hexadecimal digits.
    InvalidDigest {
        /// The artefact identifier.
        id: String,
        /// The digest as written in the manifest.
        value: String,
    },
    /// The sub-indication does not belong to the indication.
    InvalidSubIndication {
        /// The artefact identifier.
        id: String,
        /// The indication.
        indication: &'static str,
        /// The sub-indication as written in the manifest.
        value: String,
    },
    /// Two artefact paths collide on a file system that ignores letter case,
    /// or one names a file where the other needs a directory.
    PathConflict {
        /// The identifier of the second artefact.
        id: String,
        /// The path as written in the manifest.
        path: String,
    },
    /// A link names an artefact of a kind that does not fit the link,
    /// repeats an artefact already in the same list, or starts a chain with
    /// another certificate than the issuer.
    LinkMismatch {
        /// The artefact identifier.
        id: String,
        /// The link field.
        link: &'static str,
        /// The identifier the link names.
        target: String,
    },
    /// A link names an artefact that is not in the manifest, or the artefact itself.
    InvalidLink {
        /// The artefact identifier.
        id: String,
        /// The link field.
        link: &'static str,
        /// The identifier the link names.
        target: String,
    },
    /// The manifest file cannot be read.
    Io(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(message) => write!(f, "the manifest is not valid: {message}"),
            Self::UnsupportedFormatVersion(version) => write!(
                f,
                "the manifest format version {version} is not supported; this program reads version {FORMAT_VERSION}"
            ),
            Self::ValidationTime(value) => write!(
                f,
                "the validation time \"{value}\" is not of the form YYYY-MM-DDTHH:MM:SSZ"
            ),
            Self::EmptyField { id, field } if id.is_empty() => {
                write!(f, "the field \"{field}\" is empty")
            }
            Self::EmptyField { id, field } => {
                write!(f, "the field \"{field}\" of \"{id}\" is empty")
            }
            Self::InvalidIdentifier(id) => write!(
                f,
                "the identifier \"{id}\" may only contain letters, digits, '.', '_', '-' and '/' between non-empty parts"
            ),
            Self::DuplicateIdentifier(id) => {
                write!(f, "the identifier \"{id}\" is used more than once")
            }
            Self::InvalidPath { id, path } => write!(
                f,
                "the path \"{path}\" of \"{id}\" is not a portable relative path inside the corpus"
            ),
            Self::DuplicatePath { id, path } => write!(
                f,
                "the path \"{path}\" of \"{id}\" names a file already listed, ignoring letter case"
            ),
            Self::InvalidDigest { id, value } => write!(
                f,
                "the sha256 \"{value}\" of \"{id}\" is not 64 lower-case hexadecimal digits"
            ),
            Self::InvalidSubIndication {
                id,
                indication,
                value,
            } => write!(
                f,
                "the sub-indication \"{value}\" of \"{id}\" is not one of those defined for {indication}"
            ),
            Self::PathConflict { id, path } => write!(
                f,
                "the path \"{path}\" of \"{id}\" conflicts with another path of the manifest, ignoring letter case"
            ),
            Self::LinkMismatch { id, link, target } => write!(
                f,
                "the link {link} = \"{target}\" of \"{id}\" names an artefact of the wrong kind or repeats one"
            ),
            Self::InvalidLink { id, link, target } => write!(
                f,
                "the link {link} = \"{target}\" of \"{id}\" does not name another artefact of the manifest"
            ),
            Self::Io(message) => write!(f, "the manifest cannot be read: {message}"),
        }
    }
}

impl std::error::Error for ManifestError {}

impl Manifest {
    /// Parses and checks the text of a manifest.
    ///
    /// # Errors
    ///
    /// Returns a [`ManifestError`] when the text does not describe a valid manifest.
    pub fn parse(text: &str) -> Result<Self, ManifestError> {
        let raw: RawManifest = toml::from_str(text).map_err(|e| syntax_error(text, &e))?;
        let header = raw.header.check()?;
        let mut kinds = HashMap::new();
        let mut paths = PathSet::default();
        let mut artefacts = Vec::with_capacity(raw.artefact.len());
        for entry in raw.artefact {
            let artefact = entry.check()?;
            if kinds.insert(artefact.id.clone(), artefact.kind).is_some() {
                return Err(ManifestError::DuplicateIdentifier(artefact.id));
            }
            paths.insert(&artefact)?;
            artefacts.push(artefact);
        }
        for artefact in &artefacts {
            artefact.check_links(&kinds)?;
        }
        Ok(Self { header, artefacts })
    }

    /// Reads, parses and checks a manifest file.
    ///
    /// # Errors
    ///
    /// Returns [`ManifestError::Io`] when the file cannot be read, and the
    /// errors of [`Manifest::parse`] otherwise.
    pub fn load(path: &std::path::Path) -> Result<Self, ManifestError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ManifestError::Io(format!("{}: {e}", path.display())))?;
        Self::parse(&text)
    }

    /// Replaces the artefact that has the identifier of `artefact`, or
    /// appends `artefact` if there is none.
    pub fn upsert(&mut self, artefact: Artefact) {
        match self.artefacts.iter_mut().find(|a| a.id == artefact.id) {
            Some(existing) => *existing = artefact,
            None => self.artefacts.push(artefact),
        }
    }

    /// Writes the manifest in the format that [`Manifest::parse`] reads,
    /// with the fields in the order of `testdata/README.md`, one line each,
    /// and links and DSS results as inline tables.
    pub fn to_toml(&self) -> String {
        let mut out = String::from(
            "# Manifest of the test corpus. The format is described in README.md.\n\n[header]\n",
        );
        let validation_time = self
            .header
            .validation_time
            .format(&Rfc3339)
            .unwrap_or_default();
        push_field(
            &mut out,
            "format-version",
            &self.header.format_version.to_string(),
        );
        push_field(&mut out, "validation-time", &quoted(&validation_time));
        push_field(
            &mut out,
            "openssl-version",
            &quoted(&self.header.openssl_version),
        );
        push_field(&mut out, "dss-version", &quoted(&self.header.dss_version));
        for artefact in &self.artefacts {
            out.push_str("\n[[artefact]]\n");
            artefact.write_toml(&mut out);
        }
        out
    }
}

impl Artefact {
    fn write_toml(&self, out: &mut String) {
        push_field(out, "id", &quoted(&self.id));
        push_field(out, "path", &quoted(&self.path.to_string_lossy()));
        push_field(out, "sha256", &quoted(&self.sha256));
        push_field(out, "kind", &quoted(self.kind.as_str()));
        push_field(out, "purpose", &quoted(&self.purpose));
        push_field(
            out,
            "expected-openssl",
            &quoted(self.expected_openssl.as_str()),
        );
        let dss = match &self.expected_dss {
            DssResult::Rejected => quoted("rejected"),
            DssResult::NotApplicable => quoted("not-applicable"),
            DssResult::Indication {
                indication,
                sub_indication,
            } => {
                let mut fields = vec![format!("indication = {}", quoted(indication.as_str()))];
                if let Some(sub_indication) = sub_indication {
                    fields.push(format!("sub-indication = {}", quoted(sub_indication)));
                }
                inline_table(&fields)
            }
        };
        push_field(out, "expected-dss", &dss);
        let links = &self.links;
        let list = |values: &[String]| {
            let items: Vec<String> = values.iter().map(|v| quoted(v)).collect();
            format!("[{}]", items.join(", "))
        };
        let mut fields = Vec::new();
        if let Some(issuer) = &links.issuer {
            fields.push(format!("issuer = {}", quoted(issuer)));
        }
        if !links.chain.is_empty() {
            fields.push(format!("chain = {}", list(&links.chain)));
        }
        if !links.timestamp_chain.is_empty() {
            fields.push(format!(
                "timestamp-chain = {}",
                list(&links.timestamp_chain)
            ));
        }
        if !links.revocation.is_empty() {
            fields.push(format!("revocation = {}", list(&links.revocation)));
        }
        if let Some(content) = &links.content {
            fields.push(format!("content = {}", quoted(content)));
        }
        if !fields.is_empty() {
            push_field(out, "links", &inline_table(&fields));
        }
        if let Some(notes) = &self.notes {
            push_field(out, "notes", &quoted(notes));
        }
    }
}

fn push_field(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(value);
    out.push('\n');
}

fn inline_table(fields: &[String]) -> String {
    format!("{{ {} }}", fields.join(", "))
}

/// A TOML basic string, with the escapes the TOML specification requires.
fn quoted(value: &str) -> String {
    toml::Value::String(value.to_owned()).to_string()
}

impl Artefact {
    fn check_links(&self, kinds: &HashMap<String, Kind>) -> Result<(), ManifestError> {
        let certificate = |kind: Kind| kind == Kind::Certificate;
        let revocation = |kind: Kind| matches!(kind, Kind::Crl | Kind::OcspResponse);
        let any = |_: Kind| true;
        let single = [
            (
                "issuer",
                self.links.issuer.as_slice(),
                &certificate as &dyn Fn(Kind) -> bool,
            ),
            ("content", self.links.content.as_slice(), &any),
        ];
        let many = [
            (
                "chain",
                self.links.chain.as_slice(),
                &certificate as &dyn Fn(Kind) -> bool,
            ),
            ("revocation", self.links.revocation.as_slice(), &revocation),
            (
                "timestamp-chain",
                self.links.timestamp_chain.as_slice(),
                &certificate as &dyn Fn(Kind) -> bool,
            ),
        ];
        for (link, targets, fits) in single.into_iter().chain(many) {
            let mut seen = HashSet::new();
            for target in targets {
                let error = |mismatch: bool| {
                    let (id, target) = (self.id.clone(), target.clone());
                    if mismatch {
                        ManifestError::LinkMismatch { id, link, target }
                    } else {
                        ManifestError::InvalidLink { id, link, target }
                    }
                };
                let kind = kinds
                    .get(target)
                    .filter(|_| target != &self.id)
                    .ok_or_else(|| error(false))?;
                if !fits(*kind) || !seen.insert(target) {
                    return Err(error(true));
                }
            }
        }
        if let (Some(issuer), Some(first)) = (&self.links.issuer, self.links.chain.first())
            && first != issuer
        {
            return Err(ManifestError::LinkMismatch {
                id: self.id.clone(),
                link: "chain",
                target: first.clone(),
            });
        }
        Ok(())
    }
}

/// The paths of the artefacts read so far, folded to lower case, with the
/// directories they imply.
#[derive(Default)]
struct PathSet {
    files: HashSet<String>,
    directories: HashMap<String, String>,
}

impl PathSet {
    fn insert(&mut self, artefact: &Artefact) -> Result<(), ManifestError> {
        let path = artefact.path.to_string_lossy().into_owned();
        let folded = path.to_lowercase();
        let conflict = || ManifestError::PathConflict {
            id: artefact.id.clone(),
            path: path.clone(),
        };
        if self.files.contains(&folded) {
            return Err(ManifestError::DuplicatePath {
                id: artefact.id.clone(),
                path: path.clone(),
            });
        }
        if self.directories.contains_key(&folded) {
            return Err(conflict());
        }
        let mut directories = Vec::new();
        for (index, _) in path.match_indices('/') {
            let directory = &path[..index];
            let folded_directory = directory.to_lowercase();
            let clashes = self.files.contains(&folded_directory)
                || self
                    .directories
                    .get(&folded_directory)
                    .is_some_and(|spelling| spelling != directory);
            if clashes {
                return Err(conflict());
            }
            directories.push((folded_directory, directory.to_owned()));
        }
        self.files.insert(folded);
        self.directories.extend(directories);
        Ok(())
    }
}

/// Builds a syntax error that names the line and column, without the
/// excerpt that the TOML parser adds.
fn syntax_error(text: &str, error: &toml::de::Error) -> ManifestError {
    let location = error.span().map(|span| {
        let before = text.get(..span.start).unwrap_or(text);
        let line = before.matches('\n').count() + 1;
        let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        format!("line {line}, column {column}: ")
    });
    ManifestError::Syntax(format!(
        "{}{}",
        location.unwrap_or_default(),
        error.message()
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    header: RawHeader,
    #[serde(default)]
    artefact: Vec<RawArtefact>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawHeader {
    format_version: u32,
    validation_time: String,
    openssl_version: String,
    dss_version: String,
}

impl RawHeader {
    fn check(self) -> Result<Header, ManifestError> {
        if self.format_version != FORMAT_VERSION {
            return Err(ManifestError::UnsupportedFormatVersion(self.format_version));
        }
        Ok(Header {
            format_version: self.format_version,
            validation_time: validation_time(&self.validation_time)?,
            openssl_version: non_empty(self.openssl_version, "", "openssl-version")?,
            dss_version: non_empty(self.dss_version, "", "dss-version")?,
        })
    }
}

/// Parses a time of the exact form of `validation-time`,
/// `YYYY-MM-DDTHH:MM:SSZ`, or returns `None`. The `tsa` subcommand reads
/// its `--time` with this rule.
pub fn utc_time(value: &str) -> Option<OffsetDateTime> {
    validation_time(value).ok()
}

/// Parses a time of the exact form `YYYY-MM-DDTHH:MM:SSZ`, in whole seconds
/// and without leap seconds, as certificate times require (RFC 5280,
/// section 4.1.2.5).
fn validation_time(value: &str) -> Result<OffsetDateTime, ManifestError> {
    let error = || ManifestError::ValidationTime(value.to_owned());
    let shape = value.len() == 20
        && value.bytes().enumerate().all(|(i, b)| match i {
            4 | 7 => b == b'-',
            10 => b == b'T',
            13 | 16 => b == b':',
            19 => b == b'Z',
            _ => b.is_ascii_digit(),
        });
    if !shape || &value[17..19] == "60" {
        return Err(error());
    }
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| error())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct RawArtefact {
    id: String,
    path: String,
    sha256: String,
    kind: Kind,
    purpose: String,
    expected_openssl: OpensslResult,
    expected_dss: RawDssResult,
    #[serde(default)]
    links: RawLinks,
    notes: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawLinks {
    issuer: Option<String>,
    #[serde(default)]
    chain: Vec<String>,
    #[serde(default)]
    revocation: Vec<String>,
    content: Option<String>,
    #[serde(default, rename = "timestamp-chain")]
    timestamp_chain: Vec<String>,
}

impl RawArtefact {
    fn check(self) -> Result<Artefact, ManifestError> {
        let id = non_empty(self.id, "", "id")?;
        if !portable_relative(&id) {
            return Err(ManifestError::InvalidIdentifier(id));
        }
        if !portable_relative(&self.path) || corpus_file(&self.path) {
            return Err(ManifestError::InvalidPath {
                id,
                path: self.path,
            });
        }
        let is_digest = self.sha256.len() == 64
            && self
                .sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !is_digest {
            return Err(ManifestError::InvalidDigest {
                id,
                value: self.sha256,
            });
        }
        let purpose = non_empty(self.purpose, &id, "purpose")?;
        let notes = self
            .notes
            .map(|notes| non_empty(notes, &id, "notes"))
            .transpose()?;
        let expected_dss = match self.expected_dss {
            RawDssResult::Rejected => DssResult::Rejected,
            RawDssResult::NotApplicable => DssResult::NotApplicable,
            RawDssResult::Indication {
                indication,
                sub_indication,
            } => {
                if let Some(value) = &sub_indication
                    && !indication.sub_indications().contains(&value.as_str())
                {
                    return Err(ManifestError::InvalidSubIndication {
                        id,
                        indication: indication.as_str(),
                        value: value.clone(),
                    });
                }
                DssResult::Indication {
                    indication,
                    sub_indication,
                }
            }
        };
        Ok(Artefact {
            path: PathBuf::from(&self.path),
            id,
            sha256: self.sha256,
            kind: self.kind,
            purpose,
            expected_openssl: self.expected_openssl,
            expected_dss,
            links: Links {
                issuer: self.links.issuer,
                chain: self.links.chain,
                revocation: self.links.revocation,
                content: self.links.content,
                timestamp_chain: self.links.timestamp_chain,
            },
            notes,
        })
    }
}

/// `expected-dss`: "rejected", "not-applicable", or a table with an
/// indication and an optional sub-indication.
enum RawDssResult {
    Rejected,
    NotApplicable,
    Indication {
        indication: Indication,
        sub_indication: Option<String>,
    },
}

impl<'de> Deserialize<'de> for RawDssResult {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DssVisitor;

        impl<'de> Visitor<'de> for DssVisitor {
            type Value = RawDssResult;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("\"rejected\", \"not-applicable\" or a table { indication = \"...\", sub-indication = \"...\" }")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "rejected" => Ok(RawDssResult::Rejected),
                    "not-applicable" => Ok(RawDssResult::NotApplicable),
                    other => Err(E::invalid_value(de::Unexpected::Str(other), &self)),
                }
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut indication = None;
                let mut sub_indication = None;
                while let Some(key) = map.next_key::<String>()? {
                    // The TOML parser already rejects a key given twice.
                    match key.as_str() {
                        "indication" => indication = Some(map.next_value::<Indication>()?),
                        "sub-indication" => sub_indication = Some(map.next_value::<String>()?),
                        other => {
                            return Err(de::Error::unknown_field(
                                other,
                                &["indication", "sub-indication"],
                            ));
                        }
                    }
                }
                let indication =
                    indication.ok_or_else(|| de::Error::missing_field("indication"))?;
                Ok(RawDssResult::Indication {
                    indication,
                    sub_indication,
                })
            }
        }

        deserializer.deserialize_any(DssVisitor)
    }
}

/// Returns the value, or an error naming the field when it is blank.
fn non_empty(value: String, id: &str, field: &'static str) -> Result<String, ManifestError> {
    if value.trim().is_empty() {
        Err(ManifestError::EmptyField {
            id: id.to_owned(),
            field,
        })
    } else {
        Ok(value)
    }
}

/// Reports whether the value is a relative path, separated by `/`, whose
/// parts are portable file names on Linux, macOS and Windows: non-empty,
/// not `.` or `..`, made of letters, digits, `.`, `_` and `-`, not ending
/// with `.`, and not a Windows device name (CON, PRN, AUX, NUL, COM1 to
/// COM9, LPT1 to LPT9, and, to be safe, COM0 and LPT0).
/// Reports whether a path names a file that the corpus itself keeps at its
/// root, which an artefact must not overwrite.
fn corpus_file(path: &str) -> bool {
    ["manifest.toml", "README.md"]
        .iter()
        .any(|name| path.eq_ignore_ascii_case(name))
}

fn portable_relative(value: &str) -> bool {
    !value.is_empty() && value.split('/').all(portable_name)
}

fn portable_name(name: &str) -> bool {
    const RESERVED: [&str; 4] = ["CON", "PRN", "AUX", "NUL"];
    let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
    // A trailing dot also rules out "." and "..".
    if name.is_empty() || name.ends_with('.') || !name.chars().all(allowed) {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let numbered = stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit();
    !RESERVED.contains(&stem.as_str()) && !numbered
}

#[cfg(test)]
mod tests;
