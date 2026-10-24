//! The test PKI: a root CA, one issuing CA per signature family, end-entity
//! signing certificates, a timestamping authority, an OCSP responder, and
//! validity and misconfiguration cases, all tied to the fixed validation
//! time of the manifest (ADR-0014). Every certificate is assembled by the
//! `x509-cert` certificate builder (ADR-0021).
//!
//! Generation is reproducible. Keys are derived from their names with
//! a deterministic generator, SHA-256 in counter mode, RSA PKCS#1 v1.5, ECDSA (RFC 6979) and Ed25519
//! signatures are deterministic, and RSASSA-PSS salts are derived from the
//! signed data. Running the generator twice with the same validation time
//! and the same `Cargo.lock` gives the same files, byte for byte.

pub mod hierarchy;
pub mod issue;
pub mod keys;
pub(crate) mod rng;

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use der::pem::LineEnding;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::manifest::{Artefact, DssResult, Kind, Links, Manifest, ManifestError, OpensslResult};
use hierarchy::{CERTIFICATES, CertSpec};
use issue::Issuer;
use keys::KeyPair;

/// The directory of the test PKI, relative to the manifest.
pub const DIRECTORY: &str = "pki";

/// The directory of the private keys, relative to the manifest.
pub const KEY_DIRECTORY: &str = "pki/keys";

/// The suffix of every private-key file.
pub const KEY_SUFFIX: &str = ".test-key.pem";

/// An error found while generating the test PKI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PkiError {
    /// A key pair cannot be generated.
    KeyGeneration,
    /// A value cannot be encoded.
    Encoding,
    /// A signature cannot be computed.
    Signing,
    /// A key cannot sign with the requested algorithm.
    KeyMismatch,
    /// A time is out of range.
    Time,
    /// A certificate names an issuer that is not issued before it.
    UnknownIssuer(String),
}

impl fmt::Display for PkiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyGeneration => f.write_str("a key pair cannot be generated"),
            Self::Encoding => f.write_str("a value cannot be encoded"),
            Self::Signing => f.write_str("a signature cannot be computed"),
            Self::KeyMismatch => f.write_str("a key cannot sign with the requested algorithm"),
            Self::Time => f.write_str("a certificate time is out of range"),
            Self::UnknownIssuer(name) => {
                write!(
                    f,
                    "the issuer \"{name}\" is not issued before its certificates"
                )
            }
        }
    }
}

impl std::error::Error for PkiError {}

/// A generated file and its manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    /// The manifest entry, with the digest of `contents`.
    pub artefact: Artefact,
    /// The contents of the file.
    pub contents: Vec<u8>,
}

/// The identifier of the certificate with this name.
pub fn certificate_id(name: &str) -> String {
    format!("{DIRECTORY}/{name}")
}

/// The identifier of the private key of the certificate with this name.
pub fn key_id(name: &str) -> String {
    format!("{KEY_DIRECTORY}/{name}")
}

/// Generates every certificate and private key of the test PKI, in the
/// order of [`CERTIFICATES`], each certificate followed by its key.
///
/// # Errors
///
/// Returns a [`PkiError`] if a key, certificate or file cannot be produced.
pub fn generate(validation_time: OffsetDateTime) -> Result<Vec<GeneratedFile>, PkiError> {
    let mut issued: HashMap<&str, (KeyPair, Vec<u8>)> = HashMap::new();
    let mut files = Vec::with_capacity(2 * CERTIFICATES.len());
    for spec in &CERTIFICATES {
        let key = KeyPair::derive(spec.key, spec.name)?;
        let certificate = match spec.issuer {
            Some(name) => {
                let unknown = || PkiError::UnknownIssuer(name.to_owned());
                let issuer_spec = hierarchy::find(name).ok_or_else(unknown)?;
                let (issuer_key, issuer_certificate) = issued.get(name).ok_or_else(unknown)?;
                let issuer = Issuer {
                    spec: issuer_spec,
                    key: issuer_key,
                    certificate: issuer_certificate,
                };
                issue::issue(spec, &key, Some(&issuer), validation_time)?
            }
            None => issue::issue(spec, &key, None, validation_time)?,
        };
        files.push(certificate_file(spec, &certificate)?);
        files.push(key_file(spec, &key)?);
        issued.insert(spec.name, (key, certificate));
    }
    Ok(files)
}

fn certificate_file(spec: &CertSpec, certificate: &[u8]) -> Result<GeneratedFile, PkiError> {
    let pem = der::pem::encode_string("CERTIFICATE", LineEnding::LF, certificate)
        .map_err(|_| PkiError::Encoding)?;
    let chain = hierarchy::chain(spec)?
        .iter()
        .map(|issuer| certificate_id(issuer.name))
        .collect::<Vec<_>>();
    let expected = spec.expected_dss;
    let artefact = Artefact {
        id: certificate_id(spec.name),
        path: PathBuf::from(format!("{DIRECTORY}/{}.pem", spec.name)),
        sha256: sha256_hex(pem.as_bytes()),
        kind: Kind::Certificate,
        purpose: spec.purpose.to_owned(),
        expected_openssl: spec.expected_openssl,
        expected_dss: DssResult::Indication {
            indication: expected.indication,
            sub_indication: expected.sub_indication.map(str::to_owned),
        },
        links: Links {
            issuer: chain.first().cloned(),
            chain,
            revocation: Vec::new(),
            content: None,
        },
        notes: spec.notes.map(str::to_owned),
    };
    Ok(GeneratedFile {
        artefact,
        contents: pem.into_bytes(),
    })
}

fn key_file(spec: &CertSpec, key: &KeyPair) -> Result<GeneratedFile, PkiError> {
    let pem = key.pkcs8_pem()?;
    let artefact = Artefact {
        id: key_id(spec.name),
        path: PathBuf::from(format!("{KEY_DIRECTORY}/{}{KEY_SUFFIX}", spec.name)),
        sha256: sha256_hex(pem.as_bytes()),
        kind: Kind::PrivateKey,
        purpose: format!(
            "PKCS#8 private key of {}, a test key with no value.",
            certificate_id(spec.name)
        ),
        expected_openssl: OpensslResult::Parsed,
        expected_dss: DssResult::NotApplicable,
        links: Links::default(),
        notes: None,
    };
    Ok(GeneratedFile {
        artefact,
        contents: pem.into_bytes(),
    })
}

/// The SHA-256 digest of `data`, as 64 lower-case hexadecimal digits.
pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// An error found while writing the test PKI into the corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateError {
    /// The manifest cannot be read, or would not be valid once updated.
    Manifest(ManifestError),
    /// The test PKI cannot be generated.
    Pki(PkiError),
    /// A file cannot be written.
    Io(String),
}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(error) => error.fmt(f),
            Self::Pki(error) => error.fmt(f),
            Self::Io(message) => write!(f, "a file cannot be written: {message}"),
        }
    }
}

impl std::error::Error for GenerateError {}

/// What [`write_into_corpus`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// The number of files written.
    pub written: usize,
    /// The identifiers of the manifest entries removed because the
    /// generator no longer produces them.
    pub removed: Vec<String>,
    /// Files under the PKI directory that no manifest entry names, as
    /// paths relative to the manifest's directory. They are left in place.
    pub unlisted: Vec<String>,
}

/// Reports whether an entry belongs to what `generate pki` produces: a
/// certificate or private key whose identifier is under [`DIRECTORY`].
fn generated_here(artefact: &Artefact) -> bool {
    artefact.id.starts_with(&format!("{DIRECTORY}/"))
        && matches!(artefact.kind, Kind::Certificate | Kind::PrivateKey)
}

/// Generates the test PKI with the validation time of the manifest at
/// `manifest_path`, writes each file under the manifest's directory, and
/// records each in the manifest.
///
/// Entries with the same identifiers are replaced. Certificate and private
/// key entries under [`DIRECTORY`] that the generator no longer produces
/// are removed; their files are not deleted. Other entries are kept. The
/// manifest is written anew, without any comment added by hand, and last,
/// through a temporary file renamed over it, after every other step that
/// can fail, so that a failure leaves the previous manifest in place.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the manifest cannot be read or updated,
/// or a file cannot be generated or written.
pub fn write_into_corpus(manifest_path: &Path) -> Result<Summary, GenerateError> {
    let mut manifest = Manifest::load(manifest_path).map_err(GenerateError::Manifest)?;
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let files = generate(manifest.header.validation_time).map_err(GenerateError::Pki)?;
    let generated: Vec<&str> = files.iter().map(|f| f.artefact.id.as_str()).collect();
    let mut removed = Vec::new();
    manifest.artefacts.retain(|artefact| {
        let stale = generated_here(artefact) && !generated.contains(&artefact.id.as_str());
        if stale {
            removed.push(artefact.id.clone());
        }
        !stale
    });
    for file in &files {
        manifest.upsert(file.artefact.clone());
    }
    let text = manifest.to_toml();
    // The updated manifest must itself be valid before anything is written.
    Manifest::parse(&text).map_err(GenerateError::Manifest)?;
    let io = |path: &Path, error: std::io::Error| {
        GenerateError::Io(format!("{}: {error}", path.display()))
    };
    for file in &files {
        let path = root.join(&file.artefact.path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
        }
        std::fs::write(&path, &file.contents).map_err(|e| io(&path, e))?;
    }
    // The scan runs before the manifest is replaced, so that every step
    // that can fail leaves the previous manifest in place.
    let listed: Vec<String> = manifest
        .artefacts
        .iter()
        .map(|a| a.path.to_string_lossy().into_owned())
        .collect();
    let mut unlisted = Vec::new();
    collect_files(root, Path::new(DIRECTORY), &mut unlisted).map_err(|e| io(root, e))?;
    unlisted.retain(|path| !listed.contains(path) && !path.ends_with("/README.md"));
    unlisted.sort();
    let temporary = manifest_path.with_extension("toml.tmp");
    std::fs::write(&temporary, text).map_err(|e| io(&temporary, e))?;
    if let Err(error) = std::fs::rename(&temporary, manifest_path) {
        let _ = std::fs::remove_file(&temporary);
        return Err(io(manifest_path, error));
    }
    Ok(Summary {
        written: files.len(),
        removed,
        unlisted,
    })
}

/// Collects the files under `root/relative`, as `/`-separated paths
/// relative to `root`.
fn collect_files(root: &Path, relative: &Path, out: &mut Vec<String>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let path = relative.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            collect_files(root, &path, out)?;
        } else {
            let parts: Vec<String> = path
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            out.push(parts.join("/"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
