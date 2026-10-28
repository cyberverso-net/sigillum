//! Malformed variants of the signed corpus, under `mutations/`.
//!
//! ADR-0014 of the sigillum documentation has `sigillum-testpki` produce
//! malformed signed documents by mutating signatures that DSS created. Each
//! variant here derives from one committed signature of `signed/`: the
//! mutation changes bytes of that file and computes no new signature value.
//! The mutations are pure functions of their source, so the variants are
//! reproduced byte for byte from the committed corpus, without Java.
//!
//! The variants of this module are two CAdES signatures, one with a
//! modified signed attribute and one with modified encapsulated content
//! and intact signed attributes, and two JAdES signatures in the JWS compact serialisation
//! (RFC 7515, section 7.1): one with a tampered protected header, one with
//! a protected header parameter given twice. The PAdES variants are added
//! by #112.

use std::fmt;
use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};

use crate::manifest::{Artefact, Divergence, DssResult, Indication, Kind, Manifest, OpensslResult};
use crate::pki::{self, GenerateError, GeneratedFile, Summary, sha256_hex};

/// The directory of the variants, relative to the manifest.
pub const DIRECTORY: &str = "mutations";

/// A variant of a signature of the signed corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// CAdES with a modified signed attribute: the signing time.
    CadesModifiedSignedAttribute,
    /// CAdES with its encapsulated content changed and its signed
    /// attributes intact.
    CadesModifiedContent,
    /// JAdES with a tampered protected header: `iat`, the signing time.
    JadesTamperedHeader,
    /// JAdES with a protected header parameter, `iat`, given twice.
    JadesDuplicateHeaderParameter,
}

/// The variants, in the order of the corpus.
pub const MUTATIONS: [Mutation; 4] = [
    Mutation::CadesModifiedSignedAttribute,
    Mutation::CadesModifiedContent,
    Mutation::JadesTamperedHeader,
    Mutation::JadesDuplicateHeaderParameter,
];

/// The JAdES signature that both JAdES variants derive from.
const JADES_SOURCE: &str = "signed/jades-compact-b-b-p256";

impl Mutation {
    /// The name in the identifier.
    fn name(self) -> &'static str {
        match self {
            Self::CadesModifiedSignedAttribute => "cades-modified-signed-attribute",
            Self::CadesModifiedContent => "cades-modified-content",
            Self::JadesTamperedHeader => "jades-tampered-header",
            Self::JadesDuplicateHeaderParameter => "jades-duplicate-header-parameter",
        }
    }

    /// The identifier, such as `mutations/jades-tampered-header`.
    pub fn id(self) -> String {
        format!("{DIRECTORY}/{}", self.name())
    }

    /// The path, relative to the manifest, with the extension of the source.
    pub fn path(self) -> PathBuf {
        let extension = match self {
            Self::CadesModifiedSignedAttribute | Self::CadesModifiedContent => "p7m",
            Self::JadesTamperedHeader | Self::JadesDuplicateHeaderParameter => "jws",
        };
        PathBuf::from(format!("{}.{extension}", self.id()))
    }

    /// The identifier of the signature of the signed corpus it derives from.
    pub fn source(self) -> &'static str {
        match self {
            Self::CadesModifiedSignedAttribute | Self::CadesModifiedContent => {
                "signed/cades-enveloping-b-b-p256"
            }
            Self::JadesTamperedHeader | Self::JadesDuplicateHeaderParameter => JADES_SOURCE,
        }
    }

    /// Derives the variant from the contents of its source.
    ///
    /// # Errors
    ///
    /// Returns [`Unsupported`] when the source lacks a structure that the
    /// mutation needs.
    pub fn apply(self, source: &[u8]) -> Result<Vec<u8>, Unsupported> {
        match self {
            Self::CadesModifiedSignedAttribute => modify_signing_time(source),
            Self::CadesModifiedContent => modify_encapsulated_content(source),
            Self::JadesTamperedHeader => tamper_protected_header(source),
            Self::JadesDuplicateHeaderParameter => duplicate_protected_header_parameter(source),
        }
    }

    /// The manifest entry of the variant, whose file holds `contents`,
    /// derived from the entry of its source: the same links, so that DSS
    /// validates it with the same files.
    pub fn artefact(self, source: &Artefact, contents: &[u8]) -> Artefact {
        let failed = |sub: &str| DssResult::Indication {
            indication: Indication::TotalFailed,
            sub_indication: Some(sub.to_owned()),
        };
        let (purpose, expected_openssl, expected_dss, dss_divergence, notes) = match self {
            Self::CadesModifiedSignedAttribute => (
                format!(
                    "CAdES signature {}, with the signing time in its signed attributes moved one second later after signing.",
                    source.id
                ),
                OpensslResult::Rejected,
                failed("SIG_CRYPTO_FAILURE"),
                None,
                "The signing-time attribute (RFC 5652, section 11.3) holds 291216100001Z instead of 291216100000Z, and the signature value was not computed again. The DSS result is a prediction from ETSI EN 319 102-1 V1.4.1, clause 5.2.7.4: the content still matches the message-digest attribute (step 2), but the signature value no longer verifies over the changed signed attributes, so step 4 returns FAILED with SIG_CRYPTO_FAILURE from the building block. The validation process for basic signatures returns that result (clause 5.3.4, step 5), reported as TOTAL-FAILED with SIG_CRYPTO_FAILURE (clause 5.1.3, Table 6). DSS 6.5.1 gives this result in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only. openssl cms -verify rejects the signature for the same reason.",
            ),
            Self::CadesModifiedContent => (
                format!(
                    "CAdES signature {}, with the first octet of its encapsulated content changed after signing and its signed attributes intact.",
                    source.id
                ),
                OpensslResult::Rejected,
                failed("HASH_FAILURE"),
                None,
                "The eContent of the encapsulated content starts with S instead of s, and nothing else changed: the signed attributes, and so the signature value over them, still verify, but the message-digest attribute (RFC 5652, section 11.2) no longer matches the digest of the content. The DSS result is a prediction from ETSI EN 319 102-1 V1.4.1: the hash of a signed data item does not match the corresponding hash value in the signature (clause 5.2.7.3, Table 15, and Table 6), so step 2 of clause 5.2.7.4 returns FAILED with HASH_FAILURE from the building block. The validation process for basic signatures returns that result (clause 5.3.4, step 5), reported as TOTAL-FAILED with HASH_FAILURE (clause 5.1.3, Table 6). DSS 6.5.1 gives this result in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only. openssl cms -verify rejects the signature because the content does not match the message digest.",
            ),
            Self::JadesTamperedHeader => (
                format!(
                    "JAdES signature {}, with iat in its protected header moved one second later after signing.",
                    source.id
                ),
                OpensslResult::NotApplicable,
                failed("SIG_CRYPTO_FAILURE"),
                Some(Divergence {
                    entry: "DIV-6".to_owned(),
                    indication: Indication::TotalFailed,
                    sub_indication: Some("HASH_FAILURE".to_owned()),
                }),
                "The protected header holds iat 1892109601 instead of 1892109600, and the signature value was not computed again. The DSS result is a prediction from ETSI EN 319 102-1 V1.4.1. HASH_FAILURE means that the hash of a signed data item does not match the corresponding hash value in the signature (clause 5.2.7.3, Table 15, and Table 6), and this JWS carries no hash value of its payload, which is unchanged. Its signature value covers the JWS Signing Input, protected header included (RFC 7515, section 5.2, step 8), and no longer verifies, so step 4 of clause 5.2.7.4 returns FAILED with SIG_CRYPTO_FAILURE from the building block. The validation process for basic signatures returns that result (clause 5.3.4, step 5), reported as TOTAL-FAILED with SIG_CRYPTO_FAILURE (clause 5.1.3, Table 6). Clause 5.2.7.4 leaves its first two steps to the signature type, and refers to the CAdES, XAdES and PAdES standards and RFC 3852, not to ETSI TS 119 182-1. DSS 6.5.1 gives TOTAL-FAILED with HASH_FAILURE instead, in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023): it treats the JWS Signing Input as a reference whose data is not intact. The difference is the divergence DIV-6 of docs/design/divergences.md.",
            ),
            Self::JadesDuplicateHeaderParameter => (
                format!(
                    "JAdES signature {}, with a second iat, one day later, added to its protected header after signing.",
                    source.id
                ),
                OpensslResult::NotApplicable,
                DssResult::Rejected,
                None,
                "The protected header holds iat twice, 1892109600 and then 1892196000, and the signature value was not computed again (ADR-0014). RFC 7515, section 4, lets a JWS parser reject duplicate Header Parameter names or keep the lexically last one. DSS 6.5.1 rejects the JWS, so the validate-document mode of tools/dss-oracle gives rejected, and sigillum rejects them under ADR-0016. Because the header changed, the signature value no longer verifies either: a verifier that keeps the last iat fails on the signature, so the fixture alone does not show that a verifier checks for duplicate names.",
            ),
        };
        Artefact {
            id: self.id(),
            path: self.path(),
            sha256: sha256_hex(contents),
            kind: Kind::SignedDocument,
            purpose,
            expected_openssl,
            expected_dss,
            links: source.links.clone(),
            notes: Some(notes.to_owned()),
            dss_divergence,
            attack_class: None,
        }
    }
}

/// Why a mutation cannot apply to its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported(pub &'static str);

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Unsupported {}

/// The largest CMS signature that the CMS mutations read, in bytes. The
/// CAdES signatures of the corpus are a few kilobytes long.
pub const MAX_CMS_LEN: usize = 1024 * 1024;

/// The largest source file that [`generate`] reads, in bytes, which covers
/// every signature of the signed corpus with a wide margin.
pub const MAX_SOURCE_LEN: usize = 4 * 1024 * 1024;

/// Refuses a CMS signature longer than [`MAX_CMS_LEN`], before anything is
/// allocated for it.
fn check_cms_len(cms: &[u8]) -> Result<(), Unsupported> {
    if cms.len() > MAX_CMS_LEN {
        Err(Unsupported(
            "the CMS signature is longer than the limit of 1 MiB",
        ))
    } else {
        Ok(())
    }
}

/// The DER encoding of the object identifier of the signing-time attribute,
/// 1.2.840.113549.1.9.5 (RFC 5652, section 11.3).
const SIGNING_TIME_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05,
];

/// Moves the signing time in the signed attributes of a CMS signature one
/// second later, by changing the last digit of its seconds, without
/// changing any length: 0 to 8 become one more, 9 becomes 8.
///
/// The attribute is found by a scan for the bytes of its identifier, not by
/// a structural parse of the CMS signature: the corpus sources, whose
/// digests [`generate`] checks first, hold it once. The input is at most
/// [`MAX_CMS_LEN`] bytes, and must hold the identifier of the
/// signing-time attribute once,
/// followed by a SET of one UTCTime or GeneralizedTime of the form that DER
/// requires, `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ` (RFC 5652, section 11.3).
///
/// # Errors
///
/// Returns [`Unsupported`] when the attribute is missing, given more than
/// once, or not of that form.
pub fn modify_signing_time(cms: &[u8]) -> Result<Vec<u8>, Unsupported> {
    check_cms_len(cms)?;
    let mut found = cms
        .windows(SIGNING_TIME_OID.len())
        .enumerate()
        .filter(|(_, window)| *window == SIGNING_TIME_OID)
        .map(|(at, _)| at + SIGNING_TIME_OID.len());
    let (Some(value), None) = (found.next(), found.next()) else {
        return Err(Unsupported(
            "the CMS signature does not hold the signing-time attribute exactly once",
        ));
    };
    let malformed = Unsupported("the signing-time attribute is not a SET of one DER time");
    let header = cms.get(value..value + 4).ok_or(malformed)?;
    let length = match header {
        [0x31, 0x0f, 0x17, 0x0d] => 13,
        [0x31, 0x11, 0x18, 0x0f] => 15,
        _ => return Err(malformed),
    };
    let start = value + 4;
    let time = cms.get(start..start + length).ok_or(malformed)?;
    let (digits, zone) = time.split_at(length - 1);
    if zone != b"Z" || !digits.iter().all(u8::is_ascii_digit) {
        return Err(malformed);
    }
    let mut out = cms.to_vec();
    let last = start + length - 2;
    out[last] = if out[last] == b'9' {
        b'8'
    } else {
        out[last] + 1
    };
    Ok(out)
}

/// The DER encoding of the object identifier id-data,
/// 1.2.840.113549.1.7.1 (RFC 5652, section 4).
const ID_DATA_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];

/// Changes the first octet of the encapsulated content of a CMS signature,
/// by flipping its bit 0x20, so that `s` becomes `S`, without changing
/// any length. The signed attributes are left intact.
///
/// The content is found by a scan for the bytes of id-data followed by a
/// `[0]` tag, not by a structural parse of the CMS signature: the corpus
/// sources, whose digests [`generate`] checks first, hold them once. The
/// input is at most [`MAX_CMS_LEN`] bytes, and must hold id-data followed
/// by a `[0]` tag once: the
/// `eContentType` and `eContent` of an encapsulated content (RFC 5652,
/// section 5.2). `eContent` must be a primitive OCTET STRING of at least
/// one octet, with DER lengths of at most two octets after the first.
///
/// # Errors
///
/// Returns [`Unsupported`] when the encapsulated content is missing,
/// given more than once, or not of that form.
pub fn modify_encapsulated_content(cms: &[u8]) -> Result<Vec<u8>, Unsupported> {
    check_cms_len(cms)?;
    let mut found = cms
        .windows(ID_DATA_OID.len() + 1)
        .enumerate()
        .filter(|(_, window)| {
            window[..ID_DATA_OID.len()] == ID_DATA_OID && window[ID_DATA_OID.len()] == 0xa0
        })
        .map(|(at, _)| at + ID_DATA_OID.len() + 1);
    let (Some(outer), None) = (found.next(), found.next()) else {
        return Err(Unsupported(
            "the CMS signature does not hold encapsulated content of type id-data exactly once",
        ));
    };
    let malformed =
        Unsupported("the encapsulated content is not a primitive OCTET STRING with DER lengths");
    let (outer_length, octets) = der_length(cms, outer).ok_or(malformed)?;
    if cms.get(octets) != Some(&0x04) {
        return Err(malformed);
    }
    let (length, start) = der_length(cms, octets + 1).ok_or(malformed)?;
    if outer_length != start - octets + length || start + length > cms.len() {
        return Err(malformed);
    }
    if length == 0 {
        return Err(Unsupported("the encapsulated content is empty"));
    }
    let mut out = cms.to_vec();
    out[start] ^= 0x20;
    Ok(out)
}

/// Reads the DER length at `at`, in the short form or the long form of
/// one or two octets, and returns it with the position after it.
fn der_length(bytes: &[u8], at: usize) -> Option<(usize, usize)> {
    let first = *bytes.get(at)?;
    let (length, after) = match first {
        0..=0x7f => (usize::from(first), at + 1),
        0x81 => (usize::from(*bytes.get(at + 1)?), at + 2),
        0x82 => (
            usize::from(u16::from_be_bytes([
                *bytes.get(at + 1)?,
                *bytes.get(at + 2)?,
            ])),
            at + 3,
        ),
        _ => return None,
    };
    // DER: the shortest form.
    let minimal = match first {
        0x81 => length >= 0x80,
        0x82 => length >= 0x100,
        _ => true,
    };
    minimal.then_some((length, after))
}

/// One day, in seconds: the distance of the second `iat`.
const DAY: u64 = 86_400;

/// Moves `iat` in the protected header of a compact JWS one second later,
/// without a new signature value.
///
/// # Errors
///
/// Returns [`Unsupported`] when the input is not a compact JWS whose
/// protected header holds one `iat`, as described under
/// [`duplicate_protected_header_parameter`].
pub fn tamper_protected_header(jws: &[u8]) -> Result<Vec<u8>, Unsupported> {
    let parts = CompactJws::parse(jws)?;
    let iat = parts.iat()?;
    let next = iat
        .value
        .checked_add(1)
        .ok_or(Unsupported("iat is too large"))?;
    let header = format!(
        "{}{next}{}",
        &parts.header[..iat.start],
        &parts.header[iat.end..]
    );
    Ok(parts.with_header(&header))
}

/// Adds a second `iat`, one day later than the first, at the end of the
/// protected header of a compact JWS, without a new signature value.
///
/// The input must be a JWS in the compact serialisation (RFC 7515, section
/// 7.1) of at most [`MAX_JWS_LEN`] bytes: three parts separated by `.`,
/// none empty, the first the unpadded base64url encoding of at most
/// [`MAX_HEADER_LEN`] bytes. They must be a JSON object without white space
/// around it and without escape sequences, whose members have distinct
/// names, one of them `iat` with a non-negative integer value. Only that
/// member of the outer object is read or changed.
///
/// # Errors
///
/// Returns [`Unsupported`] when the input is not of that form.
pub fn duplicate_protected_header_parameter(jws: &[u8]) -> Result<Vec<u8>, Unsupported> {
    let parts = CompactJws::parse(jws)?;
    let iat = parts.iat()?;
    let later = iat
        .value
        .checked_add(DAY)
        .ok_or(Unsupported("iat is too large"))?;
    let stem = parts
        .header
        .strip_suffix('}')
        .ok_or(Unsupported("the protected header does not end with }"))?;
    Ok(parts.with_header(&format!("{stem},\"iat\":{later}}}")))
}

/// The largest JWS that the JWS mutations read, in bytes. The JWS of the
/// corpus are a few kilobytes long.
pub const MAX_JWS_LEN: usize = 1024 * 1024;

/// The largest protected header that the JWS mutations decode, in bytes
/// after base64url decoding.
pub const MAX_HEADER_LEN: usize = 64 * 1024;

/// A JWS in the compact serialisation, with its protected header decoded.
struct CompactJws<'a> {
    /// The protected header, as JSON text.
    header: String,
    /// The payload and the signature, as encoded, with the `.` between them.
    rest: &'a str,
}

/// The integer value of `iat` in a protected header, and where its digits are.
struct Iat {
    value: u64,
    start: usize,
    end: usize,
}

/// The length of the base64url encoding, without padding, of
/// [`MAX_HEADER_LEN`] bytes.
const MAX_ENCODED_HEADER_LEN: usize = (MAX_HEADER_LEN * 4).div_ceil(3);

impl<'a> CompactJws<'a> {
    /// Reads a JWS of at most [`MAX_JWS_LEN`] bytes, whose protected header
    /// decodes to at most [`MAX_HEADER_LEN`] bytes, before anything is
    /// allocated for it.
    fn parse(jws: &'a [u8]) -> Result<Self, Unsupported> {
        if jws.len() > MAX_JWS_LEN {
            return Err(Unsupported("the JWS is longer than the limit of 1 MiB"));
        }
        let not_compact = Unsupported("the input is not a JWS in the compact serialisation");
        let text = std::str::from_utf8(jws).map_err(|_| not_compact)?;
        let mut parts = text.splitn(4, '.');
        let (Some(header), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(not_compact);
        };
        if [header, payload, signature].iter().any(|p| p.is_empty()) {
            return Err(not_compact);
        }
        if header.len() > MAX_ENCODED_HEADER_LEN {
            return Err(Unsupported(
                "the protected header is longer than the limit of 64 KiB",
            ));
        }
        let rest = &text[header.len() + 1..];
        let decoded = Base64UrlUnpadded::decode_vec(header)
            .map_err(|_| Unsupported("the protected header is not unpadded base64url"))?;
        let header = String::from_utf8(decoded)
            .map_err(|_| Unsupported("the protected header is not UTF-8"))?;
        // Without escapes, every name is written as it decodes, so the
        // names read from the text are the names of the object.
        if header.contains('\\') {
            return Err(Unsupported("the protected header holds an escape sequence"));
        }
        let object =
            Unsupported("the protected header is not a JSON object without white space around it");
        if !header.starts_with('{') || !header.ends_with('}') {
            return Err(object);
        }
        serde_json::from_str::<serde_json::Value>(&header).map_err(|_| object)?;
        Ok(Self { header, rest })
    }

    /// Finds `iat` among the members of the outer object of the header,
    /// whose names must all differ, and reads its value, a non-negative
    /// integer. The header is valid JSON without escapes, so a string ends
    /// at the next quotation mark, and the members of nested objects and
    /// arrays are skipped.
    fn iat(&self) -> Result<Iat, Unsupported> {
        let text = self.header.as_str();
        let bytes = text.as_bytes();
        let mut names: Vec<&str> = Vec::new();
        let mut found = None;
        let mut depth = 0usize;
        let mut expect_name = false;
        let mut at = 0;
        while let Some(&byte) = bytes.get(at) {
            match byte {
                b'"' => {
                    // Valid JSON: every string is closed.
                    let Some(length) = text[at + 1..].find('"') else {
                        break;
                    };
                    let end = at + 1 + length;
                    if depth == 1 && expect_name {
                        let name = &text[at + 1..end];
                        if names.contains(&name) {
                            return Err(Unsupported(
                                "the protected header gives a name more than once",
                            ));
                        }
                        names.push(name);
                        if name == "iat" {
                            found = Some(end + 1);
                        }
                        expect_name = false;
                    }
                    at = end;
                }
                // A name follows an opening brace or a comma. Only names
                // at depth 1 are read; a value at depth 1 always follows
                // its name, which clears the flag.
                b'{' => {
                    depth += 1;
                    expect_name = true;
                }
                b'[' => depth += 1,
                b'}' | b']' => depth = depth.saturating_sub(1),
                b',' => expect_name = true,
                _ => {}
            }
            at += 1;
        }
        let after_name = found.ok_or(Unsupported(
            "the protected header has no iat at the top level",
        ))?;
        let skip = |from: usize| {
            from + text[from..]
                .bytes()
                .take_while(u8::is_ascii_whitespace)
                .count()
        };
        // Valid JSON: only white space and a colon follow the name.
        let start = skip(skip(after_name) + 1);
        let end = start + text[start..].bytes().take_while(u8::is_ascii_digit).count();
        let not_integer = Unsupported("iat is not a non-negative integer");
        let value: u64 = text[start..end].parse().map_err(|_| not_integer)?;
        if !matches!(bytes.get(skip(end)), Some(b',' | b'}')) {
            return Err(not_integer);
        }
        Ok(Iat { value, start, end })
    }

    /// The JWS with `header` as its protected header.
    fn with_header(&self, header: &str) -> Vec<u8> {
        format!(
            "{}.{}",
            Base64UrlUnpadded::encode_string(header.as_bytes()),
            self.rest
        )
        .into_bytes()
    }
}

/// An error found while generating the variants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    /// The manifest does not list the source of a variant.
    NotInManifest(String),
    /// The file of a source differs from the digest in its manifest entry.
    DigestMismatch(String),
    /// A mutation cannot apply to its source.
    Mutation {
        /// The identifier of the variant.
        id: String,
        /// Why.
        reason: Unsupported,
    },
    /// A file cannot be read.
    Io(String),
}

impl fmt::Display for MutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInManifest(id) => write!(
                f,
                "the manifest does not list {id}, from which a malformed variant derives"
            ),
            Self::DigestMismatch(id) => write!(
                f,
                "the file of {id} differs from the sha256 of its manifest entry"
            ),
            Self::Mutation { id, reason } => {
                write!(f, "{id} cannot be derived from its source: {reason}")
            }
            Self::Io(message) => write!(
                f,
                "a source of the malformed variants cannot be read: {message}"
            ),
        }
    }
}

impl std::error::Error for MutationError {}

/// Reads a file of at most [`MAX_SOURCE_LEN`] bytes, without reading more.
fn read_limited(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_SOURCE_LEN as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SOURCE_LEN {
        return Err(std::io::Error::other("the file is larger than 4 MiB"));
    }
    Ok(bytes)
}

/// Reports whether an entry belongs to what `generate mutations` produces:
/// any entry whose identifier is under [`DIRECTORY`].
fn generated_here(artefact: &Artefact) -> bool {
    artefact.id.starts_with(&format!("{DIRECTORY}/"))
}

/// Derives every variant of [`MUTATIONS`] from the corpus under `root`,
/// listed in `manifest`. Each source must be listed, its file must be at
/// most [`MAX_SOURCE_LEN`] bytes, which is read without reading more, and
/// it must have the digest of its entry, so that a variant always derives
/// from the committed signature.
///
/// # Errors
///
/// Returns a [`MutationError`] if a source is missing, cannot be read,
/// differs from its entry or does not have the structure that its
/// mutation needs.
pub fn generate(root: &Path, manifest: &Manifest) -> Result<Vec<GeneratedFile>, MutationError> {
    let mut files = Vec::new();
    for mutation in MUTATIONS {
        let id = mutation.source();
        let source = manifest
            .artefacts
            .iter()
            .find(|a| a.id == id)
            .ok_or_else(|| MutationError::NotInManifest(id.to_owned()))?;
        let path = root.join(&source.path);
        let bytes = read_limited(&path)
            .map_err(|error| MutationError::Io(format!("{id}: {}: {error}", path.display())))?;
        if sha256_hex(&bytes) != source.sha256 {
            return Err(MutationError::DigestMismatch(id.to_owned()));
        }
        let contents = mutation
            .apply(&bytes)
            .map_err(|reason| MutationError::Mutation {
                id: mutation.id(),
                reason,
            })?;
        files.push(GeneratedFile {
            artefact: mutation.artefact(source, &contents),
            contents,
        });
    }
    Ok(files)
}

/// Derives the variants from the corpus of the manifest at
/// `manifest_path`, writes each under the manifest's directory, and records
/// each in the manifest, following the regeneration rules of
/// [`pki::write_into_corpus`]. Every entry under [`DIRECTORY`] belongs to
/// this generator. It runs after `generate signed`, whose signatures it
/// reads; when the manifest does not list one of them, or its file differs
/// from its entry, nothing is written.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the manifest cannot be read or updated,
/// a variant cannot be derived, or a file cannot be written.
pub fn write_into_corpus(manifest_path: &Path) -> Result<Summary, GenerateError> {
    let root = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    pki::write_generated(
        manifest_path,
        DIRECTORY,
        generated_here,
        |manifest| generate(root, manifest).map_err(GenerateError::Mutation),
        |_, _| {},
    )
}

#[cfg(test)]
mod tests;
