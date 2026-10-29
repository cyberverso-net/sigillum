//! Parsers of the untrusted input that the `tsa` subcommand reads: the
//! digest algorithm, the digest and the time given on the command line,
//! the key and certificate files, read up to [`MAX_FILE_LEN`] bytes, and
//! the start of a PEM file.
//!
//! Each accepts only the exact forms documented on it. They live in the
//! library so that the fuzz target `tsa_input` can reach them.

use std::fmt;
use std::io::Read;
use std::path::Path;

use time::OffsetDateTime;

use super::DigestAlgorithm;
use crate::manifest;

/// Parses a digest algorithm: `SHA-256`, `SHA-384` or `SHA-512`, in any
/// letter case and with or without the hyphen, or the object identifier
/// of one of them in canonical dotted form. An identifier with leading
/// zeros in an arc, such as `2.16.840.1.101.3.4.2.01`, is refused.
///
/// # Errors
///
/// Returns a message naming the supported algorithms for anything else.
pub fn digest_algorithm(value: &str) -> Result<DigestAlgorithm, String> {
    // The object identifier is compared as text with the three supported
    // ones, not parsed: the parser of const-oid 0.9.6 overflows on arcs
    // that do not fit in 32 bits, as the fuzz target tsa_input found.
    DigestAlgorithm::ALL
        .into_iter()
        .find(|algorithm| {
            let name = algorithm.name();
            value.eq_ignore_ascii_case(name)
                || value.eq_ignore_ascii_case(&name.replace('-', ""))
                || value == algorithm.oid().to_string()
        })
        .ok_or_else(|| {
            format!(
                "unsupported digest algorithm: {value}; use SHA-256, SHA-384, SHA-512 or their object identifiers"
            )
        })
}

/// Parses a digest: a non-empty, even number of hexadecimal digits, in
/// either letter case.
///
/// # Errors
///
/// Returns a message for any other text.
pub fn hex_digest(value: &str) -> Result<Vec<u8>, String> {
    let error = || format!("not an even number of hexadecimal digits: {value}");
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(error());
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .filter(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(error)
}

/// Parses a time with the rule of the manifest's `validation-time`,
/// `YYYY-MM-DDTHH:MM:SSZ`, and refuses times before 1970, which a
/// `genTime` here cannot hold.
///
/// # Errors
///
/// Returns a message for any other text.
pub fn time(value: &str) -> Result<OffsetDateTime, String> {
    manifest::utc_time(value)
        .filter(|time| time.unix_timestamp() >= 0)
        .ok_or_else(|| format!("not a time of the form YYYY-MM-DDTHH:MM:SSZ from 1970: {value}"))
}

/// The largest key or certificate file that `tsa` reads, 64 KiB. A PEM or
/// DER key or certificate of the test PKI takes a few kilobytes, so the
/// limit is generous, and it keeps an oversized file from exhausting memory.
pub const MAX_FILE_LEN: u64 = 64 * 1024;

/// An error found while reading a key or certificate file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    /// The file cannot be opened or read.
    Io(String),
    /// The file is larger than the limit, in bytes.
    TooLarge(u64),
}

impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => f.write_str(message),
            Self::TooLarge(limit) => write!(f, "the file is larger than {limit} bytes"),
        }
    }
}

impl std::error::Error for FileError {}

/// Reads a key or certificate file of at most [`MAX_FILE_LEN`] bytes.
///
/// # Errors
///
/// Returns [`FileError::Io`] if the file cannot be read, and
/// [`FileError::TooLarge`] if it is longer than the limit.
pub fn read_file(path: &Path) -> Result<Vec<u8>, FileError> {
    let file = std::fs::File::open(path).map_err(|e| FileError::Io(e.to_string()))?;
    read_limited(file, MAX_FILE_LEN)
}

/// Reads at most `limit` bytes from `reader`. It reads one byte more than
/// the limit, and no further, to tell whether the input is longer.
///
/// # Errors
///
/// Returns [`FileError::Io`] if reading fails, and [`FileError::TooLarge`]
/// if the input is longer than `limit` bytes.
pub fn read_limited(reader: impl Read, limit: u64) -> Result<Vec<u8>, FileError> {
    let mut contents = Vec::new();
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|e| FileError::Io(e.to_string()))?;
    if u64::try_from(contents.len()).map_or(true, |len| len > limit) {
        return Err(FileError::TooLarge(limit));
    }
    Ok(contents)
}

/// The deepest nesting of constructed values that [`check_der`] accepts.
/// A certificate of the test PKI nests about ten deep.
pub const MAX_DER_DEPTH: usize = 32;

/// Why [`check_der`] refused an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerError {
    /// A tag, length or content runs past its parent or the input.
    Truncated,
    /// A length has the indefinite form, which DER forbids (X.690,
    /// clause 10.1).
    IndefiniteLength,
    /// A length has more than four octets.
    LengthTooLong,
    /// A high tag number has more than four octets.
    TagTooLong,
    /// Constructed values are nested more than [`MAX_DER_DEPTH`] deep.
    TooDeep,
    /// Bytes follow the outermost value.
    TrailingData,
}

impl fmt::Display for DerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "a DER length exceeds the bytes available",
            Self::IndefiniteLength => "a DER value has an indefinite length",
            Self::LengthTooLong => "a DER length has more than four octets",
            Self::TagTooLong => "a DER tag has more than four octets",
            Self::TooDeep => "DER values are nested more than 32 deep",
            Self::TrailingData => "bytes follow the DER value",
        })
    }
}

impl std::error::Error for DerError {}

/// Checks that `input` is one DER value whose every length, at every
/// level of nesting, fits in its parent and in the input.
///
/// der 0.7.10 decodes owned values, such as the `INTEGER` of a serial
/// number, with `Reader::read_vec`, which allocates the declared length
/// before it checks that the input holds that many bytes. A few bytes could
/// then request hundreds of megabytes. Once this check passes, no declared
/// length exceeds the input, so decoding allocates at most about the size
/// of the input. The check borrows the input and allocates nothing.
///
/// It reads the identifier and length octets of X.690, clauses 8.1.2 and
/// 8.1.3, with definite lengths of at most four octets and tags of at most
/// four octets, and descends into constructed values to a depth of
/// [`MAX_DER_DEPTH`]. It does not check the contents themselves, which the
/// decoder then does.
///
/// # Errors
///
/// Returns a [`DerError`] for the first length or tag it refuses.
pub fn check_der(input: &[u8]) -> Result<(), DerError> {
    if check_value(input, 0)?.is_empty() {
        Ok(())
    } else {
        Err(DerError::TrailingData)
    }
}

/// Checks the value at the start of `input`, nested `depth` deep, and
/// returns the bytes that follow it.
fn check_value(input: &[u8], depth: usize) -> Result<&[u8], DerError> {
    let (&identifier, mut rest) = input.split_first().ok_or(DerError::Truncated)?;
    // X.690, clause 8.1.2.4: a tag number of 31 or more follows in
    // subsequent octets, the last with bit 8 clear.
    if identifier & 0x1f == 0x1f {
        let mut octets = 0;
        loop {
            let (&octet, next) = rest.split_first().ok_or(DerError::Truncated)?;
            rest = next;
            octets += 1;
            if octets > 4 {
                return Err(DerError::TagTooLong);
            }
            if octet & 0x80 == 0 {
                break;
            }
        }
    }
    // X.690, clause 8.1.3: the short form, or the long form with the
    // number of length octets in bits 7 to 1 of the first.
    let (&first, next) = rest.split_first().ok_or(DerError::Truncated)?;
    rest = next;
    let len = match first {
        0x80 => return Err(DerError::IndefiniteLength),
        0x00..=0x7f => usize::from(first),
        _ => {
            let count = usize::from(first & 0x7f);
            if count > 4 {
                return Err(DerError::LengthTooLong);
            }
            let (octets, next) = rest.split_at_checked(count).ok_or(DerError::Truncated)?;
            rest = next;
            octets
                .iter()
                .fold(0, |len, &octet| (len << 8) | usize::from(octet))
        }
    };
    let (content, after) = rest.split_at_checked(len).ok_or(DerError::Truncated)?;
    // X.690, clause 8.1.2.5: bit 6 marks a constructed value.
    if identifier & 0x20 != 0 {
        if depth >= MAX_DER_DEPTH {
            return Err(DerError::TooDeep);
        }
        let mut inner = content;
        while !inner.is_empty() {
            inner = check_value(inner, depth + 1)?;
        }
    }
    Ok(after)
}

/// The UTF-8 byte order mark.
const BYTE_ORDER_MARK: &[u8] = b"\xef\xbb\xbf";

/// The contents of a file without a leading UTF-8 byte order mark and
/// white space, which text editors may add before a PEM document.
///
/// RFC 7468, section 2, permits data before the encapsulation boundary,
/// and the production `W` of its section 3 defines the white space: HT,
/// LF, VT, FF, CR and SP. This tool deliberately skips only a byte order
/// mark and that white space, not other text before the boundary.
pub fn trim_pem_start(contents: &[u8]) -> &[u8] {
    let contents = contents.strip_prefix(BYTE_ORDER_MARK).unwrap_or(contents);
    let start = contents
        .iter()
        .position(|b| !matches!(b, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' '))
        .unwrap_or(contents.len());
    contents.get(start..).unwrap_or_default()
}

/// Reports whether a file holds a PEM document, after [`trim_pem_start`].
pub fn is_pem(contents: &[u8]) -> bool {
    trim_pem_start(contents).starts_with(b"-----BEGIN ")
}

#[cfg(test)]
mod tests;
