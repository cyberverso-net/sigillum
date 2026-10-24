//! The `tsa` subcommand: its options, the parsers of its arguments, and
//! the issuance of one token to standard output.
//!
//! The parsers of the untrusted command-line text are in the library
//! module `timestamp::input`, where they are tested and fuzzed.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use sigillum_testpki::timestamp::{DigestAlgorithm, Tsa, input};
use time::OffsetDateTime;

/// The exit code of a usage error, as clap uses it.
const USAGE: u8 = 2;

/// Options of `tsa`, which does not read the manifest.
#[derive(clap::Args)]
pub struct TsaOptions {
    /// Digest algorithm of the message imprint: SHA-256, SHA-384 or
    /// SHA-512, by name (with or without the hyphen, in any letter case) or
    /// by object identifier.
    #[arg(long, value_parser = digest_algorithm)]
    digest_algorithm: DigestAlgorithm,
    /// Digest to timestamp, in hexadecimal, as long as the algorithm's output.
    #[arg(long, value_parser = hex)]
    digest: HexDigest,
    /// Time of the timestamp, of the exact form YYYY-MM-DDTHH:MM:SSZ, from 1970.
    #[arg(long, value_parser = utc_time)]
    time: OffsetDateTime,
    /// Private key of the timestamping authority, a PKCS#8 PEM file of at
    /// most 64 KiB.
    #[arg(long)]
    tsa_key: PathBuf,
    /// Certificate of the timestamping authority, a DER file or a single
    /// PEM block, of at most 64 KiB. Chain files are refused.
    #[arg(long)]
    tsa_cert: PathBuf,
}

/// A digest given in hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq)]
struct HexDigest(Vec<u8>);

/// Parses `--digest-algorithm` with [`input::digest_algorithm`].
fn digest_algorithm(value: &str) -> Result<DigestAlgorithm, String> {
    input::digest_algorithm(value)
}

/// Parses `--digest` with [`input::hex_digest`].
fn hex(value: &str) -> Result<HexDigest, String> {
    input::hex_digest(value).map(HexDigest)
}

/// Parses `--time` with [`input::time`].
fn utc_time(value: &str) -> Result<OffsetDateTime, String> {
    input::time(value)
}

/// Issues the token and writes it to standard output, returning the exit
/// code: 0 on success; 1 when a file cannot be read or is larger than
/// [`input::MAX_FILE_LEN`], the key or certificate is not valid, or the
/// token cannot be issued or written; and 2 when the digest does not have
/// the algorithm's length.
pub fn run(options: &TsaOptions) -> ExitCode {
    let fail = |message: String| {
        eprintln!("sigillum-testpki tsa: {message}");
        ExitCode::FAILURE
    };
    let algorithm = options.digest_algorithm;
    let digest = &options.digest.0;
    if digest.len() != algorithm.output_len() {
        eprintln!(
            "sigillum-testpki tsa: a {} digest has {} octets, not {}",
            algorithm.name(),
            algorithm.output_len(),
            digest.len()
        );
        return ExitCode::from(USAGE);
    }
    let key = match input::read_file(&options.tsa_key) {
        Ok(key) => key,
        Err(error) => return fail(format!("{}: {error}", options.tsa_key.display())),
    };
    let certificate = match input::read_file(&options.tsa_cert) {
        Ok(certificate) => certificate,
        Err(error) => return fail(format!("{}: {error}", options.tsa_cert.display())),
    };
    let token = Tsa::from_pem(&key, &certificate)
        .and_then(|tsa| tsa.issue(algorithm, digest, options.time));
    let token = match token {
        Ok(token) => token,
        Err(error) => return fail(error.to_string()),
    };
    let mut stdout = std::io::stdout().lock();
    match stdout.write_all(&token).and_then(|()| stdout.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(format!("the token cannot be written: {error}")),
    }
}
