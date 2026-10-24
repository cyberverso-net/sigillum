//! Command-line entry point of `sigillum-testpki`.
//!
//! Exit codes: 0 on success, 1 when the manifest cannot be read or is not
//! valid, 2 on a usage error, 3 when the subcommand is not implemented yet.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use sigillum_testpki::manifest::Manifest;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// Generator and checker of the sigillum test PKI and corpus.
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate artefacts of the test corpus.
    Generate(ManifestOptions),
    /// Issue an RFC 3161 timestamp token for a digest at a given time.
    Tsa(TsaOptions),
    /// Check every artefact against the results recorded in the manifest.
    Verify(ManifestOptions),
}

/// Options of the subcommands that work on the corpus.
#[derive(clap::Args)]
struct ManifestOptions {
    /// Path to the manifest of the test corpus.
    #[arg(long, default_value = "testdata/manifest.toml")]
    manifest: PathBuf,
}

/// Options of `tsa`, which does not read the manifest.
#[derive(clap::Args)]
struct TsaOptions {
    /// Time of the timestamp, as an RFC 3339 time.
    #[arg(long, value_parser = rfc3339)]
    time: OffsetDateTime,
    /// Private key of the timestamping authority, in PKCS#8.
    #[arg(long)]
    tsa_key: PathBuf,
    /// Certificate of the timestamping authority.
    #[arg(long)]
    tsa_cert: PathBuf,
}

const NOT_IMPLEMENTED: u8 = 3;

fn rfc3339(value: &str) -> Result<OffsetDateTime, String> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| format!("not an RFC 3339 time: {value}"))
}

fn format_time(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_else(|_| time.to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let (name, time) = match &cli.command {
        Command::Generate(options) | Command::Verify(options) => {
            let name = if matches!(cli.command, Command::Generate(_)) {
                "generate"
            } else {
                "verify"
            };
            match Manifest::load(&options.manifest) {
                Ok(manifest) => (name, manifest.header.validation_time),
                Err(error) => {
                    eprintln!("sigillum-testpki: {error}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Command::Tsa(options) => ("tsa", options.time),
    };
    eprintln!(
        "sigillum-testpki {name}: not implemented yet (time {})",
        format_time(time)
    );
    ExitCode::from(NOT_IMPLEMENTED)
}
