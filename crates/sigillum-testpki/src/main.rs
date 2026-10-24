//! Command-line entry point of `sigillum-testpki`.
//!
//! Exit codes: 0 on success, 1 when the manifest cannot be read or is not
//! valid or an artefact cannot be generated or written, 2 on a usage error,
//! 3 when the subcommand is not implemented yet.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sigillum_testpki::manifest::Manifest;
use sigillum_testpki::pki;
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
    /// Generate artefacts of the test corpus and record them in the manifest.
    Generate(GenerateOptions),
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

/// Options of `generate`.
#[derive(clap::Args)]
struct GenerateOptions {
    /// The artefacts to generate.
    target: Target,
    #[command(flatten)]
    corpus: ManifestOptions,
}

/// The artefacts that `generate` can produce.
#[derive(Clone, Copy, ValueEnum)]
enum Target {
    /// The certificates and private keys of the test PKI, under pki/.
    Pki,
    /// The CRLs of the test PKI, under crl/, after the certificates.
    Crls,
}

impl Target {
    /// The name of the target on the command line.
    fn name(self) -> &'static str {
        match self {
            Self::Pki => "pki",
            Self::Crls => "crls",
        }
    }
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
        Command::Generate(GenerateOptions { target, corpus }) => {
            let result = match target {
                Target::Pki => pki::write_into_corpus(&corpus.manifest),
                Target::Crls => pki::crl::write_into_corpus(&corpus.manifest),
            };
            let name = target.name();
            return match result {
                Ok(summary) => {
                    println!(
                        "sigillum-testpki generate {name}: wrote {} files and updated {}",
                        summary.written,
                        corpus.manifest.display()
                    );
                    for id in &summary.removed {
                        eprintln!(
                            "sigillum-testpki generate {name}: removed the manifest entry {id}, which is no longer generated"
                        );
                    }
                    for path in &summary.unlisted {
                        eprintln!(
                            "sigillum-testpki generate {name}: no manifest entry names {path}"
                        );
                    }
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    eprintln!("sigillum-testpki: {error}");
                    ExitCode::FAILURE
                }
            };
        }
        Command::Verify(options) => match Manifest::load(&options.manifest) {
            Ok(manifest) => ("verify", manifest.header.validation_time),
            Err(error) => {
                eprintln!("sigillum-testpki: {error}");
                return ExitCode::FAILURE;
            }
        },
        Command::Tsa(options) => ("tsa", options.time),
    };
    eprintln!(
        "sigillum-testpki {name}: not implemented yet (time {})",
        format_time(time)
    );
    ExitCode::from(NOT_IMPLEMENTED)
}
