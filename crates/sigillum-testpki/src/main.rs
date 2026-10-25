//! Command-line entry point of `sigillum-testpki`.
//!
//! Exit codes: 0 on success, 1 when the manifest cannot be read or is not
//! valid, an artefact cannot be generated or written, `tsa` cannot read
//! its key or certificate or issue the token, or `verify` finds an
//! artefact without its expected result or cannot run its checks, 2 on a
//! usage error.

mod tsa_cli;
mod verify_cli;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use sigillum_testpki::pki::{self, GenerateError, Summary};
use sigillum_testpki::timestamp;
use tsa_cli::TsaOptions;
use verify_cli::VerifyOptions;

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
    Verify(VerifyOptions),
}

/// Options of the subcommands that work on the corpus.
#[derive(clap::Args)]
pub struct ManifestOptions {
    /// Path to the manifest of the test corpus.
    #[arg(long, default_value = "testdata/manifest.toml")]
    pub manifest: PathBuf,
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
    /// The standalone timestamp tokens and the data they cover, under
    /// timestamps/, after the certificates.
    Timestamps,
    /// The OCSP responses of the test PKI, under ocsp/, after the
    /// certificates.
    Ocsp,
}

impl Target {
    /// The name of the target on the command line.
    fn name(self) -> &'static str {
        match self {
            Self::Pki => "pki",
            Self::Crls => "crls",
            Self::Timestamps => "timestamps",
            Self::Ocsp => "ocsp",
        }
    }
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Generate(GenerateOptions { target, corpus }) => {
            let result = match target {
                Target::Pki => pki::write_into_corpus(&corpus.manifest),
                Target::Crls => pki::crl::write_into_corpus(&corpus.manifest),
                Target::Timestamps => timestamp::write_into_corpus(&corpus.manifest),
                Target::Ocsp => pki::ocsp::write_into_corpus(&corpus.manifest),
            };
            report(target.name(), result, &corpus.manifest)
        }
        Command::Verify(options) => verify_cli::run(&options),
        Command::Tsa(options) => tsa_cli::run(&options),
    }
}

/// Reports what `generate` did for the target `name`, and returns the exit
/// code.
fn report(name: &str, result: Result<Summary, GenerateError>, manifest: &Path) -> ExitCode {
    match result {
        Ok(summary) => {
            println!(
                "sigillum-testpki generate {name}: wrote {} files and updated {}",
                summary.written,
                manifest.display()
            );
            for id in &summary.removed {
                eprintln!(
                    "sigillum-testpki generate {name}: removed the manifest entry {id}, which is no longer generated"
                );
            }
            for path in &summary.unlisted {
                eprintln!("sigillum-testpki generate {name}: no manifest entry names {path}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("sigillum-testpki: {error}");
            ExitCode::FAILURE
        }
    }
}
