//! The `verify` subcommand: its options, and the report of the checks.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::ArgGroup;
use sigillum_testpki::manifest::{Manifest, OpensslResult};
use sigillum_testpki::openssl::process::Program;
use sigillum_testpki::openssl::{self, Finding, OpensslError, Scratch};

use crate::ManifestOptions;

/// Options of `verify`. At least one check must be chosen.
#[derive(clap::Args)]
#[command(group(ArgGroup::new("checks").required(true).multiple(true)))]
pub struct VerifyOptions {
    #[command(flatten)]
    corpus: ManifestOptions,
    /// Check every artefact with OpenSSL, whose version must be the one
    /// that the manifest header names.
    #[arg(long, group = "checks")]
    openssl: bool,
    /// The OpenSSL program to run: a path, or a name looked up in PATH.
    #[arg(
        long,
        value_name = "PROGRAM",
        default_value = "openssl",
        requires = "openssl"
    )]
    openssl_program: PathBuf,
    /// Check with this OpenSSL release in place of the one that the
    /// manifest header names, against the same expected results. The
    /// program must be that release.
    #[arg(
        long,
        value_name = "VERSION",
        requires = "openssl",
        value_parser = openssl_version
    )]
    openssl_version: Option<String>,
}

/// Parses `--openssl-version` with [`openssl::is_version`].
fn openssl_version(value: &str) -> Result<String, String> {
    if openssl::is_version(value) {
        Ok(value.to_owned())
    } else {
        Err("not an OpenSSL version, such as 4.0.3".to_owned())
    }
}

/// Runs the chosen checks and reports every artefact whose result differs
/// from the manifest. Returns 0 when every artefact has its expected
/// result, and 1 otherwise or when the checks cannot run.
pub fn run(options: &VerifyOptions) -> ExitCode {
    let fail = |message: String| {
        eprintln!("sigillum-testpki verify: {message}");
        ExitCode::FAILURE
    };
    let path = &options.corpus.manifest;
    let mut manifest = match Manifest::load(path) {
        Ok(manifest) => manifest,
        Err(error) => return fail(error.to_string()),
    };
    if let Some(version) = &options.openssl_version {
        eprintln!(
            "sigillum-testpki verify: checks with OpenSSL {version} in place of OpenSSL {}, the release of the manifest header",
            manifest.header.openssl_version
        );
        manifest.header.openssl_version.clone_from(version);
    }
    let corpus = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let scratch = match Scratch::create() {
        Ok(scratch) => scratch,
        Err(error) => return fail(format!("no temporary directory: {error}")),
    };
    // An empty configuration file, so that the checks do not depend on the
    // configuration of the system.
    let config = scratch.path().join("openssl.cnf");
    if let Err(error) = std::fs::write(&config, "") {
        return fail(format!("{}: {error}", config.display()));
    }
    let program =
        Program::new(program_path(&options.openssl_program), scratch.path()).with_config(config);
    let report = match openssl::verify(&manifest, &corpus, scratch.path(), &program) {
        Ok(report) => report,
        Err(OpensslError::VersionMismatch { found, expected })
            if options.openssl_version.is_some() =>
        {
            return fail(format!(
                "--openssl-version names OpenSSL {expected}, but openssl is OpenSSL {found}"
            ));
        }
        Err(error) => return fail(error.to_string()),
    };
    let mut mismatches = 0;
    for finding in report.mismatches() {
        mismatches += 1;
        eprintln!("{}", describe(finding));
    }
    println!(
        "sigillum-testpki verify --openssl: OpenSSL {}, {} artefacts, {} as expected, {mismatches} not as expected",
        report.version,
        report.findings.len(),
        report.findings.len() - mismatches
    );
    if mismatches == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// A program given by a path with more than one component is resolved
/// against the current directory, since the program runs in the corpus.
fn program_path(program: &Path) -> PathBuf {
    if program.components().count() > 1 {
        std::path::absolute(program).unwrap_or_else(|_| program.to_path_buf())
    } else {
        program.to_path_buf()
    }
}

/// The report of one finding whose result is not the expected one.
fn describe(finding: &Finding) -> String {
    let expected = finding.expected.as_str();
    let mut text = match &finding.actual {
        Ok(actual) => format!(
            "sigillum-testpki verify: {}: OpenSSL gives {}, the manifest expects {expected}",
            finding.id,
            OpensslResult::as_str(*actual)
        ),
        Err(reason) => format!(
            "sigillum-testpki verify: {}: the OpenSSL check cannot run: {reason}; the manifest expects {expected}",
            finding.id
        ),
    };
    for line in finding.detail.lines() {
        text.push_str("\n    ");
        text.push_str(line);
    }
    text
}
