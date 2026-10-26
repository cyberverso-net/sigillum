//! The `verify` subcommand: its options, and the report of the checks.

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::CommandFactory;
use clap::error::ErrorKind;
use sigillum_testpki::dss::{self, DssError};
use sigillum_testpki::manifest::{Manifest, OpensslResult};
use sigillum_testpki::openssl::process::Program;
use sigillum_testpki::openssl::{self, Finding, OpensslError, Scratch};
use sigillum_testpki::signed::JavaOracle;

use crate::{Cli, ManifestOptions};

/// Options of `verify`. Without `--openssl` or `--dss`, both checks run.
#[derive(clap::Args)]
pub struct VerifyOptions {
    #[command(flatten)]
    corpus: ManifestOptions,
    /// Check every artefact with OpenSSL, whose version must be the one
    /// that the manifest header names.
    #[arg(long)]
    openssl: bool,
    /// The OpenSSL program to run: a path, or a name looked up in PATH.
    #[arg(long, value_name = "PROGRAM")]
    openssl_program: Option<PathBuf>,
    /// Check with this OpenSSL release in place of the one that the
    /// manifest header names, against the same expected results. The
    /// program must be that release.
    #[arg(long, value_name = "VERSION", value_parser = openssl_version)]
    openssl_version: Option<String>,
    /// Check every artefact with DSS through tools/dss-oracle, whose DSS
    /// version must be the one that the manifest header names.
    #[arg(long)]
    dss: bool,
    /// The executable JAR of tools/dss-oracle.
    #[arg(long, value_name = "JAR")]
    dss_oracle: Option<PathBuf>,
    /// The Java launcher that runs tools/dss-oracle.
    #[arg(long, value_name = "PROGRAM")]
    java: Option<PathBuf>,
}

/// The default JAR of `--dss-oracle`.
const DEFAULT_DSS_ORACLE: &str = "tools/dss-oracle/target/dss-oracle.jar";

/// Parses `--openssl-version` with [`openssl::is_version`].
fn openssl_version(value: &str) -> Result<String, String> {
    if openssl::is_version(value) {
        Ok(value.to_owned())
    } else {
        Err("not an OpenSSL version, such as 4.0.3".to_owned())
    }
}

impl VerifyOptions {
    /// The checks to run, `(openssl, dss)`: those chosen, or both when
    /// none is. An option of a check that does not run is a usage error,
    /// which exits with code 2.
    fn checks(&self) -> (bool, bool) {
        let (openssl, dss) = if self.openssl || self.dss {
            (self.openssl, self.dss)
        } else {
            (true, true)
        };
        let unused = [
            ("--openssl-program", self.openssl_program.is_some(), openssl),
            ("--openssl-version", self.openssl_version.is_some(), openssl),
            ("--dss-oracle", self.dss_oracle.is_some(), dss),
            ("--java", self.java.is_some(), dss),
        ];
        for (option, given, runs) in unused {
            if given && !runs {
                let check = if option.starts_with("--openssl") {
                    "--openssl"
                } else {
                    "--dss"
                };
                let mut cli = Cli::command();
                cli.build();
                let mut verify = cli
                    .find_subcommand_mut("verify")
                    .map_or_else(Cli::command, std::mem::take);
                verify
                    .error(
                        ErrorKind::ArgumentConflict,
                        format!("{option} is an option of the {check} check, which does not run"),
                    )
                    .exit();
            }
        }
        (openssl, dss)
    }
}

/// Runs the chosen checks and reports every artefact whose result differs
/// from the manifest. Returns 0 when every artefact has its expected
/// result, and 1 otherwise or when the checks cannot run.
pub fn run(options: &VerifyOptions) -> ExitCode {
    let (openssl, dss) = options.checks();
    let path = &options.corpus.manifest;
    let manifest = match Manifest::load(path) {
        Ok(manifest) => manifest,
        Err(error) => return fail(&error.to_string()),
    };
    let corpus = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut passed = true;
    if openssl {
        passed &= run_openssl(options, manifest.clone(), &corpus);
    }
    if dss {
        passed &= run_dss(options, &manifest, &corpus);
    }
    if passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("sigillum-testpki verify: {message}");
    ExitCode::FAILURE
}

/// Runs the OpenSSL checks, and reports whether every artefact has its
/// expected result.
fn run_openssl(options: &VerifyOptions, mut manifest: Manifest, corpus: &Path) -> bool {
    let fail = |message: String| {
        eprintln!("sigillum-testpki verify: {message}");
        false
    };
    if let Some(version) = &options.openssl_version {
        eprintln!(
            "sigillum-testpki verify: checks with OpenSSL {version} in place of OpenSSL {}, the release of the manifest header",
            manifest.header.openssl_version
        );
        manifest.header.openssl_version.clone_from(version);
    }
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
    let program_name = options
        .openssl_program
        .clone()
        .unwrap_or_else(|| PathBuf::from("openssl"));
    let program = Program::new(program_path(&program_name), scratch.path()).with_config(config);
    let report = match openssl::verify(&manifest, corpus, scratch.path(), &program) {
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
    mismatches == 0
}

/// Runs the DSS checks, and reports whether every artefact has its
/// expected result.
fn run_dss(options: &VerifyOptions, manifest: &Manifest, corpus: &Path) -> bool {
    let fail = |message: String| {
        eprintln!("sigillum-testpki verify: {message}");
        false
    };
    let java = options
        .java
        .clone()
        .unwrap_or_else(|| PathBuf::from("java"));
    let jar = options
        .dss_oracle
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DSS_ORACLE));
    let oracle = JavaOracle {
        java: program_path(&java),
        jar: std::path::absolute(&jar).unwrap_or(jar),
        timeout: dss::TIMEOUT,
    };
    let scratch = match Scratch::create() {
        Ok(scratch) => scratch,
        Err(error) => return fail(format!("no temporary directory: {error}")),
    };
    let jobs = std::thread::available_parallelism().unwrap_or(NonZeroUsize::MIN);
    let report = match dss::verify(manifest, corpus, scratch.path(), &oracle, jobs) {
        Ok(report) => report,
        Err(error @ DssError::Run(_)) => {
            return fail(format!("{error}; the Java launcher is {}", java.display()));
        }
        Err(error) => return fail(error.to_string()),
    };
    let mut mismatches = 0;
    for finding in report.mismatches() {
        mismatches += 1;
        eprintln!("{}", describe_dss(finding));
    }
    println!(
        "sigillum-testpki verify --dss: DSS {}, {} artefacts, {} as expected ({} with a recorded divergence), {mismatches} not as expected",
        report.version,
        report.findings.len(),
        report.findings.len() - mismatches,
        report
            .divergent()
            .filter(|finding| finding.matches())
            .count()
    );
    mismatches == 0
}

/// A program given by a path with more than one component is resolved
/// against the current directory, since the program runs elsewhere.
fn program_path(program: &Path) -> PathBuf {
    if program.components().count() > 1 {
        std::path::absolute(program).unwrap_or_else(|_| program.to_path_buf())
    } else {
        program.to_path_buf()
    }
}

/// The report of one OpenSSL finding whose result is not the expected one.
fn describe(finding: &Finding) -> String {
    let expected = finding.expected.as_str();
    let text = match &finding.actual {
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
    with_detail(text, &finding.detail)
}

/// The report of one DSS finding whose result is not the expected one.
fn describe_dss(finding: &dss::Finding) -> String {
    let expected = finding.expectation();
    let text = match &finding.actual {
        Ok(actual) => format!(
            "sigillum-testpki verify: {}: DSS gives {actual}, the check expects {expected}",
            finding.id
        ),
        Err(reason) => format!(
            "sigillum-testpki verify: {}: the DSS check cannot run: {reason}; the check expects {expected}",
            finding.id
        ),
    };
    with_detail(text, &finding.detail)
}

/// `text` followed by the lines of `detail`, indented.
fn with_detail(mut text: String, detail: &str) -> String {
    for line in detail.lines() {
        text.push_str("\n    ");
        text.push_str(line);
    }
    text
}
