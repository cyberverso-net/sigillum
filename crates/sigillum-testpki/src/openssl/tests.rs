//! Tests of the OpenSSL checks, with a runner that stands in for
//! `openssl`: the commands built for each kind of artefact, the reading of
//! their output, the version check and the comparison with the manifest.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use proptest::prelude::*;

use super::*;
use crate::manifest::{Artefact, DssResult, Kind, Links, Manifest, OpensslResult};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The validation time of the corpus, 2030-01-15T10:00:00Z, in seconds
/// since the epoch, as `-attime` takes it.
const ATTIME: &str = "1894701600";

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn committed() -> Result<Manifest, Box<dyn std::error::Error>> {
    Ok(Manifest::load(&testdata().join("manifest.toml"))?)
}

fn artefact<'a>(manifest: &'a Manifest, id: &str) -> Result<&'a Artefact, String> {
    manifest
        .artefacts
        .iter()
        .find(|a| a.id == id)
        .ok_or_else(|| format!("no {id}"))
}

fn artefact_mut<'a>(manifest: &'a mut Manifest, id: &str) -> Result<&'a mut Artefact, String> {
    manifest
        .artefacts
        .iter_mut()
        .find(|a| a.id == id)
        .ok_or_else(|| format!("no {id}"))
}

fn strings(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

fn output(success: bool, stdout: &str, stderr: &str) -> Output {
    Output {
        success,
        stdout: stdout.to_owned(),
        stderr: stderr.to_owned(),
    }
}

fn version_output(version: &str) -> Output {
    output(
        true,
        &format!("OpenSSL {version} 30 Jan 2024 (Library: OpenSSL {version} 30 Jan 2024)\n"),
        "",
    )
}

/// A fresh, empty scratch directory for one test, removed when dropped.
struct TempDir(Scratch);

impl std::ops::Deref for TempDir {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.0.path()
    }
}

impl AsRef<Path> for TempDir {
    fn as_ref(&self) -> &Path {
        self.0.path()
    }
}

/// The directory is removed here too, so that no test leaves it behind,
/// even when a change to `Scratch` stops it from removing itself.
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.path());
    }
}

/// Removes a directory of a test when dropped, also when the test fails.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fresh base directory for scratch directories, removed when the
/// returned guard is dropped.
fn base(name: &str) -> Result<Cleanup, std::io::Error> {
    let dir = std::env::temp_dir().join(format!(
        "sigillum-testpki-unit-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    Ok(Cleanup(dir))
}

/// A new scratch directory; `_name` says what the test uses it for.
fn scratch(_name: &str) -> Result<TempDir, std::io::Error> {
    Ok(TempDir(Scratch::create()?))
}

/// The argument that names bundle `n`, a bare file name, since `openssl`
/// runs in the scratch directory.
fn bundle(_scratch: &Path, n: usize) -> String {
    format!("bundle-{n}.pem")
}

/// The file of bundle `n` in `scratch`.
fn bundle_file(scratch: &Path, n: usize) -> PathBuf {
    scratch.join(format!("bundle-{n}.pem"))
}

/// The argument that names the corpus file `path`: its absolute path.
fn c(path: &str) -> String {
    absolute(&testdata())
        .join(path)
        .to_string_lossy()
        .into_owned()
}

fn absolute(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn corpus_file(path: &str) -> Result<Vec<u8>, std::io::Error> {
    std::fs::read(testdata().join(path))
}

/// The PEM form of the DER file `path` of the corpus, with `label`.
fn pem_of(path: &str, label: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(
        der::pem::encode_string(label, der::pem::LineEnding::LF, &corpus_file(path)?)
            .map_err(|e| e.to_string())?,
    )
}

fn value_after<'a>(args: &'a [String], option: &str) -> Vec<&'a str> {
    args.windows(2)
        .filter(|pair| pair[0] == option)
        .map(|pair| pair[1].as_str())
        .collect()
}

/// The times that `openssl crl -lastupdate -nextupdate` prints for a
/// current CRL of the corpus.
const FRESH_CRL: &str =
    "lastUpdate=Jan 14 10:00:00 2030 GMT\nnextUpdate=Jan 21 10:00:00 2030 GMT\n";

/// A runner that answers as OpenSSL would if every artefact had the result
/// that `manifest` expects, and records the commands.
struct Oracle {
    expected: HashMap<String, OpensslResult>,
    version: String,
    calls: RefCell<Vec<Vec<String>>>,
}

impl Oracle {
    fn new(manifest: &Manifest) -> Self {
        Self {
            expected: manifest
                .artefacts
                .iter()
                .map(|a| (c(&a.path.to_string_lossy()), a.expected_openssl))
                .collect(),
            version: manifest.header.openssl_version.clone(),
            calls: RefCell::new(Vec::new()),
        }
    }

    fn is(&self, path: &str, result: OpensslResult) -> bool {
        self.expected.get(path) == Some(&result)
    }

    fn answer(&self, args: &[String]) -> Output {
        let first = |option: &str| value_after(args, option).first().copied().unwrap_or("");
        match args.first().map(String::as_str) {
            Some("version") => version_output(&self.version),
            Some("verify") => {
                let cert = args.last().map_or("", String::as_str);
                let crls_ok = value_after(args, "-CRLfile")
                    .iter()
                    .all(|crl| self.is(crl, OpensslResult::Verified));
                if crls_ok && self.is(cert, OpensslResult::Verified) {
                    output(true, &format!("{cert}: OK\n"), "")
                } else {
                    output(false, "", &format!("error {cert}: verification failed\n"))
                }
            }
            Some("crl") => output(true, FRESH_CRL, "verify OK\n"),
            Some("ocsp") => {
                if self.is(first("-respin"), OpensslResult::Verified) {
                    output(
                        true,
                        &format!(
                            "{}: WARNING: Status times invalid.\n0:error:1380007E:OCSP routines:OCSP_check_validity:status not yet valid\ngood\n\tThis Update: Jan 14 10:00:00 2030 GMT\n",
                            first("-cert")
                        ),
                        "Response verify OK\n",
                    )
                } else {
                    output(false, "", "Response Verify Failure\n")
                }
            }
            Some("ts") => {
                if self.is(first("-in"), OpensslResult::Verified) {
                    output(true, "Verification: OK\n", "")
                } else {
                    output(false, "Verification: FAILED\n", "")
                }
            }
            Some("pkey") => output(self.is(first("-in"), OpensslResult::Parsed), "", ""),
            _ => output(false, "", "unknown command\n"),
        }
    }
}

impl Runner for Oracle {
    fn run(&self, args: &[OsString]) -> Result<Output, RunError> {
        let args = strings(args);
        let answer = self.answer(&args);
        self.calls.borrow_mut().push(args);
        Ok(answer)
    }
}

// The version check (acceptance criterion 3).

#[test]
fn the_version_is_read_from_openssl_version() {
    assert_eq!(
        parse_version("OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)\n"),
        Ok("3.0.13".to_owned())
    );
    assert_eq!(
        parse_version("OpenSSL 3.5.9 29 Sep 2026\n"),
        Ok("3.5.9".to_owned())
    );
    assert_eq!(
        parse_version("OpenSSL 1.1.1w  11 Sep 2023"),
        Ok("1.1.1w".to_owned())
    );
}

#[test]
fn other_version_output_is_refused() {
    for text in [
        "",
        "\n",
        "LibreSSL 3.3.6\n",
        "OpenSSL\n",
        "OpenSSL  3.0.13\n",
        "openssl 3.0.13\n",
        "OpenSSL 3.0.13; 30 Jan 2024\n",
        "OpenSSL 3.0.13-dev 30 Jan 2024 (Library: OpenSSL 3.0.13-dev\n",
        "OpenSSL 3.0.13 30 Jan 2024 (Library: LibreSSL 3.3.6)\n",
        "OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL)\n",
        "OpenSSL 3.0.13 30 Jan 2024\nOpenSSL 3.5.9 29 Sep 2026\n",
        "Using configuration from x\nOpenSSL 3.0.13\n",
        "OpenSSL .\n",
        "OpenSSL 3.0.13\u{a0}30 Jan 2024\n",
    ] {
        assert!(
            matches!(parse_version(text), Err(OpensslError::UnknownVersion(_))),
            "{text:?}: {:?}",
            parse_version(text)
        );
    }
}

#[test]
fn a_version_is_a_digit_then_letters_digits_dots_and_hyphens() {
    for version in ["3.5.9", "4.0.3", "1.1.1w", "3.0.13-dev", "4"] {
        assert!(is_version(version), "{version}");
    }
    for version in [
        "", "v3.5.9", "-4", ".1", "3.5.9 ", " 3.5.9", "3.5;9", "3.5/9", "3\u{a0}5",
    ] {
        assert!(!is_version(version), "{version:?}");
    }
}

#[test]
fn a_library_of_another_version_is_refused() {
    assert_eq!(
        parse_version("OpenSSL 3.5.9 29 Sep 2026 (Library: OpenSSL 3.5.8 1 Jul 2026)\n"),
        Err(OpensslError::LibraryMismatch {
            program: "3.5.9".to_owned(),
            library: "3.5.8".to_owned(),
        })
    );
}

#[test]
fn check_version_runs_openssl_version() {
    let calls = RefCell::new(Vec::new());
    let runner = |args: &[OsString]| {
        calls.borrow_mut().push(strings(args));
        Ok(version_output("3.0.13"))
    };
    assert_eq!(check_version(&runner, "3.0.13"), Ok("3.0.13".to_owned()));
    assert_eq!(*calls.borrow(), vec![vec!["version".to_owned()]]);
}

#[test]
fn another_version_fails_with_both_versions_named() {
    let runner = |_: &[OsString]| Ok(version_output("3.5.9"));
    let error = check_version(&runner, "3.0.13");
    assert_eq!(
        error,
        Err(OpensslError::VersionMismatch {
            found: "3.5.9".to_owned(),
            expected: "3.0.13".to_owned(),
        })
    );
    let message = error.map_err(|e| e.to_string()).err().unwrap_or_default();
    assert!(message.contains("OpenSSL 3.0.13"), "{message}");
    assert!(message.contains("OpenSSL 3.5.9"), "{message}");
}

#[test]
fn a_version_that_only_starts_alike_is_another_version() {
    let runner = |_: &[OsString]| Ok(version_output("3.0.130"));
    assert!(matches!(
        check_version(&runner, "3.0.13"),
        Err(OpensslError::VersionMismatch { .. })
    ));
}

#[test]
fn a_failing_or_missing_openssl_stops_the_check() {
    let failing = |_: &[OsString]| Ok(output(false, "OpenSSL 3.0.13 30 Jan 2024\n", "error\n"));
    assert!(matches!(
        check_version(&failing, "3.0.13"),
        Err(OpensslError::Run(RunError::Io(_)))
    ));
    let missing = |_: &[OsString]| Err(RunError::Spawn("openssl: not found".to_owned()));
    let error = check_version(&missing, "3.0.13");
    assert_eq!(
        error,
        Err(OpensslError::Run(RunError::Spawn(
            "openssl: not found".to_owned()
        )))
    );
}

#[test]
fn verify_checks_the_version_before_any_artefact() -> TestResult {
    let manifest = committed()?;
    let scratch = scratch("version-first")?;
    let calls = RefCell::new(Vec::new());
    let runner = |args: &[OsString]| {
        calls.borrow_mut().push(strings(args));
        Ok(version_output("4.0.3"))
    };
    let result = verify(&manifest, &testdata(), &scratch, &runner);
    assert!(matches!(result, Err(OpensslError::VersionMismatch { .. })));
    assert_eq!(calls.borrow().len(), 1);
    Ok(())
}

// The commands (acceptance criteria 1 and 2).

#[test]
fn a_certificate_is_checked_with_openssl_verify_at_the_validation_time() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("certificate-args")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let signer = artefact(&manifest, "pki/signer-p256")?;
    let crls = checker.default_crls(signer);
    assert_eq!(
        crls.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
        ["crl/ca-ecdsa", "crl/root-ca"]
    );
    assert_eq!(
        strings(&checker.certificate_args(signer, &crls)?),
        [
            "verify",
            "-attime",
            ATTIME,
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            &bundle(&dir, 1),
            "-untrusted",
            &bundle(&dir, 2),
            "-crl_check_all",
            "-CRLfile",
            &c("crl/ca-ecdsa.crl"),
            "-CRLfile",
            &c("crl/root-ca.crl"),
            &c("pki/signer-p256.pem"),
        ]
    );
    assert_eq!(
        std::fs::read(bundle_file(&dir, 1))?,
        corpus_file("pki/root-ca.pem")?
    );
    assert_eq!(
        std::fs::read(bundle_file(&dir, 2))?,
        corpus_file("pki/ca-ecdsa.pem")?
    );
    Ok(())
}

#[test]
fn the_root_is_its_own_trust_anchor_without_crls() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("root-args")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let root = artefact(&manifest, "pki/root-ca")?;
    assert!(checker.default_crls(root).is_empty());
    assert_eq!(
        strings(&checker.certificate_args(root, &[])?),
        [
            "verify",
            "-attime",
            ATTIME,
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            &bundle(&dir, 1),
            &c("pki/root-ca.pem"),
        ]
    );
    assert_eq!(
        std::fs::read(bundle_file(&dir, 1))?,
        corpus_file("pki/root-ca.pem")?
    );
    Ok(())
}

#[test]
fn the_crls_of_a_certificate_come_before_those_of_its_chain_without_repeats() -> TestResult {
    let mut manifest = committed()?;
    // pki/signer-p256 also links the CRL of the root, as its CA does.
    artefact_mut(&mut manifest, "pki/signer-p256")?
        .links
        .revocation
        .push("crl/root-ca".to_owned());
    let dir = scratch("crl-order")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let signer = artefact(&manifest, "pki/signer-p256")?;
    assert_eq!(
        checker
            .default_crls(signer)
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>(),
        ["crl/ca-ecdsa", "crl/root-ca"]
    );
    let ca = artefact(&manifest, "pki/ca-ecdsa")?;
    assert_eq!(
        checker
            .chain_crls(signer)
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>(),
        ["crl/root-ca"]
    );
    assert!(checker.chain_crls(ca).is_empty());
    Ok(())
}

#[test]
fn a_crl_is_checked_with_openssl_crl_against_its_issuer() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("crl-args")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let crl = artefact(&manifest, "crl/ca-ecdsa")?;
    assert_eq!(
        strings(&checker.crl_args(crl)?),
        [
            "crl",
            "-inform",
            "DER",
            "-in",
            &c("crl/ca-ecdsa.crl"),
            "-noout",
            "-lastupdate",
            "-nextupdate",
            "-verify",
            "-no-CApath",
            "-no-CAstore",
            "-CAfile",
            &bundle(&dir, 1),
        ]
    );
    assert_eq!(
        std::fs::read(bundle_file(&dir, 1))?,
        corpus_file("pki/ca-ecdsa.pem")?
    );
    Ok(())
}

#[test]
fn a_pem_crl_is_read_as_pem() -> TestResult {
    let dir = scratch("pem-crl")?;
    let corpus = dir.join("corpus");
    std::fs::create_dir_all(corpus.join("crl"))?;
    std::fs::create_dir_all(corpus.join("pki"))?;
    std::fs::write(
        corpus.join("crl/root-ca.pem"),
        pem_of("crl/root-ca.crl", "X509 CRL")?,
    )?;
    std::fs::write(
        corpus.join("pki/root-ca.pem"),
        corpus_file("pki/root-ca.pem")?,
    )?;
    let mut manifest = committed()?;
    manifest
        .artefacts
        .retain(|a| a.id == "pki/root-ca" || a.id == "crl/root-ca");
    artefact_mut(&mut manifest, "crl/root-ca")?.path = PathBuf::from("crl/root-ca.pem");
    let scratch = dir.join("scratch");
    std::fs::create_dir_all(&scratch)?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &corpus, &scratch, &oracle);
    let args = strings(&checker.crl_args(artefact(&manifest, "crl/root-ca")?)?);
    assert_eq!(args[0], "crl");
    assert_eq!(args[1], "-in");
    assert_eq!(
        args[2],
        absolute(&corpus).join("crl/root-ca.pem").to_string_lossy()
    );
    Ok(())
}

#[test]
fn a_crl_is_also_checked_with_each_certificate_of_its_issuer_that_verifies() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("crl-certificates")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let finding = checker.check(artefact(&manifest, "crl/ca-ecdsa")?);
    assert_eq!(finding.actual, Ok(OpensslResult::Verified));
    let calls = oracle.calls.borrow();
    assert_eq!(calls[0][0], "crl");
    let checked: BTreeSet<&str> = calls[1..]
        .iter()
        .map(|call| {
            assert_eq!(call[0], "verify");
            assert_eq!(
                value_after(call, "-CRLfile"),
                [&c("crl/ca-ecdsa.crl"), &c("crl/root-ca.crl")]
            );
            assert!(call.contains(&"-crl_check_all".to_owned()));
            call.last().map_or("", String::as_str)
        })
        .collect();
    let expected: BTreeSet<String> = manifest
        .artefacts
        .iter()
        .filter(|a| {
            a.kind == Kind::Certificate
                && a.links.issuer.as_deref() == Some("pki/ca-ecdsa")
                && a.expected_openssl == OpensslResult::Verified
        })
        .map(|a| c(&a.path.to_string_lossy()))
        .collect();
    assert!(expected.len() > 3);
    assert_eq!(
        checked,
        expected.iter().map(String::as_str).collect::<BTreeSet<_>>()
    );
    Ok(())
}

#[test]
fn a_crl_whose_issuer_issued_nothing_that_verifies_rests_on_openssl_crl() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("crl-alone")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let finding = checker.check(artefact(&manifest, "crl/ca-expired")?);
    assert_eq!(finding.actual, Ok(OpensslResult::Verified));
    assert_eq!(oracle.calls.borrow().len(), 1);
    Ok(())
}

#[test]
fn an_ocsp_response_is_checked_for_its_covered_certificate() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("ocsp-args")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    for id in ["ocsp/signer-p256", "ocsp/try-later"] {
        let response = artefact(&manifest, id)?;
        let (args, cert) = checker.ocsp_args(response)?;
        let respin = c(&response.path.to_string_lossy());
        assert_eq!(cert, c("pki/signer-p256.pem"));
        let first = if id == "ocsp/signer-p256" { 1 } else { 3 };
        let expected_bundle = bundle(&dir, first);
        let other = bundle(&dir, first + 1);
        assert_eq!(
            strings(&args),
            [
                "ocsp",
                "-respin",
                &respin,
                "-no_nonce",
                "-issuer",
                &c("pki/ca-ecdsa.pem"),
                "-cert",
                &c("pki/signer-p256.pem"),
                "-no-CApath",
                "-no-CAstore",
                "-CAfile",
                &expected_bundle,
                "-verify_other",
                &other,
                "-attime",
                ATTIME,
            ]
        );
        assert_eq!(
            std::fs::read(bundle_file(&dir, first))?,
            corpus_file("pki/root-ca.pem")?
        );
        // Every certificate of the chain but the trust anchor, then the
        // responder that the entry links, if any.
        let mut other = corpus_file("pki/ca-ecdsa.pem")?;
        if id == "ocsp/signer-p256" {
            other.extend(corpus_file("pki/ocsp-responder.pem")?);
        }
        assert_eq!(std::fs::read(bundle_file(&dir, first + 1))?, other);
    }
    let (args, cert) = checker.ocsp_args(artefact(&manifest, "ocsp/signer-rsa-2048")?)?;
    assert_eq!(cert, c("pki/signer-rsa-2048.pem"));
    assert_eq!(
        value_after(&strings(&args), "-issuer"),
        [&c("pki/ca-rsa.pem")]
    );
    Ok(())
}

/// `-verify_other` holds every certificate of the chain of the covered
/// certificate but the trust anchor, or the issuer when that is the
/// trust anchor itself, then the responder that the entry links and its
/// chain but the trust anchor, for a response without certificates.
#[test]
fn ocsp_verify_other_holds_the_chain_without_its_anchor() -> TestResult {
    let mut manifest = committed()?;
    // A chain with two intermediate CAs, as far as the manifest says.
    artefact_mut(&mut manifest, "pki/signer-p256")?.links.chain = vec![
        "pki/ca-ecdsa".to_owned(),
        "pki/ca-rsa".to_owned(),
        "pki/root-ca".to_owned(),
    ];
    // A certificate that the trust anchor issued.
    artefact_mut(&mut manifest, "ocsp/signer-p384")?.notes =
        Some("Covered certificate: pki/ca-rsa.".to_owned());
    let dir = scratch("verify-other")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let (args, _) = checker.ocsp_args(artefact(&manifest, "ocsp/signer-p256")?)?;
    assert_eq!(
        value_after(&strings(&args), "-verify_other"),
        [bundle(&dir, 2)]
    );
    assert_eq!(
        std::fs::read(bundle_file(&dir, 2))?,
        [
            corpus_file("pki/ca-ecdsa.pem")?,
            corpus_file("pki/ca-rsa.pem")?,
            corpus_file("pki/ocsp-responder.pem")?
        ]
        .concat()
    );
    let (args, _) = checker.ocsp_args(artefact(&manifest, "ocsp/signer-p384")?)?;
    assert_eq!(
        value_after(&strings(&args), "-verify_other"),
        [bundle(&dir, 4)]
    );
    assert_eq!(
        std::fs::read(bundle_file(&dir, 4))?,
        [
            corpus_file("pki/root-ca.pem")?,
            corpus_file("pki/ocsp-responder.pem")?,
            corpus_file("pki/ca-ecdsa.pem")?
        ]
        .concat()
    );
    Ok(())
}

/// A responder that is its own trust anchor is still offered to
/// `-verify_other`.
#[test]
fn ocsp_verify_other_holds_a_responder_without_a_chain_above_it() -> TestResult {
    let mut manifest = committed()?;
    let response = artefact_mut(&mut manifest, "ocsp/signer-p256")?;
    response.links.issuer = Some("pki/signer-p384".to_owned());
    response.links.chain = vec!["pki/signer-p384".to_owned()];
    let dir = scratch("verify-other-root")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let (args, _) = checker.ocsp_args(artefact(&manifest, "ocsp/signer-p256")?)?;
    assert_eq!(
        value_after(&strings(&args), "-verify_other"),
        [bundle(&dir, 2)]
    );
    assert_eq!(
        std::fs::read(bundle_file(&dir, 2))?,
        [
            corpus_file("pki/ca-ecdsa.pem")?,
            corpus_file("pki/signer-p384.pem")?
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn a_timestamp_token_is_checked_with_its_content_and_the_crls_of_its_chain() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("ts-args")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    assert_eq!(
        strings(&checker.timestamp_args(artefact(&manifest, "timestamps/valid")?)?),
        [
            "ts",
            "-verify",
            "-in",
            &c("timestamps/valid.tst"),
            "-token_in",
            "-data",
            &c("timestamps/content.txt"),
            "-CAfile",
            &bundle(&dir, 1),
            "-untrusted",
            &bundle(&dir, 2),
            "-crl_check_all",
            "-attime",
            ATTIME,
        ]
    );
    let trust = String::from_utf8(std::fs::read(bundle_file(&dir, 1))?)?;
    let expected = format!(
        "{}{}{}",
        String::from_utf8(corpus_file("pki/root-ca.pem")?)?,
        pem_of("crl/ca-ecdsa.crl", "X509 CRL")?,
        pem_of("crl/root-ca.crl", "X509 CRL")?
    );
    assert_eq!(trust, expected);
    // The signer too, since a token may omit its certificates.
    assert_eq!(
        std::fs::read(bundle_file(&dir, 2))?,
        [
            corpus_file("pki/tsa.pem")?,
            corpus_file("pki/ca-ecdsa.pem")?
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn a_timestamp_token_without_crls_omits_crl_check_all() -> TestResult {
    let mut manifest = committed()?;
    let token = artefact_mut(&mut manifest, "timestamps/valid")?;
    token.links.issuer = Some("pki/root-ca".to_owned());
    token.links.chain = vec!["pki/root-ca".to_owned()];
    let dir = scratch("ts-bare")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    assert_eq!(
        strings(&checker.timestamp_args(artefact(&manifest, "timestamps/valid")?)?),
        [
            "ts",
            "-verify",
            "-in",
            &c("timestamps/valid.tst"),
            "-token_in",
            "-data",
            &c("timestamps/content.txt"),
            "-CAfile",
            &bundle(&dir, 1),
            "-untrusted",
            &bundle(&dir, 2),
            "-attime",
            ATTIME,
        ]
    );
    // The signer is offered even when it is the trust anchor, for a token
    // without certificates.
    assert_eq!(
        std::fs::read(bundle_file(&dir, 2))?,
        corpus_file("pki/root-ca.pem")?
    );
    Ok(())
}

#[test]
fn a_private_key_is_parsed_with_openssl_pkey() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("key-args")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    assert_eq!(
        strings(&checker.key_args(artefact(&manifest, "pki/keys/root-ca")?)?),
        ["pkey", "-in", &c("pki/keys/root-ca.test-key.pem"), "-noout"]
    );
    Ok(())
}

#[test]
fn every_time_dependent_command_runs_at_the_validation_time() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("attime")?;
    let oracle = Oracle::new(&manifest);
    let report = verify(&manifest, &testdata(), &dir, &oracle)?;
    assert_eq!(report.findings.len(), manifest.artefacts.len());
    let calls = oracle.calls.borrow();
    let mut commands = BTreeSet::new();
    for call in calls.iter() {
        let command = call[0].as_str();
        commands.insert(command);
        let attime = value_after(call, "-attime");
        match command {
            "verify" | "ocsp" | "ts" => assert_eq!(attime, [ATTIME], "{call:?}"),
            // openssl crl -verify checks only the signature, and the
            // validity of the CRL is checked by openssl verify.
            "crl" | "pkey" | "version" => assert!(attime.is_empty(), "{call:?}"),
            _ => return Err(format!("unexpected command {call:?}").into()),
        }
        if matches!(command, "verify" | "ocsp" | "crl") {
            assert!(call.contains(&"-no-CApath".to_owned()), "{call:?}");
            assert!(call.contains(&"-no-CAstore".to_owned()), "{call:?}");
        }
    }
    assert_eq!(
        commands,
        BTreeSet::from(["crl", "ocsp", "pkey", "ts", "verify", "version"])
    );
    Ok(())
}

// The reading of the output.

fn single(output: Output) -> impl Fn(&[OsString]) -> Result<Output, RunError> {
    move |_: &[OsString]| Ok(output.clone())
}

fn check_with(
    manifest: &Manifest,
    id: &str,
    runner: &dyn Runner,
    name: &str,
) -> Result<Finding, Box<dyn std::error::Error>> {
    let dir = scratch(name)?;
    let checker = Checker::new(manifest, &testdata(), &dir, runner);
    Ok(checker.check(artefact(manifest, id)?))
}

#[test]
fn a_certificate_verifies_only_with_exit_0_and_its_ok_line() -> TestResult {
    let manifest = committed()?;
    let id = "pki/signer-p256";
    for (answer, expected) in [
        (
            output(true, &format!("{}: OK\n", c("pki/signer-p256.pem")), ""),
            OpensslResult::Verified,
        ),
        (
            output(false, &format!("{}: OK\n", c("pki/signer-p256.pem")), ""),
            OpensslResult::Rejected,
        ),
        (output(true, "", ""), OpensslResult::Rejected),
        (
            output(
                true,
                &format!("{}: OK, or not\n", c("pki/signer-p256.pem")),
                "",
            ),
            OpensslResult::Rejected,
        ),
        (
            output(true, &format!("{}: OK\n", c("pki/signer-p384.pem")), ""),
            OpensslResult::Rejected,
        ),
        (
            output(false, "", "error 12 at 0 depth lookup: CRL has expired\n"),
            OpensslResult::Rejected,
        ),
    ] {
        let finding = check_with(&manifest, id, &single(answer.clone()), "cert-output")?;
        assert_eq!(finding.actual, Ok(expected), "{answer:?}");
        assert!(
            finding.detail.contains("openssl verify -attime"),
            "{}",
            finding.detail
        );
    }
    Ok(())
}

#[test]
fn a_crl_verifies_only_when_openssl_crl_says_verify_ok() -> TestResult {
    let manifest = committed()?;
    // The vanilla build of OpenSSL 3.0.13 exits with 0 even when the
    // signature does not verify.
    for (answer, expected) in [
        (
            output(true, FRESH_CRL, "verify OK\n"),
            OpensslResult::Verified,
        ),
        (
            output(true, FRESH_CRL, "verify failure\n"),
            OpensslResult::Rejected,
        ),
        (
            output(false, FRESH_CRL, "verify OK\n"),
            OpensslResult::Rejected,
        ),
        (
            output(true, &format!("{FRESH_CRL}verify OK\n"), ""),
            OpensslResult::Rejected,
        ),
    ] {
        let finding = check_with(
            &manifest,
            "crl/ca-expired",
            &single(answer.clone()),
            "crl-output",
        )?;
        assert_eq!(finding.actual, Ok(expected), "{answer:?}");
    }
    Ok(())
}

/// Every CRL must be current at the validation time, 2030-01-15T10:00:00Z:
/// issued at or before it, and with a next update after it.
#[test]
fn a_crl_verifies_only_when_it_is_current_at_the_validation_time() -> TestResult {
    let manifest = committed()?;
    for (times, expected) in [
        (FRESH_CRL, OpensslResult::Verified),
        (
            "lastUpdate=Jan 15 10:00:00 2030 GMT\nnextUpdate=Jan 15 10:00:01 2030 GMT\n",
            OpensslResult::Verified,
        ),
        (
            "lastUpdate=Jan  1 10:00:00 2030 GMT\nnextUpdate=Jan  8 10:00:00 2030 GMT\n",
            OpensslResult::Rejected,
        ),
        (
            "lastUpdate=Jan 14 10:00:00 2030 GMT\nnextUpdate=Jan 15 10:00:00 2030 GMT\n",
            OpensslResult::Rejected,
        ),
        (
            "lastUpdate=Jan 15 10:00:01 2030 GMT\nnextUpdate=Jan 21 10:00:00 2030 GMT\n",
            OpensslResult::Rejected,
        ),
        (
            "lastUpdate=Jan 14 10:00:00 2030 GMT\nnextUpdate=NONE\n",
            OpensslResult::Rejected,
        ),
    ] {
        // crl/ca-expired has no certificate expected to verify, so the
        // times alone decide beside the signature.
        let finding = check_with(
            &manifest,
            "crl/ca-expired",
            &single(output(true, times, "verify OK\n")),
            "crl-times",
        )?;
        assert_eq!(finding.actual, Ok(expected), "{times:?}");
    }
    Ok(())
}

/// Times that cannot be read after a verified signature stop the check:
/// they are no evidence that the CRL is stale.
#[test]
fn unreadable_crl_times_stop_the_check() -> TestResult {
    let manifest = committed()?;
    for times in [
        "",
        "lastUpdate=Jan 14 10:00:00 2030 GMT\n",
        "lastUpdate=2030-01-14 10:00:00Z\nnextUpdate=2030-01-21 10:00:00Z\n",
        "lastUpdate=Jan 14 10:00:00.5 2030 GMT\nnextUpdate=Jan 21 10:00:00 2030 GMT\n",
    ] {
        let finding = check_with(
            &manifest,
            "crl/ca-expired",
            &single(output(true, times, "verify OK\n")),
            "crl-unreadable-times",
        )?;
        let message = finding.actual.err().unwrap_or_default();
        assert!(
            message.contains("cannot read thisUpdate and nextUpdate"),
            "{times:?}: {message}"
        );
    }
    // A signature that does not verify still rejects, whatever the times.
    let finding = check_with(
        &manifest,
        "crl/ca-expired",
        &single(output(true, "", "verify failure\n")),
        "crl-unreadable-times",
    )?;
    assert_eq!(finding.actual, Ok(OpensslResult::Rejected));
    Ok(())
}

#[test]
fn crl_times_are_read_from_openssl_crl() {
    let parsed = crl_times(FRESH_CRL);
    assert_eq!(
        parsed,
        Some((
            time::macros::datetime!(2030-01-14 10:00:00 UTC),
            time::macros::datetime!(2030-01-21 10:00:00 UTC)
        ))
    );
    assert_eq!(
        crl_times("lastUpdate=Jan  1 00:00:00 2050 GMT\r\nnextUpdate=Dec 31 23:59:59 2050 GMT\r\n"),
        Some((
            time::macros::datetime!(2050-01-01 00:00:00 UTC),
            time::macros::datetime!(2050-12-31 23:59:59 UTC)
        ))
    );
    for stdout in [
        "",
        "lastUpdate=Jan 14 10:00:00 2030 GMT\n",
        "nextUpdate=Jan 21 10:00:00 2030 GMT\n",
        "lastUpdate=Jan 14 10:00:00 2030 GMT\nnextUpdate=NONE\n",
        "lastUpdate=Jan 14 10:00:00 2030\nnextUpdate=Jan 21 10:00:00 2030 GMT\n",
        "lastUpdate=Foo 14 10:00:00 2030 GMT\nnextUpdate=Jan 21 10:00:00 2030 GMT\n",
        "lastUpdate=Jan 14 10:00:00 2030 GMT\nlastUpdate=Jan 14 10:00:00 2030 GMT\nnextUpdate=Jan 21 10:00:00 2030 GMT\n",
    ] {
        assert_eq!(crl_times(stdout), None, "{stdout:?}");
    }
}

#[test]
fn a_crl_is_rejected_when_a_certificate_of_its_issuer_then_fails() -> TestResult {
    let manifest = committed()?;
    let runner = |args: &[OsString]| {
        let args = strings(args);
        Ok(if args[0] == "crl" {
            output(true, FRESH_CRL, "verify OK\n")
        } else if args.last().map(String::as_str) == Some(c("pki/signer-p384.pem").as_str()) {
            output(false, "", "error 12 at 0 depth lookup: CRL has expired\n")
        } else {
            output(
                true,
                &format!("{}: OK\n", args.last().map_or("", String::as_str)),
                "",
            )
        })
    };
    let finding = check_with(&manifest, "crl/ca-ecdsa", &runner, "crl-then")?;
    assert_eq!(finding.actual, Ok(OpensslResult::Rejected));
    assert!(
        finding.detail.contains(&c("pki/signer-p384.pem")),
        "{}",
        finding.detail
    );
    assert!(
        finding.detail.contains("CRL has expired"),
        "{}",
        finding.detail
    );
    Ok(())
}

#[test]
fn an_ocsp_response_verifies_with_a_status_for_the_certificate() -> TestResult {
    let manifest = committed()?;
    let id = "ocsp/signer-p256";
    let cert = c("pki/signer-p256.pem");
    let warning = &format!(
        "{cert}: WARNING: Status times invalid.\n0:error:1380007E:OCSP routines:OCSP_check_validity:status not yet valid:crypto/ocsp/ocsp_cl.c:324:\ngood\n\tThis Update: Jan 14 10:00:00 2030 GMT\n"
    );
    for (answer, expected) in [
        (
            output(true, warning, "Response verify OK\n"),
            OpensslResult::Verified,
        ),
        (
            output(
                true,
                &format!("{cert}: revoked\n\tReason: keyCompromise\n"),
                "Response verify OK\n",
            ),
            OpensslResult::Verified,
        ),
        (
            output(true, &format!("{cert}: unknown\n"), "Response verify OK\n"),
            OpensslResult::Verified,
        ),
        (
            output(false, warning, "Response verify OK\n"),
            OpensslResult::Rejected,
        ),
        (
            output(true, warning, "Response Verify Failure\n"),
            OpensslResult::Rejected,
        ),
        (
            output(
                true,
                &format!("{cert}: ERROR: No Status found.\n"),
                "Response verify OK\n",
            ),
            OpensslResult::Rejected,
        ),
        (
            output(true, "", "Response verify OK\n"),
            OpensslResult::Rejected,
        ),
        (
            output(false, "", "Responder Error: trylater (3)\n"),
            OpensslResult::Rejected,
        ),
    ] {
        let finding = check_with(&manifest, id, &single(answer.clone()), "ocsp-output")?;
        assert_eq!(finding.actual, Ok(expected), "{answer:?}");
    }
    Ok(())
}

#[test]
fn a_timestamp_token_verifies_with_verification_ok() -> TestResult {
    let manifest = committed()?;
    for (answer, expected) in [
        (
            output(true, "Verification: OK\n", "Using configuration from x\n"),
            OpensslResult::Verified,
        ),
        (
            output(false, "Verification: OK\n", ""),
            OpensslResult::Rejected,
        ),
        (
            output(true, "Verification: FAILED\n", ""),
            OpensslResult::Rejected,
        ),
        (
            output(true, "", "Verification: OK\n"),
            OpensslResult::Rejected,
        ),
    ] {
        let finding = check_with(
            &manifest,
            "timestamps/valid",
            &single(answer.clone()),
            "ts-output",
        )?;
        assert_eq!(finding.actual, Ok(expected), "{answer:?}");
    }
    Ok(())
}

#[test]
fn a_private_key_parses_with_exit_0() -> TestResult {
    let manifest = committed()?;
    for (answer, expected) in [
        (output(true, "", ""), OpensslResult::Parsed),
        (
            output(false, "", "Could not read key\n"),
            OpensslResult::Rejected,
        ),
    ] {
        let finding = check_with(
            &manifest,
            "pki/keys/root-ca",
            &single(answer.clone()),
            "key-output",
        )?;
        assert_eq!(finding.actual, Ok(expected), "{answer:?}");
    }
    Ok(())
}

#[test]
fn ocsp_status_is_read_after_the_certificate_and_its_warnings() {
    let cert = "./pki/signer-p256.pem";
    assert_eq!(
        ocsp_status("./pki/signer-p256.pem: good\n", cert),
        Some("good")
    );
    assert_eq!(
        ocsp_status(
            "./pki/signer-p256.pem: WARNING: Status times invalid.\nerror line\nrevoked\n\tReason: x\n",
            cert
        ),
        Some("revoked")
    );
    assert_eq!(
        ocsp_status("./pki/signer-p256.pem: unknown\r\n", cert),
        Some("unknown")
    );
    for stdout in [
        "",
        "good\n",
        "./pki/signer-p256.pem: ERROR: No Status found.\n",
        "./pki/signer-p256.pem: WARNING: Status times invalid.\n",
        "./pki/signer-p384.pem: good\n",
        "x./pki/signer-p256.pem: good\n",
        "./pki/signer-p256.pem: goods\n",
        "./pki/signer-p256.pem:good\n",
    ] {
        assert_eq!(ocsp_status(stdout, cert), None, "{stdout:?}");
    }
}

#[test]
fn the_covered_certificate_is_the_first_sentence_of_the_notes() {
    assert_eq!(
        covered_certificate("Covered certificate: pki/signer-p256."),
        Some("pki/signer-p256")
    );
    assert_eq!(
        covered_certificate("Covered certificate: pki/signer-p256. More text. Here."),
        Some("pki/signer-p256")
    );
    for notes in [
        "",
        "Covered certificate: ",
        "Covered certificate: .",
        "Covered certificate: pki/signer-p256",
        "covered certificate: pki/signer-p256.",
        "A note. Covered certificate: pki/signer-p256.",
        "Covered certificate: pki/a b.",
    ] {
        assert_eq!(covered_certificate(notes), None, "{notes:?}");
    }
}

// Findings that are errors.

#[test]
fn a_failed_run_is_a_mismatch_that_names_the_reason() -> TestResult {
    let manifest = committed()?;
    let runner = |_: &[OsString]| Err(RunError::TimedOut(std::time::Duration::from_secs(60)));
    let finding = check_with(&manifest, "pki/signer-p256", &runner, "run-error")?;
    assert!(!finding.matches());
    let message = finding.actual.err().unwrap_or_default();
    assert!(message.contains("ran longer than 60 s"), "{message}");
    Ok(())
}

#[test]
fn missing_links_and_notes_are_reported() -> TestResult {
    let mut manifest = committed()?;
    artefact_mut(&mut manifest, "crl/ca-rsa")?.links = Links::default();
    artefact_mut(&mut manifest, "ocsp/signer-p256")?.notes =
        Some("No covered certificate.".to_owned());
    artefact_mut(&mut manifest, "ocsp/signer-p384")?.notes = None;
    artefact_mut(&mut manifest, "ocsp/signer-p521")?.notes =
        Some("Covered certificate: pki/no-such-certificate.".to_owned());
    artefact_mut(&mut manifest, "ocsp/tsa")?.notes =
        Some("Covered certificate: crl/root-ca.".to_owned());
    artefact_mut(&mut manifest, "ocsp/nonce")?.notes =
        Some("Covered certificate: pki/root-ca.".to_owned());
    artefact_mut(&mut manifest, "timestamps/valid")?
        .links
        .content = None;
    artefact_mut(&mut manifest, "timestamps/imprint-mismatch")?.links = Links::default();
    let dir = scratch("missing-links")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    for (id, reason) in [
        ("crl/ca-rsa", "issuer"),
        ("ocsp/signer-p256", "covered certificate"),
        ("ocsp/signer-p384", "covered certificate"),
        ("ocsp/signer-p521", "pki/no-such-certificate"),
        ("ocsp/tsa", "crl/root-ca"),
        ("ocsp/nonce", "issuer"),
        ("timestamps/valid", "content"),
        ("timestamps/imprint-mismatch", "issuer"),
    ] {
        let finding = checker.check(artefact(&manifest, id)?);
        let message = finding.actual.err().unwrap_or_default();
        assert!(message.contains(reason), "{id}: {message}");
    }
    assert!(oracle.calls.borrow().is_empty());
    Ok(())
}

#[test]
fn an_unreadable_bundle_member_is_reported() -> TestResult {
    let mut manifest = committed()?;
    artefact_mut(&mut manifest, "pki/root-ca")?.path = PathBuf::from("pki/no-such-root.pem");
    let dir = scratch("unreadable")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let finding = checker.check(artefact(&manifest, "pki/signer-p256")?);
    let message = finding.actual.err().unwrap_or_default();
    assert!(message.contains("pki/no-such-root.pem"), "{message}");
    Ok(())
}

#[test]
fn documents_are_not_applicable_and_run_nothing() -> TestResult {
    let mut manifest = committed()?;
    manifest.artefacts.push(Artefact {
        id: "documents/pades".to_owned(),
        path: PathBuf::from("documents/pades.pdf"),
        sha256: "0".repeat(64),
        kind: Kind::SignedDocument,
        purpose: "A signed PDF.".to_owned(),
        expected_openssl: OpensslResult::NotApplicable,
        expected_dss: DssResult::NotApplicable,
        links: Links::default(),
        notes: None,
    });
    let dir = scratch("documents")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    for id in ["timestamps/content", "documents/pades"] {
        let finding = checker.check(artefact(&manifest, id)?);
        assert_eq!(finding.actual, Ok(OpensslResult::NotApplicable), "{id}");
        assert!(finding.matches());
        assert!(finding.detail.is_empty());
    }
    assert!(oracle.calls.borrow().is_empty());
    artefact_mut(&mut manifest, "timestamps/content")?.expected_openssl = OpensslResult::Parsed;
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    assert!(
        !checker
            .check(artefact(&manifest, "timestamps/content")?)
            .matches()
    );
    Ok(())
}

#[test]
fn signed_documents_with_an_openssl_result_are_not_supported_yet() -> TestResult {
    let mut manifest = committed()?;
    manifest.artefacts.push(Artefact {
        id: "documents/cades".to_owned(),
        path: PathBuf::from("documents/cades.p7m"),
        sha256: "0".repeat(64),
        kind: Kind::SignedDocument,
        purpose: "A CAdES signature.".to_owned(),
        expected_openssl: OpensslResult::Verified,
        expected_dss: DssResult::NotApplicable,
        links: Links::default(),
        notes: None,
    });
    let dir = scratch("cades")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let finding = checker.check(artefact(&manifest, "documents/cades")?);
    let message = finding.actual.err().unwrap_or_default();
    assert!(message.contains("not supported yet"), "{message}");
    assert!(oracle.calls.borrow().is_empty());
    Ok(())
}

// The comparison with the manifest (acceptance criterion 5).

#[test]
fn the_committed_corpus_matches_an_openssl_that_agrees_with_it() -> TestResult {
    let manifest = committed()?;
    let dir = scratch("agree")?;
    let oracle = Oracle::new(&manifest);
    let report = verify(&manifest, &testdata(), &dir, &oracle)?;
    assert_eq!(report.version, manifest.header.openssl_version);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>(),
        manifest
            .artefacts
            .iter()
            .map(|a| a.id.as_str())
            .collect::<Vec<_>>()
    );
    let mismatches: Vec<_> = report.mismatches().collect();
    assert!(mismatches.is_empty(), "{mismatches:#?}");
    Ok(())
}

#[test]
fn a_wrong_expected_result_is_a_mismatch() -> TestResult {
    let manifest = committed()?;
    let oracle = Oracle::new(&manifest);
    for (id, wrong) in [
        ("crl/ca-rsa", OpensslResult::Rejected),
        ("pki/signer-p384", OpensslResult::Rejected),
        ("ocsp/unknown", OpensslResult::Rejected),
        ("timestamps/imprint-mismatch", OpensslResult::Verified),
        ("pki/keys/root-ca", OpensslResult::Verified),
        ("pki/root-ca", OpensslResult::Parsed),
    ] {
        let mut corrupted = manifest.clone();
        artefact_mut(&mut corrupted, id)?.expected_openssl = wrong;
        let dir = scratch("wrong")?;
        let report = verify(&corrupted, &testdata(), &dir, &oracle)?;
        let mismatches: Vec<_> = report.mismatches().collect();
        assert_eq!(mismatches.len(), 1, "{id}: {mismatches:#?}");
        assert_eq!(mismatches[0].id, id);
        assert_eq!(mismatches[0].expected, wrong);
        assert!(mismatches[0].actual.is_ok());
        assert_ne!(mismatches[0].actual, Ok(wrong));
    }
    Ok(())
}

// Missing input files.

/// A missing file makes OpenSSL fail, which must not pass for the
/// rejection that the manifest expects: the check cannot run.
#[test]
fn a_missing_input_file_is_a_check_error_not_a_rejection() -> TestResult {
    for (id, missing, expected) in [
        ("ocsp/try-later", "ocsp/try-later", OpensslResult::Rejected),
        (
            "timestamps/imprint-mismatch",
            "timestamps/imprint-mismatch",
            OpensslResult::Rejected,
        ),
        (
            "pki/signer-expired",
            "pki/signer-expired",
            OpensslResult::Rejected,
        ),
        (
            "crl/ca-ecdsa-wrong-key",
            "crl/ca-ecdsa-wrong-key",
            OpensslResult::Rejected,
        ),
        (
            "pki/keys/root-ca",
            "pki/keys/root-ca",
            OpensslResult::Parsed,
        ),
        (
            "timestamps/valid",
            "timestamps/content",
            OpensslResult::Verified,
        ),
        (
            "ocsp/signer-p256",
            "pki/signer-p256",
            OpensslResult::Verified,
        ),
        ("ocsp/signer-p256", "pki/ca-ecdsa", OpensslResult::Verified),
        (
            "ocsp/signer-p256",
            "ocsp/signer-p256",
            OpensslResult::Verified,
        ),
        ("pki/signer-p256", "crl/ca-ecdsa", OpensslResult::Verified),
    ] {
        let mut manifest = committed()?;
        artefact_mut(&mut manifest, missing)?.path = PathBuf::from("missing/file.der");
        let dir = scratch("missing")?;
        let oracle = Oracle::new(&manifest);
        let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
        let finding = checker.check(artefact(&manifest, id)?);
        assert_eq!(finding.expected, expected);
        let message = finding.actual.err().unwrap_or_default();
        assert!(
            message.contains("missing/file.der"),
            "{id} without {missing}: {message}"
        );
        assert!(oracle.calls.borrow().is_empty(), "{id} without {missing}");
    }
    Ok(())
}

// Files in other forms.

/// A corpus with the root in DER, its key in DER, and the CA certificate
/// in PEM without a final line ending.
fn other_forms(dir: &Path) -> Result<Manifest, Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir.join("pki/keys"))?;
    let root = corpus_file("pki/root-ca.pem")?;
    let (_, root_der) = der::pem::decode_vec(&root).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("pki/root-ca.der"), &root_der)?;
    let key = corpus_file("pki/keys/root-ca.test-key.pem")?;
    let (_, key_der) = der::pem::decode_vec(&key).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("pki/keys/root-ca.der"), key_der)?;
    let ca = String::from_utf8(corpus_file("pki/ca-ecdsa.pem")?)?;
    std::fs::write(dir.join("pki/ca-ecdsa.pem"), ca.trim_end())?;
    let mut manifest = committed()?;
    manifest
        .artefacts
        .retain(|a| ["pki/root-ca", "pki/keys/root-ca", "pki/ca-ecdsa"].contains(&a.id.as_str()));
    artefact_mut(&mut manifest, "pki/root-ca")?.path = PathBuf::from("pki/root-ca.der");
    artefact_mut(&mut manifest, "pki/keys/root-ca")?.path = PathBuf::from("pki/keys/root-ca.der");
    artefact_mut(&mut manifest, "pki/ca-ecdsa")?
        .links
        .revocation
        .clear();
    Ok(manifest)
}

#[test]
fn der_files_and_pem_without_a_final_line_ending_are_handled() -> TestResult {
    let dir = scratch("other-forms")?;
    let corpus = dir.join("corpus");
    let manifest = other_forms(&corpus)?;
    let bundles = dir.join("scratch");
    std::fs::create_dir_all(&bundles)?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &corpus, &bundles, &oracle);
    assert_eq!(
        strings(&checker.key_args(artefact(&manifest, "pki/keys/root-ca")?)?),
        [
            "pkey",
            "-inform",
            "DER",
            "-in",
            &absolute(&corpus)
                .join("pki/keys/root-ca.der")
                .to_string_lossy(),
            "-noout"
        ]
    );
    checker.certificate_args(artefact(&manifest, "pki/ca-ecdsa")?, &[])?;
    // The root in DER is written in PEM, as the committed file is.
    assert_eq!(
        std::fs::read(bundle_file(&bundles, 1))?,
        corpus_file("pki/root-ca.pem")?
    );
    let ca = String::from_utf8(corpus_file("pki/ca-ecdsa.pem")?)?;
    let crl = artefact(&committed()?, "crl/root-ca")?.clone();
    let mut with_crl = manifest.clone();
    with_crl.artefacts.push(crl);
    std::fs::create_dir_all(corpus.join("crl"))?;
    std::fs::copy(
        testdata().join("crl/root-ca.crl"),
        corpus.join("crl/root-ca.crl"),
    )?;
    let checker = Checker::new(&with_crl, &corpus, &bundles, &oracle);
    let ca_artefact = artefact(&with_crl, "pki/ca-ecdsa")?;
    let crl_artefact = artefact(&with_crl, "crl/root-ca")?;
    let path = checker.bundle(&[ca_artefact, crl_artefact])?;
    assert_eq!(
        String::from_utf8(std::fs::read(bundles.join(path))?)?,
        format!("{ca}{}", pem_of("crl/root-ca.crl", "X509 CRL")?)
    );
    Ok(())
}

#[test]
fn a_corpus_file_larger_than_the_limit_is_refused() -> TestResult {
    let dir = scratch("large")?;
    let corpus = dir.join("corpus");
    std::fs::create_dir_all(corpus.join("pki"))?;
    let len = usize::try_from(MAX_FILE_LEN)?;
    std::fs::write(corpus.join("pki/root-ca.pem"), vec![b' '; len + 1])?;
    let mut manifest = committed()?;
    manifest.artefacts.retain(|a| a.id == "pki/root-ca");
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &corpus, &dir, &oracle);
    let root = artefact(&manifest, "pki/root-ca")?;
    let error = checker.read(root).err().unwrap_or_default();
    assert!(error.contains("is larger than 1048576 bytes"), "{error}");
    std::fs::write(corpus.join("pki/root-ca.pem"), vec![b' '; len])?;
    assert_eq!(checker.read(root)?.len(), len);
    Ok(())
}

#[test]
fn a_detail_keeps_the_start_of_long_output() {
    let long: String = (1..=30).map(|n| format!("line {n}\n")).collect();
    let detail = describe(&os(&["version"]), &output(true, &long, "error\n"));
    assert!(detail.starts_with("openssl version\nline 1\n"), "{detail}");
    assert!(detail.contains("line 20\n[...]\nerror\n"), "{detail}");
    assert!(!detail.contains("line 21"), "{detail}");
    let short: String = (1..=20).map(|n| format!("line {n}\n")).collect();
    assert!(!describe(&os(&["version"]), &output(true, &short, "")).contains("[...]"));
    assert_eq!(
        describe(&os(&["version"]), &output(true, "", "")),
        "openssl version\n"
    );
}

#[test]
fn the_errors_name_the_versions() {
    assert_eq!(
        OpensslError::LibraryMismatch {
            program: "3.5.9".to_owned(),
            library: "3.5.8".to_owned()
        }
        .to_string(),
        "openssl is OpenSSL 3.5.9 but uses the library of OpenSSL 3.5.8"
    );
    assert!(
        OpensslError::UnknownVersion("LibreSSL 3.3.6\n".to_owned())
            .to_string()
            .contains("\"LibreSSL 3.3.6\\n\", which is not the version of an OpenSSL release")
    );
    assert_eq!(
        OpensslError::Run(RunError::Spawn("x".to_owned())).to_string(),
        "openssl cannot be started: x"
    );
}

#[test]
fn a_timestamp_token_without_a_chain_is_checked_with_its_signer_as_anchor() -> TestResult {
    let mut manifest = committed()?;
    let token = artefact_mut(&mut manifest, "timestamps/valid")?;
    token.links.issuer = Some("pki/root-ca".to_owned());
    token.links.chain.clear();
    let dir = scratch("ts-no-chain")?;
    let oracle = Oracle::new(&manifest);
    let checker = Checker::new(&manifest, &testdata(), &dir, &oracle);
    let args = strings(&checker.timestamp_args(artefact(&manifest, "timestamps/valid")?)?);
    assert_eq!(value_after(&args, "-CAfile"), [bundle(&dir, 1)]);
    assert_eq!(value_after(&args, "-untrusted"), [bundle(&dir, 2)]);
    for n in [1, 2] {
        assert_eq!(
            std::fs::read(bundle_file(&dir, n))?,
            corpus_file("pki/root-ca.pem")?
        );
    }
    Ok(())
}

// The scratch directory.

/// OpenSSL runs in the corpus, so a scratch directory under a relative
/// temporary directory must still be named by an absolute path.
#[test]
fn a_scratch_directory_under_a_relative_base_is_absolute() -> TestResult {
    let base = PathBuf::from(format!(
        "../../target/sigillum-testpki-relative-base-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&base)?;
    let guard = Cleanup(base.clone());
    let scratch = Scratch::create_in(&base)?;
    assert!(scratch.path().is_absolute(), "{}", scratch.path().display());
    assert!(scratch.path().is_dir());
    drop(scratch);
    drop(guard);
    assert!(!base.exists());
    Ok(())
}

#[test]
fn a_scratch_directory_is_removed_when_dropped() -> TestResult {
    let base = base("removed")?;
    let scratch = Scratch::create_in(&base.0)?;
    let path = scratch.path().to_path_buf();
    assert!(path.is_dir());
    std::fs::write(path.join("file"), b"x")?;
    let other = Scratch::create_in(&base.0)?;
    assert_ne!(other.path(), path);
    drop(scratch);
    assert!(!path.exists());
    assert!(other.path().is_dir());
    Ok(())
}

/// Bundles are named by bare file names, without the path of the scratch
/// directory, so that a path with commas or white space cannot be split
/// by `openssl ts -untrusted`.
#[test]
fn bundles_are_named_without_the_scratch_path() -> TestResult {
    let base = base("separators")?;
    let unusual = base.0.join("temporary files, with a space");
    std::fs::create_dir_all(&unusual)?;
    let scratch = Scratch::create_in(&unusual)?;
    let manifest = committed()?;
    let oracle = Oracle::new(&manifest);
    let report = verify(&manifest, &testdata(), scratch.path(), &oracle)?;
    assert_eq!(report.mismatches().count(), 0);
    let calls = oracle.calls.borrow();
    let mut bundles = 0;
    for arg in calls.iter().flatten() {
        assert!(!arg.contains("temporary files"), "{arg}");
        if arg.starts_with("bundle-") {
            bundles += 1;
            assert!(!arg.contains([',', ' ', '/', '\\']), "{arg}");
            assert!(scratch.path().join(arg).is_file(), "{arg}");
        }
    }
    assert!(bundles > 100, "{bundles}");
    Ok(())
}

proptest! {
    #[test]
    fn parse_version_reads_any_release_number(
        version in "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,3}[a-z]?",
        date in "[0-9]{1,2} [A-Z][a-z]{2} [0-9]{4}",
    ) {
        let text = format!("OpenSSL {version} {date} (Library: OpenSSL {version} {date})\n");
        prop_assert_eq!(parse_version(&text), Ok(version.clone()));
        let text = format!("OpenSSL {version} {date}\n");
        prop_assert_eq!(parse_version(&text), Ok(version));
    }

    #[test]
    fn the_output_readers_accept_any_text(text in ".{0,200}", cert in ".{0,20}") {
        let _ = parse_version(&text);
        let _ = ocsp_status(&text, &cert);
        let _ = covered_certificate(&text);
        let _ = crl_times(&text);
    }
}
