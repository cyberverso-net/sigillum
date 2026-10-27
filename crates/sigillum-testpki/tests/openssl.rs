//! Integration tests of `sigillum-testpki verify --openssl` with a real
//! OpenSSL: the committed corpus, a copy whose manifest expects a wrong
//! result, and a manifest that names another OpenSSL version.
//!
//! They need the OpenSSL release that the manifest header names, which
//! few machines have. They run when the environment variable
//! `SIGILLUM_TESTPKI_OPENSSL` names that program, as the workflow
//! `fixtures-openssl.yml` sets it, and otherwise only say that they did
//! not run. The tests of `src/openssl/tests.rs` cover the same logic on
//! every platform, with a program that stands in for OpenSSL.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The variable that names the OpenSSL program.
const VARIABLE: &str = "SIGILLUM_TESTPKI_OPENSSL";

/// The variable that, set to `1`, makes a missing program a failure
/// rather than a reason not to run, as the workflow sets it.
const REQUIRED: &str = "SIGILLUM_TESTPKI_OPENSSL_REQUIRED";

/// The program that the variables name: `Ok(None)` when it is not named
/// and not required, and an error when it is required but not named, or
/// when `required` is neither `0` nor `1`.
fn program_from(
    program: Option<String>,
    required: Option<String>,
) -> Result<Option<String>, String> {
    let required = match required.as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        Some(other) => return Err(format!("{REQUIRED} is {other:?}, not 0 or 1")),
    };
    match program.filter(|p| !p.is_empty()) {
        Some(program) => Ok(Some(program)),
        None if required => Err(format!("{REQUIRED} is 1, but {VARIABLE} names no program")),
        None => Ok(None),
    }
}

/// The OpenSSL program to test with, or `None` after saying that the test
/// does not run.
fn openssl(test: &str) -> Result<Option<String>, String> {
    let program = program_from(std::env::var(VARIABLE).ok(), std::env::var(REQUIRED).ok())?;
    if program.is_none() {
        eprintln!("{test}: {VARIABLE} is not set, so this test does not run OpenSSL");
    }
    Ok(program)
}

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn verify(program: &str, manifest: &Path) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_sigillum-testpki"))
        .args([
            "verify",
            "--openssl",
            "--openssl-program",
            program,
            "--manifest",
        ])
        .arg(manifest)
        .output()
}

/// A fresh copy of the committed corpus, in a directory named after the
/// test.
fn copy_of_corpus(name: &str) -> std::io::Result<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    copy_dir(&testdata(), &dir)?;
    Ok(dir)
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&entry.path(), &target)?;
        } else {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

/// Replaces `from` by `to` in the entry `id` of the manifest text, and
/// nowhere else.
fn edit_entry(manifest: &str, id: &str, from: &str, to: &str) -> Result<String, String> {
    let start = manifest
        .find(&format!("id = \"{id}\"\n"))
        .ok_or_else(|| format!("no entry {id}"))?;
    let end = manifest[start..]
        .find("\n[[artefact]]")
        .map_or(manifest.len(), |offset| start + offset);
    let entry = &manifest[start..end];
    if entry.matches(from).count() != 1 {
        return Err(format!("{from} is not in the entry {id} exactly once"));
    }
    Ok(format!(
        "{}{}{}",
        &manifest[..start],
        entry.replace(from, to),
        &manifest[end..]
    ))
}

#[test]
fn the_committed_corpus_matches_openssl() -> TestResult {
    let Some(program) = openssl("the_committed_corpus_matches_openssl")? else {
        return Ok(());
    };
    let output = verify(&program, &testdata().join("manifest.toml"))?;
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(stdout.contains(", 0 not as expected"), "{stdout}");
    assert!(stderr.is_empty(), "{stderr}");
    Ok(())
}

#[test]
fn a_wrong_expected_result_makes_verify_fail() -> TestResult {
    let Some(program) = openssl("a_wrong_expected_result_makes_verify_fail")? else {
        return Ok(());
    };
    let dir = copy_of_corpus("openssl-wrong-expected-result")?;
    let manifest = dir.join("manifest.toml");
    let committed = std::fs::read_to_string(&manifest)?;
    let corrupted = edit_entry(
        &committed,
        "crl/ca-rsa",
        "expected-openssl = \"verified\"",
        "expected-openssl = \"rejected\"",
    )?;
    std::fs::write(&manifest, corrupted)?;
    let output = verify(&program, &manifest)?;
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stdout.contains(", 1 not as expected"), "{stdout}");
    assert!(
        stderr.contains("crl/ca-rsa: OpenSSL gives verified, the manifest expects rejected"),
        "{stderr}"
    );
    assert!(stderr.contains("openssl crl"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_cades_signature_that_does_not_verify_makes_verify_fail() -> TestResult {
    let Some(program) = openssl("a_cades_signature_that_does_not_verify_makes_verify_fail")? else {
        return Ok(());
    };
    let dir = copy_of_corpus("openssl-cades-tampered")?;
    // The last octet of a CAdES B-B signature is the last octet of its signature value.
    let file = dir.join("signed/cades-enveloping-b-b-rsa.p7m");
    let mut bytes = std::fs::read(&file)?;
    if let Some(last) = bytes.last_mut() {
        *last ^= 0xff;
    }
    std::fs::write(&file, bytes)?;
    let output = verify(&program, &dir.join("manifest.toml"))?;
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stdout.contains(", 1 not as expected"), "{stdout}");
    assert!(
        stderr.contains(
            "signed/cades-enveloping-b-b-rsa: OpenSSL gives rejected, the manifest expects verified"
        ),
        "{stderr}"
    );
    assert!(stderr.contains("openssl cms -verify"), "{stderr}");
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn another_openssl_version_in_the_manifest_makes_verify_fail() -> TestResult {
    let Some(program) = openssl("another_openssl_version_in_the_manifest_makes_verify_fail")?
    else {
        return Ok(());
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("openssl-other-version");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let manifest = dir.join("manifest.toml");
    let committed = std::fs::read_to_string(testdata().join("manifest.toml"))?;
    let start = committed
        .find("openssl-version = \"")
        .ok_or("no openssl-version")?;
    let end = start
        + committed[start..]
            .find('\n')
            .ok_or("no end of the openssl-version line")?;
    std::fs::write(
        &manifest,
        format!(
            "{}openssl-version = \"0.0.1\"{}",
            &committed[..start],
            &committed[end..]
        ),
    )?;
    let output = verify(&program, &manifest)?;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr
            .contains("the manifest records the results of OpenSSL 0.0.1, but openssl is OpenSSL "),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn another_openssl_version_given_on_the_command_line_must_be_the_one_run() -> TestResult {
    let Some(program) =
        openssl("another_openssl_version_given_on_the_command_line_must_be_the_one_run")?
    else {
        return Ok(());
    };
    let output = Command::new(env!("CARGO_BIN_EXE_sigillum-testpki"))
        .args(["verify", "--openssl", "--openssl-program", &program])
        .args(["--openssl-version", "0.0.1", "--manifest"])
        .arg(testdata().join("manifest.toml"))
        .output()?;
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(
        stderr.contains("--openssl-version names OpenSSL 0.0.1, but openssl is OpenSSL "),
        "{stderr}"
    );
    assert!(output.stdout.is_empty());
    Ok(())
}

/// A fixture that is expected to be rejected, and is missing, must not
/// pass for its rejection.
#[test]
fn a_missing_fixture_makes_verify_fail() -> TestResult {
    let Some(program) = openssl("a_missing_fixture_makes_verify_fail")? else {
        return Ok(());
    };
    let dir = copy_of_corpus("openssl-missing-fixture")?;
    std::fs::remove_file(dir.join("ocsp/try-later.der"))?;
    std::fs::remove_file(dir.join("timestamps/imprint-mismatch.tst"))?;
    let output = verify(&program, &dir.join("manifest.toml"))?;
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{stdout}{stderr}");
    assert!(stdout.contains(", 2 not as expected"), "{stdout}");
    for (id, path) in [
        ("ocsp/try-later", "ocsp/try-later.der"),
        (
            "timestamps/imprint-mismatch",
            "timestamps/imprint-mismatch.tst",
        ),
    ] {
        assert!(
            stderr.lines().any(|line| line.starts_with(&format!(
                "sigillum-testpki verify: {id}: the OpenSSL check cannot run: {path}: "
            )) && line.ends_with("; the manifest expects rejected")),
            "{stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn a_required_program_must_be_named() {
    let some = |text: &str| Some(text.to_owned());
    assert_eq!(program_from(None, None), Ok(None));
    assert_eq!(program_from(None, some("0")), Ok(None));
    assert_eq!(program_from(some(""), None), Ok(None));
    assert_eq!(program_from(some("openssl"), None), Ok(some("openssl")));
    assert_eq!(
        program_from(some("openssl"), some("1")),
        Ok(some("openssl"))
    );
    for (program, required) in [
        (None, "1"),
        (some(""), "1"),
        (some("openssl"), "yes"),
        (None, ""),
    ] {
        let result = program_from(program.clone(), some(required));
        assert!(result.is_err(), "{program:?} {required:?}: {result:?}");
    }
}

#[test]
fn edit_entry_changes_one_entry_only() -> TestResult {
    let manifest = "[[artefact]]\nid = \"a\"\nx = 1\n\n[[artefact]]\nid = \"b\"\nx = 1\n";
    assert_eq!(
        edit_entry(manifest, "b", "x = 1", "x = 2")?,
        "[[artefact]]\nid = \"a\"\nx = 1\n\n[[artefact]]\nid = \"b\"\nx = 2\n"
    );
    assert_eq!(
        edit_entry(manifest, "a", "x = 1", "x = 2")?,
        "[[artefact]]\nid = \"a\"\nx = 2\n\n[[artefact]]\nid = \"b\"\nx = 1\n"
    );
    assert!(edit_entry(manifest, "c", "x = 1", "x = 2").is_err());
    assert!(edit_entry(manifest, "a", "y = 1", "x = 2").is_err());
    Ok(())
}

// A corpus with two intermediate CAs, built with OpenSSL itself.

/// Runs `program` with `args` in `dir`, with an empty configuration file.
fn run_openssl(program: &str, dir: &Path, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(dir)
        .env("OPENSSL_CONF", dir.join("keys/empty.cnf"))
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "openssl {}: {}",
            args.join(" "),
            text(&output.stderr)
        ))
    }
}

/// Issues `name`, with a P-256 key, from `issuer`, valid from 2025 to
/// 2040, with the extensions `extensions`.
fn issue(
    program: &str,
    dir: &Path,
    name: &str,
    issuer: &str,
    serial: &str,
    extensions: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let key = format!("keys/{name}.pem");
    let request = format!("keys/{name}.csr");
    let ext = format!("keys/{name}.ext");
    run_openssl(
        program,
        dir,
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            &key,
        ],
    )?;
    run_openssl(
        program,
        dir,
        &[
            "req",
            "-new",
            "-key",
            &key,
            "-subj",
            &format!("/CN=multi {name}"),
            "-out",
            &request,
        ],
    )?;
    std::fs::write(dir.join(&ext), extensions)?;
    run_openssl(
        program,
        dir,
        &[
            "x509",
            "-req",
            "-in",
            &request,
            "-CA",
            &format!("pki/{issuer}.pem"),
            "-CAkey",
            &format!("keys/{issuer}.pem"),
            "-set_serial",
            serial,
            "-not_before",
            "20250101000000Z",
            "-not_after",
            "20400101000000Z",
            "-extfile",
            &ext,
            "-out",
            &format!("pki/{name}.pem"),
        ],
    )?;
    Ok(())
}

/// One manifest entry, with the digest of its file.
fn entry(
    dir: &Path,
    id: &str,
    path: &str,
    kind: &str,
    expected: &str,
    extra: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(std::fs::read(dir.join(path))?);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "\n[[artefact]]\nid = \"{id}\"\npath = \"{path}\"\nsha256 = \"{hex}\"\nkind = \"{kind}\"\npurpose = \"A fixture of the test.\"\nexpected-openssl = \"{expected}\"\nexpected-dss = \"not-applicable\"\n{extra}"
    ))
}

/// A corpus whose certificates sit below two intermediate CAs, with an
/// OCSP response that the issuing CA signs and a timestamp token without
/// certificates, as a token is when its request did not set certReq
/// (RFC 3161, section 2.4.1).
fn multi_intermediate_corpus(
    program: &str,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["pki", "keys", "ocsp", "timestamps"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    std::fs::write(dir.join("keys/empty.cnf"), "")?;
    let ca = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n";
    run_openssl(
        program,
        &dir,
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "keys/root.pem",
        ],
    )?;
    run_openssl(
        program,
        &dir,
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "keys/root.pem",
            "-subj",
            "/CN=multi root",
            "-not_before",
            "20250101000000Z",
            "-not_after",
            "20400101000000Z",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-out",
            "pki/root.pem",
        ],
    )?;
    issue(program, &dir, "ca1", "root", "2", ca)?;
    issue(program, &dir, "ca2", "ca1", "3", ca)?;
    issue(
        program,
        &dir,
        "leaf",
        "ca2",
        "4",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n",
    )?;
    issue(
        program,
        &dir,
        "tsa",
        "ca2",
        "5",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n",
    )?;
    issue(
        program,
        &dir,
        "responder",
        "ca2",
        "6",
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=OCSPSigning\n",
    )?;
    std::fs::write(
        dir.join("keys/index.txt"),
        "V\t400101000000Z\t\t04\tunknown\t/CN=multi leaf\n",
    )?;
    run_openssl(
        program,
        &dir,
        &[
            "ocsp",
            "-issuer",
            "pki/ca2.pem",
            "-cert",
            "pki/leaf.pem",
            "-no_nonce",
            "-reqout",
            "keys/request.der",
        ],
    )?;
    run_openssl(
        program,
        &dir,
        &[
            "ocsp",
            "-index",
            "keys/index.txt",
            "-rsigner",
            "pki/ca2.pem",
            "-rkey",
            "keys/ca2.pem",
            "-CA",
            "pki/ca2.pem",
            "-reqin",
            "keys/request.der",
            "-respout",
            "ocsp/leaf.der",
            "-ndays",
            "3650",
        ],
    )?;
    // A response from a delegated responder, without the certs field,
    // which RFC 6960, section 4.2.1, makes optional.
    run_openssl(
        program,
        &dir,
        &[
            "ocsp",
            "-index",
            "keys/index.txt",
            "-rsigner",
            "pki/responder.pem",
            "-rkey",
            "keys/responder.pem",
            "-CA",
            "pki/ca2.pem",
            "-reqin",
            "keys/request.der",
            "-respout",
            "ocsp/leaf-delegated.der",
            "-resp_no_certs",
            "-ndays",
            "3650",
        ],
    )?;
    std::fs::write(dir.join("timestamps/content.txt"), "content\n")?;
    std::fs::write(
        dir.join("keys/ts.cnf"),
        "[tsa]\ndefault_tsa = tsa1\n[tsa1]\nserial = keys/serial\nsigner_digest = sha256\ndefault_policy = 1.3.6.1.4.1.32473.1.2\ndigests = sha256\ness_cert_id_alg = sha256\ness_cert_id_chain = no\n",
    )?;
    std::fs::write(dir.join("keys/serial"), "01\n")?;
    // Without -cert, the request does not ask for the certificate, so the
    // token carries none.
    run_openssl(
        program,
        &dir,
        &[
            "ts",
            "-query",
            "-data",
            "timestamps/content.txt",
            "-sha256",
            "-no_nonce",
            "-out",
            "keys/query.tsq",
        ],
    )?;
    run_openssl(
        program,
        &dir,
        &[
            "ts",
            "-reply",
            "-config",
            "keys/ts.cnf",
            "-queryfile",
            "keys/query.tsq",
            "-signer",
            "pki/tsa.pem",
            "-inkey",
            "keys/tsa.pem",
            "-token_out",
            "-out",
            "timestamps/token.tst",
        ],
    )?;
    let version = sigillum_testpki::manifest::Manifest::load(&testdata().join("manifest.toml"))?
        .header
        .openssl_version;
    let below = |issuer: &str, chain: &str| {
        format!("links = {{ issuer = \"{issuer}\", chain = [{chain}] }}\n")
    };
    let mut manifest = format!(
        "[header]\nformat-version = 2\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"{version}\"\ndss-version = \"6.5.1\"\n"
    );
    manifest.push_str(&entry(
        &dir,
        "pki/root",
        "pki/root.pem",
        "certificate",
        "verified",
        "",
    )?);
    manifest.push_str(&entry(
        &dir,
        "pki/ca1",
        "pki/ca1.pem",
        "certificate",
        "verified",
        &below("pki/root", "\"pki/root\""),
    )?);
    manifest.push_str(&entry(
        &dir,
        "pki/ca2",
        "pki/ca2.pem",
        "certificate",
        "verified",
        &below("pki/ca1", "\"pki/ca1\", \"pki/root\""),
    )?);
    let under_ca2 = below("pki/ca2", "\"pki/ca2\", \"pki/ca1\", \"pki/root\"");
    manifest.push_str(&entry(
        &dir,
        "pki/leaf",
        "pki/leaf.pem",
        "certificate",
        "verified",
        &under_ca2,
    )?);
    manifest.push_str(&entry(
        &dir,
        "pki/tsa",
        "pki/tsa.pem",
        "certificate",
        "verified",
        &under_ca2,
    )?);
    manifest.push_str(&entry(
        &dir,
        "ocsp/leaf",
        "ocsp/leaf.der",
        "ocsp-response",
        "verified",
        &format!("{under_ca2}notes = \"Covered certificate: pki/leaf.\"\n"),
    )?);
    manifest.push_str(&entry(
        &dir,
        "pki/responder",
        "pki/responder.pem",
        "certificate",
        "verified",
        &under_ca2,
    )?);
    manifest.push_str(&entry(
        &dir,
        "ocsp/leaf-delegated",
        "ocsp/leaf-delegated.der",
        "ocsp-response",
        "verified",
        "links = { issuer = \"pki/responder\", chain = [\"pki/responder\", \"pki/ca2\", \"pki/ca1\", \"pki/root\"] }\nnotes = \"Covered certificate: pki/leaf.\"\n",
    )?);
    manifest.push_str(&entry(
        &dir,
        "timestamps/content",
        "timestamps/content.txt",
        "document",
        "not-applicable",
        "",
    )?);
    manifest.push_str(&entry(
        &dir,
        "timestamps/token",
        "timestamps/token.tst",
        "timestamp-token",
        "verified",
        "links = { issuer = \"pki/tsa\", chain = [\"pki/tsa\", \"pki/ca2\", \"pki/ca1\", \"pki/root\"], content = \"timestamps/content\" }\n",
    )?);
    std::fs::write(dir.join("manifest.toml"), manifest)?;
    Ok(dir)
}

/// OCSP responses for a certificate below two intermediate CAs, one from
/// its CA and one from a delegated responder without the certs field, and
/// a timestamp token without certificates from a TSA below them, verify.
#[test]
fn a_chain_with_two_intermediates_and_a_token_without_certificates_verify() -> TestResult {
    let Some(program) =
        openssl("a_chain_with_two_intermediates_and_a_token_without_certificates_verify")?
    else {
        return Ok(());
    };
    let dir = multi_intermediate_corpus(&program, "openssl-two-intermediates")?;
    let output = verify(&program, &dir.join("manifest.toml"))?;
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(
        stdout.contains("10 artefacts, 10 as expected, 0 not as expected"),
        "{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// `openssl ts` splits the file names of `-untrusted` at commas and white
/// space, so the checks must work in a temporary directory whose path holds
/// both.
#[test]
fn a_temporary_directory_with_a_space_and_a_comma_works() -> TestResult {
    let Some(program) = openssl("a_temporary_directory_with_a_space_and_a_comma_works")? else {
        return Ok(());
    };
    let dir = multi_intermediate_corpus(&program, "openssl-separators")?;
    let temporary = dir.join("temporary files, with a space");
    std::fs::create_dir_all(&temporary)?;
    let output = Command::new(env!("CARGO_BIN_EXE_sigillum-testpki"))
        .args([
            "verify",
            "--openssl",
            "--openssl-program",
            &program,
            "--manifest",
        ])
        .arg(dir.join("manifest.toml"))
        .env("TMPDIR", &temporary)
        .env("TMP", &temporary)
        .env("TEMP", &temporary)
        .output()?;
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(
        stdout.contains("10 artefacts, 10 as expected, 0 not as expected"),
        "{stdout}"
    );
    // The scratch directory was made there, and removed.
    assert_eq!(std::fs::read_dir(&temporary)?.count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A self-signed TSA, its own trust anchor, and two copies of a token
/// without certificates from it: one whose entry links the TSA as its
/// chain, and one whose entry links no chain.
fn self_signed_tsa_corpus(
    program: &str,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    for sub in ["pki", "keys", "timestamps"] {
        std::fs::create_dir_all(dir.join(sub))?;
    }
    std::fs::write(dir.join("keys/empty.cnf"), "")?;
    run_openssl(
        program,
        &dir,
        &[
            "genpkey",
            "-algorithm",
            "EC",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-out",
            "keys/tsa.pem",
        ],
    )?;
    run_openssl(
        program,
        &dir,
        &[
            "req",
            "-x509",
            "-new",
            "-key",
            "keys/tsa.pem",
            "-subj",
            "/CN=self-signed tsa",
            "-not_before",
            "20250101000000Z",
            "-not_after",
            "20400101000000Z",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
            "-addext",
            "keyUsage=critical,digitalSignature",
            "-addext",
            "extendedKeyUsage=critical,timeStamping",
            "-out",
            "pki/tsa.pem",
        ],
    )?;
    std::fs::write(dir.join("timestamps/content.txt"), "content\n")?;
    std::fs::write(
        dir.join("keys/ts.cnf"),
        "[tsa]\ndefault_tsa = tsa1\n[tsa1]\nserial = keys/serial\nsigner_digest = sha256\ndefault_policy = 1.3.6.1.4.1.32473.1.2\ndigests = sha256\ness_cert_id_alg = sha256\ness_cert_id_chain = no\n",
    )?;
    std::fs::write(dir.join("keys/serial"), "01\n")?;
    run_openssl(
        program,
        &dir,
        &[
            "ts",
            "-query",
            "-data",
            "timestamps/content.txt",
            "-sha256",
            "-no_nonce",
            "-out",
            "keys/query.tsq",
        ],
    )?;
    run_openssl(
        program,
        &dir,
        &[
            "ts",
            "-reply",
            "-config",
            "keys/ts.cnf",
            "-queryfile",
            "keys/query.tsq",
            "-signer",
            "pki/tsa.pem",
            "-inkey",
            "keys/tsa.pem",
            "-token_out",
            "-out",
            "timestamps/token.tst",
        ],
    )?;
    std::fs::copy(
        dir.join("timestamps/token.tst"),
        dir.join("timestamps/token-without-chain.tst"),
    )?;
    let version = sigillum_testpki::manifest::Manifest::load(&testdata().join("manifest.toml"))?
        .header
        .openssl_version;
    let mut manifest = format!(
        "[header]\nformat-version = 2\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"{version}\"\ndss-version = \"6.5.1\"\n"
    );
    manifest.push_str(&entry(
        &dir,
        "pki/tsa",
        "pki/tsa.pem",
        "certificate",
        "verified",
        "",
    )?);
    manifest.push_str(&entry(
        &dir,
        "timestamps/content",
        "timestamps/content.txt",
        "document",
        "not-applicable",
        "",
    )?);
    manifest.push_str(&entry(
        &dir,
        "timestamps/token",
        "timestamps/token.tst",
        "timestamp-token",
        "verified",
        "links = { issuer = \"pki/tsa\", chain = [\"pki/tsa\"], content = \"timestamps/content\" }\n",
    )?);
    manifest.push_str(&entry(
        &dir,
        "timestamps/token-without-chain",
        "timestamps/token-without-chain.tst",
        "timestamp-token",
        "verified",
        "links = { issuer = \"pki/tsa\", content = \"timestamps/content\" }\n",
    )?);
    std::fs::write(dir.join("manifest.toml"), manifest)?;
    Ok(dir)
}

/// A token without certificates from a TSA that is its own trust anchor
/// verifies: the signer must still be among the untrusted certificates.
#[test]
fn a_token_without_certificates_from_a_self_signed_tsa_verifies() -> TestResult {
    let Some(program) = openssl("a_token_without_certificates_from_a_self_signed_tsa_verifies")?
    else {
        return Ok(());
    };
    let dir = self_signed_tsa_corpus(&program, "openssl-self-signed-tsa")?;
    let output = verify(&program, &dir.join("manifest.toml"))?;
    let stdout = text(&output.stdout);
    let stderr = text(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(
        stdout.contains("4 artefacts, 4 as expected, 0 not as expected"),
        "{stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
