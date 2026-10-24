//! Tests of the command-line contract of `sigillum-testpki`.

use std::path::PathBuf;
use std::process::{Command, Output};

fn run(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_sigillum-testpki"))
        .args(args)
        .output()
}

fn committed_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/manifest.toml")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn help_lists_the_subcommands() -> std::io::Result<()> {
    let output = run(&["--help"])?;
    assert!(output.status.success());
    let stdout = text(&output.stdout);
    for subcommand in ["generate", "tsa", "verify"] {
        assert!(
            stdout.contains(subcommand),
            "{subcommand} missing from:\n{stdout}"
        );
    }
    Ok(())
}

#[test]
fn every_subcommand_has_help() -> std::io::Result<()> {
    for (subcommand, option) in [
        ("generate", "--manifest"),
        ("generate", "pki"),
        ("generate", "crls"),
        ("generate", "timestamps"),
        ("tsa", "--tsa-cert"),
        ("tsa", "--digest-algorithm"),
        ("tsa", "--digest"),
        ("verify", "--manifest"),
    ] {
        let output = run(&[subcommand, "--help"])?;
        assert!(output.status.success(), "{subcommand}");
        assert!(text(&output.stdout).contains(option), "{subcommand}");
    }
    Ok(())
}

#[test]
fn verify_reads_the_validation_time_from_the_manifest() -> std::io::Result<()> {
    let manifest = committed_manifest();
    let output = run(&["verify", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(3));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("2030-01-15T10:00:00Z"), "{stderr}");
    assert!(stderr.contains("not implemented"), "{stderr}");
    Ok(())
}

/// A fresh directory with a manifest that has only a header.
fn corpus(name: &str, artefacts: &str) -> std::io::Result<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("manifest.toml");
    std::fs::write(
        &path,
        format!(
            "[header]\nformat-version = 1\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"3.0.13\"\ndss-version = \"6.5.1\"\n{artefacts}"
        ),
    )?;
    Ok(path)
}

#[test]
fn generate_pki_writes_the_files_and_the_manifest() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("generate_pki_writes_the_files_and_the_manifest", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let output = run(&["generate", "pki", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("wrote 64 files"));
    let written = std::fs::read_to_string(&manifest)?;
    let parsed = sigillum_testpki::manifest::Manifest::parse(&written)?;
    assert_eq!(parsed.artefacts.len(), 64);
    for artefact in &parsed.artefacts {
        assert!(dir.join(&artefact.path).is_file(), "{}", artefact.id);
    }
    // Running again changes nothing, and the PKI entries are those of the
    // committed corpus, whatever other entries it holds.
    let output = run(&["generate", "pki", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(0));
    assert!(text(&output.stderr).is_empty(), "{}", text(&output.stderr));
    assert_eq!(std::fs::read_to_string(&manifest)?, written);
    assert!(!dir.join("manifest.toml.tmp").exists());
    let committed = sigillum_testpki::manifest::Manifest::load(&committed_manifest())?;
    let pki_entries = |m: &sigillum_testpki::manifest::Manifest| {
        m.artefacts
            .iter()
            .filter(|a| a.id.starts_with("pki/"))
            .map(|a| {
                // generate crls adds the revocation links.
                let mut a = a.clone();
                a.links.revocation.clear();
                (a.id.clone(), a)
            })
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    assert_eq!(pki_entries(&parsed), pki_entries(&committed));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generate_pki_keeps_other_artefacts() -> Result<(), Box<dyn std::error::Error>> {
    let other = "\n[[artefact]]\nid = \"doc/a\"\npath = \"doc/a.txt\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nkind = \"document\"\npurpose = \"Other\"\nexpected-openssl = \"not-applicable\"\nexpected-dss = \"not-applicable\"\n";
    let manifest = corpus("generate_pki_keeps_other_artefacts", other)?;
    let output = run(&["generate", "pki", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let parsed = sigillum_testpki::manifest::Manifest::load(&manifest)?;
    assert_eq!(parsed.artefacts.len(), 65);
    assert_eq!(parsed.artefacts[0].id, "doc/a");
    let _ = std::fs::remove_dir_all(manifest.parent().ok_or("no parent")?);
    Ok(())
}

#[test]
fn generate_pki_writes_nothing_when_the_manifest_would_be_invalid()
-> Result<(), Box<dyn std::error::Error>> {
    // Another artefact already uses the path of the root certificate.
    let clash = "\n[[artefact]]\nid = \"doc/a\"\npath = \"pki/root-ca.pem\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nkind = \"document\"\npurpose = \"Other\"\nexpected-openssl = \"not-applicable\"\nexpected-dss = \"not-applicable\"\n";
    let manifest = corpus("generate_pki_writes_nothing", clash)?;
    let before = std::fs::read_to_string(&manifest)?;
    let output = run(&["generate", "pki", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("pki/root-ca.pem"));
    assert_eq!(std::fs::read_to_string(&manifest)?, before);
    let dir = manifest.parent().ok_or("no parent")?;
    assert!(!dir.join("pki").exists());
    let _ = std::fs::remove_dir_all(dir);
    Ok(())
}

#[test]
fn generate_pki_reports_a_file_it_cannot_write() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("generate_pki_reports_a_file_it_cannot_write", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    // A directory where the root certificate should go.
    std::fs::create_dir_all(dir.join("pki/root-ca.pem"))?;
    let output = run(&["generate", "pki", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("a file cannot be written"));
    assert!(text(&output.stderr).contains("root-ca.pem"));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generate_pki_reports_a_directory_it_cannot_create() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("generate_pki_reports_a_directory_it_cannot_create", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    // A file where the pki directory should go.
    std::fs::write(dir.join("pki"), "")?;
    let output = run(&["generate", "pki", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("a file cannot be written"));
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generate_pki_prunes_stale_entries_and_reports_unlisted_files()
-> Result<(), Box<dyn std::error::Error>> {
    let entry = |id: &str, path: &str, kind: &str| {
        format!(
            "\n[[artefact]]\nid = \"{id}\"\npath = \"{path}\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nkind = \"{kind}\"\npurpose = \"Other\"\nexpected-openssl = \"not-applicable\"\nexpected-dss = \"not-applicable\"\n"
        )
    };
    let artefacts = [
        // A certificate the generator no longer produces: removed.
        entry("pki/old-signer", "pki/old-signer.pem", "certificate"),
        // Another kind under pki/, owned by another generator: kept.
        entry("pki/crl/ca-rsa", "pki/crl/ca-rsa.crl", "crl"),
    ]
    .concat();
    let manifest = corpus("generate_pki_prunes_stale_entries", &artefacts)?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    std::fs::create_dir_all(dir.join("pki/crl"))?;
    std::fs::write(dir.join("pki/old-signer.pem"), "")?;
    std::fs::write(dir.join("pki/crl/ca-rsa.crl"), "")?;
    std::fs::write(dir.join("pki/stray.pem"), "")?;
    let output = run(&["generate", "pki", "--manifest", &manifest.to_string_lossy()])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("removed the manifest entry pki/old-signer"),
        "{stderr}"
    );
    assert!(
        stderr.contains("no manifest entry names pki/old-signer.pem"),
        "{stderr}"
    );
    assert!(
        stderr.contains("no manifest entry names pki/stray.pem"),
        "{stderr}"
    );
    assert!(!stderr.contains("pki/crl/ca-rsa.crl"), "{stderr}");
    assert!(!stderr.contains("README.md"), "{stderr}");
    let parsed = sigillum_testpki::manifest::Manifest::load(&manifest)?;
    assert!(parsed.artefacts.iter().all(|a| a.id != "pki/old-signer"));
    assert!(parsed.artefacts.iter().any(|a| a.id == "pki/crl/ca-rsa"));
    // The file of the removed entry stays in place.
    assert!(dir.join("pki/old-signer.pem").is_file());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// A directory under pki/ that cannot be read makes the command fail before
/// the manifest is replaced, so the previous manifest stays in place.
#[test]
fn generate_pki_keeps_the_manifest_when_the_scan_fails() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let manifest = corpus("generate_pki_keeps_the_manifest_when_the_scan_fails", "")?;
        let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
        let locked = dir.join("pki/locked");
        std::fs::create_dir_all(&locked)?;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))?;
        // Where permissions do not stop reading, as for root, the case
        // cannot be built and the test has nothing to check.
        let readable = std::fs::read_dir(&locked).is_ok();
        let before = std::fs::read_to_string(&manifest)?;
        let output = if readable {
            None
        } else {
            Some(run(&[
                "generate",
                "pki",
                "--manifest",
                &manifest.to_string_lossy(),
            ])?)
        };
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755))?;
        if let Some(output) = output {
            assert_eq!(output.status.code(), Some(1), "{}", text(&output.stderr));
            assert!(text(&output.stderr).contains("a file cannot be written"));
            assert!(
                std::fs::read_to_string(&manifest)? == before,
                "the manifest was replaced"
            );
            assert!(!dir.join("manifest.toml.tmp").exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
    Ok(())
}

#[test]
fn generate_needs_a_known_target() -> std::io::Result<()> {
    let manifest = committed_manifest();
    let manifest = manifest.to_string_lossy();
    assert_eq!(
        run(&["generate", "--manifest", &manifest])?.status.code(),
        Some(2)
    );
    assert_eq!(
        run(&["generate", "unknown", "--manifest", &manifest])?
            .status
            .code(),
        Some(2)
    );
    let output = run(&["generate", "pki", "--manifest", "no/such/manifest.toml"])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("the manifest cannot be read"));
    Ok(())
}

fn testdata(path: &str) -> String {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata")
        .join(path)
        .to_string_lossy()
        .into_owned()
}

/// The arguments of `tsa` with the test TSA, for this digest and time.
fn tsa_args(algorithm: &str, digest: &str, time: &str) -> Vec<String> {
    [
        "tsa",
        "--digest-algorithm",
        algorithm,
        "--digest",
        digest,
        "--time",
        time,
        "--tsa-key",
        &testdata("pki/keys/tsa.test-key.pem"),
        "--tsa-cert",
        &testdata("pki/tsa.pem"),
    ]
    .map(str::to_owned)
    .to_vec()
}

fn run_tsa(args: &[String]) -> std::io::Result<Output> {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run(&args)
}

const SHA256_DIGEST: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

#[test]
fn tsa_writes_a_der_token_to_standard_output() -> Result<(), Box<dyn std::error::Error>> {
    let output = run_tsa(&tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00:00Z"))?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
    // The token is the one the library issues for the same request.
    let key = std::fs::read_to_string(testdata("pki/keys/tsa.test-key.pem"))?;
    let certificate = std::fs::read(testdata("pki/tsa.pem"))?;
    let tsa = sigillum_testpki::timestamp::Tsa::from_pem(key.as_bytes(), &certificate)?;
    let digest: Vec<u8> = (0..SHA256_DIGEST.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&SHA256_DIGEST[i..i + 2], 16))
        .collect::<Result<_, _>>()?;
    let expected = tsa.issue(
        sigillum_testpki::timestamp::DigestAlgorithm::Sha256,
        &digest,
        time::macros::datetime!(2030-01-14 10:00:00 UTC),
    )?;
    assert_eq!(output.stdout, expected);
    Ok(())
}

#[test]
fn tsa_accepts_every_supported_digest_algorithm() -> std::io::Result<()> {
    for (algorithm, octets) in [
        ("SHA-256", 32),
        ("sha384", 48),
        ("2.16.840.1.101.3.4.2.3", 64),
    ] {
        let digest = "ab".repeat(octets);
        let output = run_tsa(&tsa_args(algorithm, &digest, "2030-01-14T10:00:00Z"))?;
        assert_eq!(output.status.code(), Some(0), "{algorithm}");
        // The DER encoding of the digest is in the token.
        let encoded = [
            vec![0x04, u8::try_from(octets).unwrap_or(0)],
            vec![0xab; octets],
        ]
        .concat();
        assert!(
            output.stdout.windows(encoded.len()).any(|w| w == encoded),
            "{algorithm}"
        );
    }
    Ok(())
}

/// The serial number of a token, from its decoded TSTInfo.
fn serial(token: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use der::{Decode, Encode};
    let content_info = cms::content_info::ContentInfo::from_der(token)?;
    let signed_data: cms::signed_data::SignedData = content_info.content.decode_as()?;
    let econtent = signed_data
        .encap_content_info
        .econtent
        .ok_or("no eContent")?;
    let tst_info_der = der::asn1::OctetString::from_der(&econtent.to_der()?)?.into_bytes();
    let tst_info = x509_tsp::TstInfo::from_der(&tst_info_der)?;
    Ok(tst_info.serial_number.as_bytes().to_vec())
}

#[test]
fn tsa_serial_numbers_depend_on_the_digest_and_the_time() -> Result<(), Box<dyn std::error::Error>>
{
    let token = |digest: &str, time: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let output = run_tsa(&tsa_args("SHA-256", digest, time))?;
        assert_eq!(output.status.code(), Some(0));
        Ok(output.stdout)
    };
    let other_digest = "00".repeat(32);
    let first = token(SHA256_DIGEST, "2030-01-14T10:00:00Z")?;
    let again = token(SHA256_DIGEST, "2030-01-14T10:00:00Z")?;
    let later = token(SHA256_DIGEST, "2030-01-14T10:00:01Z")?;
    let other = token(&other_digest, "2030-01-14T10:00:00Z")?;
    // The same request gives the same token; any change gives a new serial.
    assert_eq!(first, again);
    let serials = [serial(&first)?, serial(&later)?, serial(&other)?];
    assert!(serials.iter().all(|serial| serial.len() == 16));
    assert_ne!(serials[0], serials[1]);
    assert_ne!(serials[0], serials[2]);
    assert_ne!(serials[1], serials[2]);
    Ok(())
}

#[test]
fn tsa_refuses_invalid_input_as_a_usage_error() -> std::io::Result<()> {
    let time = "2030-01-14T10:00:00Z";
    let cases: Vec<(Vec<String>, &str)> = vec![
        // --time accepts only the manifest form.
        (
            tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00:00+00:00"),
            "YYYY-MM-DDTHH:MM:SSZ",
        ),
        (
            tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T11:00:00+01:00"),
            "YYYY-MM-DDTHH:MM:SSZ",
        ),
        (
            tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00:00.5Z"),
            "YYYY-MM-DDTHH:MM:SSZ",
        ),
        (
            tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14t10:00:00z"),
            "YYYY-MM-DDTHH:MM:SSZ",
        ),
        (
            tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00Z"),
            "YYYY-MM-DDTHH:MM:SSZ",
        ),
        (
            tsa_args("SHA-256", SHA256_DIGEST, "1969-12-31T23:59:59Z"),
            "YYYY-MM-DDTHH:MM:SSZ",
        ),
        (
            tsa_args("SHA-256", SHA256_DIGEST, "soon"),
            "YYYY-MM-DDTHH:MM:SSZ",
        ),
        // Only SHA-256, SHA-384 and SHA-512.
        (
            tsa_args("SHA-1", SHA256_DIGEST, time),
            "unsupported digest algorithm",
        ),
        (
            tsa_args("1.3.14.3.2.26", SHA256_DIGEST, time),
            "unsupported digest algorithm",
        ),
        // An arc too large for const-oid 0.9.6, found by fuzzing.
        (
            tsa_args("99999999999999999999.1", SHA256_DIGEST, time),
            "unsupported digest algorithm",
        ),
        (
            tsa_args("SHA3-256", SHA256_DIGEST, time),
            "unsupported digest algorithm",
        ),
        // The digest is hexadecimal and as long as the algorithm's output.
        (tsa_args("SHA-256", "abc", time), "hexadecimal"),
        (tsa_args("SHA-256", "zz", time), "hexadecimal"),
        (tsa_args("SHA-256", "", time), "hexadecimal"),
        (
            tsa_args("SHA-256", &"00".repeat(48), time),
            "a SHA-256 digest has 32 octets, not 48",
        ),
        (
            tsa_args("SHA-512", SHA256_DIGEST, time),
            "a SHA-512 digest has 64 octets, not 32",
        ),
    ];
    for (args, message) in cases {
        let output = run_tsa(&args)?;
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = text(&output.stderr);
        assert!(stderr.contains(message), "{args:?}: {stderr}");
    }
    // Every option is required.
    for missing in [
        "--digest-algorithm",
        "--digest",
        "--time",
        "--tsa-key",
        "--tsa-cert",
    ] {
        let mut args = tsa_args("SHA-256", SHA256_DIGEST, time);
        let at = args.iter().position(|a| a == missing).unwrap_or(1);
        args.drain(at..at + 2);
        assert_eq!(run_tsa(&args)?.status.code(), Some(2), "{missing}");
    }
    Ok(())
}

#[test]
fn tsa_reports_unusable_keys_and_certificates() -> std::io::Result<()> {
    let with = |key: &str, certificate: &str| {
        let mut args = tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00:00Z");
        args[8] = key.to_owned();
        args[10] = certificate.to_owned();
        args
    };
    let key = testdata("pki/keys/tsa.test-key.pem");
    let certificate = testdata("pki/tsa.pem");
    // The TSA key as DER, and a key file that is not UTF-8.
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tsa_reports_unusable_keys");
    std::fs::create_dir_all(&dir)?;
    let pem = std::fs::read_to_string(&key)?;
    let base64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der_key = dir.join("tsa.der");
    std::fs::write(&der_key, decode_base64(&base64))?;
    let binary_key = dir.join("binary.key");
    std::fs::write(&binary_key, [0xff, 0xfe, 0x00, 0x30])?;
    let der_key = der_key.to_string_lossy().into_owned();
    let binary_key = binary_key.to_string_lossy().into_owned();
    let cases = [
        (
            with(&der_key, &certificate),
            "the private key is not a PKCS#8 PEM document",
        ),
        (
            with(&binary_key, &certificate),
            "the private key is not a PKCS#8 PEM document",
        ),
        (with("no/such/key.pem", &certificate), "no/such/key.pem"),
        (
            with(&key, "no/such/certificate.pem"),
            "no/such/certificate.pem",
        ),
        (
            with(&certificate, &certificate),
            "the private key is not a PKCS#8 PEM document",
        ),
        (
            with(&key, &key),
            "the certificate is not a PEM or DER X.509 certificate",
        ),
        (
            with(&testdata("pki/keys/signer-p256.test-key.pem"), &certificate),
            "the private key does not belong to the certificate",
        ),
    ];
    for (args, message) in cases {
        let output = run_tsa(&args)?;
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
        let stderr = text(&output.stderr);
        assert!(stderr.contains("sigillum-testpki tsa: "), "{stderr}");
        assert!(stderr.contains(message), "{args:?}: {stderr}");
        assert!(!stderr.contains("UTF-8"), "{stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// Decodes standard base64, for the test key only.
fn decode_base64(text: &str) -> Vec<u8> {
    let value = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let digits: Vec<u8> = text.bytes().filter(|&c| c != b'=').map(value).collect();
    let mut out = Vec::new();
    for chunk in digits.chunks(4) {
        let mut buffer = 0u32;
        for (i, digit) in chunk.iter().enumerate() {
            buffer |= u32::from(*digit) << (18 - 6 * i);
        }
        let bytes = buffer.to_be_bytes();
        out.extend_from_slice(bytes.get(1..chunk.len()).unwrap_or_default());
    }
    out
}

#[test]
fn tsa_accepts_a_certificate_after_a_byte_order_mark() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tsa_accepts_a_byte_order_mark");
    std::fs::create_dir_all(&dir)?;
    let certificate = dir.join("tsa.pem");
    let pem = std::fs::read(testdata("pki/tsa.pem"))?;
    std::fs::write(&certificate, [&b"\xef\xbb\xbf\r\n "[..], &pem].concat())?;
    let mut args = tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00:00Z");
    let plain = run_tsa(&args)?;
    args[10] = certificate.to_string_lossy().into_owned();
    let output = run_tsa(&args)?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(output.stdout, plain.stdout);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generate_timestamps_writes_the_tokens_and_the_manifest() -> Result<(), Box<dyn std::error::Error>>
{
    let manifest = corpus("generate_timestamps_writes_the_tokens", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let path = manifest.to_string_lossy().into_owned();
    // The tokens link to the test PKI, so the PKI must be in the manifest.
    let before = std::fs::read(&manifest)?;
    let output = run(&["generate", "timestamps", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("pki/tsa"), "{stderr}");
    assert!(
        stderr.contains("run sigillum-testpki generate pki first"),
        "{stderr}"
    );
    assert_eq!(std::fs::read(&manifest)?, before);
    assert!(!dir.join("timestamps").exists());
    let output = run(&["generate", "pki", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let output = run(&["generate", "timestamps", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("generate timestamps: wrote 5 files"));
    assert!(output.stderr.is_empty(), "{}", text(&output.stderr));
    let written = std::fs::read_to_string(&manifest)?;
    let parsed = sigillum_testpki::manifest::Manifest::parse(&written)?;
    assert_eq!(parsed.artefacts.len(), 69);
    // Running again changes nothing, and the entries are those of the
    // committed corpus.
    let output = run(&["generate", "timestamps", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(std::fs::read_to_string(&manifest)?, written);
    let committed = sigillum_testpki::manifest::Manifest::load(&committed_manifest())?;
    for artefact in &parsed.artefacts {
        assert!(dir.join(&artefact.path).is_file(), "{}", artefact.id);
        if artefact.id.starts_with("timestamps/") {
            assert!(committed.artefacts.contains(artefact), "{}", artefact.id);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generate_timestamps_prunes_its_stale_entries() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("generate_timestamps_prunes_its_stale_entries", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let path = manifest.to_string_lossy().into_owned();
    let output = run(&["generate", "pki", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stale = "\n[[artefact]]\nid = \"timestamps/old\"\npath = \"timestamps/old.tst\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nkind = \"timestamp-token\"\npurpose = \"Old\"\nexpected-openssl = \"not-applicable\"\nexpected-dss = \"not-applicable\"\n";
    let mut text_before = std::fs::read_to_string(&manifest)?;
    text_before.push_str(stale);
    std::fs::write(&manifest, text_before)?;
    std::fs::create_dir_all(dir.join("timestamps"))?;
    std::fs::write(dir.join("timestamps/old.tst"), "")?;
    let output = run(&["generate", "timestamps", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("generate timestamps: removed the manifest entry timestamps/old"),
        "{stderr}"
    );
    assert!(
        stderr.contains("generate timestamps: no manifest entry names timestamps/old.tst"),
        "{stderr}"
    );
    let parsed = sigillum_testpki::manifest::Manifest::load(&manifest)?;
    assert!(parsed.artefacts.iter().all(|a| a.id != "timestamps/old"));
    // Running generate pki keeps the timestamp entries.
    let output = run(&["generate", "pki", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0));
    let again = sigillum_testpki::manifest::Manifest::load(&manifest)?;
    assert_eq!(again, parsed);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn an_unreadable_manifest_is_reported() -> std::io::Result<()> {
    let output = run(&["verify", "--manifest", "no/such/manifest.toml"])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("the manifest cannot be read"));
    Ok(())
}

#[test]
fn an_invalid_manifest_is_reported() -> std::io::Result<()> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("an_invalid_manifest_is_reported");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("manifest.toml");
    std::fs::write(
        &path,
        "[header]\nformat-version = 1\nvalidation-time = \"soon\"\nopenssl-version = \"3\"\ndss-version = \"6\"\n",
    )?;
    let output = run(&["generate", "pki", "--manifest", &path.to_string_lossy()])?;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("the validation time \"soon\""));
    Ok(())
}

#[test]
fn an_unknown_subcommand_is_a_usage_error() -> std::io::Result<()> {
    let output = run(&["sign"])?;
    assert_eq!(output.status.code(), Some(2));
    Ok(())
}

/// The size limit of the key and certificate files of `tsa`.
const FILE_LIMIT: usize = 64 * 1024;

/// A copy of `source` with leading spaces, which PEM parsing skips, so
/// that the file is exactly `len` bytes long.
fn padded(dir: &std::path::Path, name: &str, source: &str, len: usize) -> std::io::Result<String> {
    let contents = std::fs::read(source)?;
    let mut padded = vec![b' '; len.saturating_sub(contents.len())];
    padded.extend_from_slice(&contents);
    assert_eq!(padded.len(), len);
    let path = dir.join(name);
    std::fs::write(&path, padded)?;
    Ok(path.to_string_lossy().into_owned())
}

#[test]
fn tsa_reads_key_and_certificate_files_up_to_64_kib() -> Result<(), Box<dyn std::error::Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("tsa_reads_files_up_to_64_kib");
    std::fs::create_dir_all(&dir)?;
    let key = testdata("pki/keys/tsa.test-key.pem");
    let certificate = testdata("pki/tsa.pem");
    let expected = run_tsa(&tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00:00Z"))?.stdout;
    let with = |key: &str, certificate: &str| {
        let mut args = tsa_args("SHA-256", SHA256_DIGEST, "2030-01-14T10:00:00Z");
        args[8] = key.to_owned();
        args[10] = certificate.to_owned();
        args
    };
    // Exactly at the limit, both files are read in full.
    let key_at = padded(&dir, "key-at", &key, FILE_LIMIT)?;
    let certificate_at = padded(&dir, "certificate-at", &certificate, FILE_LIMIT)?;
    let output = run_tsa(&with(&key_at, &certificate_at))?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert_eq!(output.stdout, expected);
    // One byte more, either file is refused before it is parsed.
    let key_over = padded(&dir, "key-over", &key, FILE_LIMIT + 1)?;
    let certificate_over = padded(&dir, "certificate-over", &certificate, FILE_LIMIT + 1)?;
    for (args, path) in [
        (with(&key_over, &certificate), &key_over),
        (with(&key, &certificate_over), &certificate_over),
    ] {
        let output = run_tsa(&args)?;
        assert_eq!(output.status.code(), Some(1), "{path}");
        assert!(output.stdout.is_empty());
        let stderr = text(&output.stderr);
        assert!(stderr.contains(path.as_str()), "{stderr}");
        assert!(stderr.contains("larger than 65536 bytes"), "{stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The manifest at `path`, parsed.
fn load(
    path: &std::path::Path,
) -> Result<sigillum_testpki::manifest::Manifest, Box<dyn std::error::Error>> {
    Ok(sigillum_testpki::manifest::Manifest::load(path)?)
}

#[test]
fn generate_crls_writes_the_crls_and_links_the_certificates()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("generate_crls_writes_the_crls", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let path = manifest.to_string_lossy().into_owned();
    let output = run(&["generate", "pki", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let output = run(&["generate", "crls", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    assert!(text(&output.stdout).contains("generate crls: wrote 12 files"));
    assert!(text(&output.stderr).is_empty(), "{}", text(&output.stderr));
    let written = std::fs::read_to_string(&manifest)?;
    // The entries are those of the committed corpus, which also holds
    // the timestamp tokens.
    let committed: Vec<_> = load(&committed_manifest())?
        .artefacts
        .into_iter()
        .filter(|a| !a.id.starts_with("timestamps/"))
        .collect();
    assert_eq!(load(&manifest)?.artefacts, committed);
    for artefact in &load(&manifest)?.artefacts {
        assert!(dir.join(&artefact.path).is_file(), "{}", artefact.id);
    }
    // Running either generator again changes nothing: generate pki keeps
    // the revocation links that generate crls set.
    for target in ["crls", "pki"] {
        let output = run(&["generate", target, "--manifest", &path])?;
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
        assert!(text(&output.stderr).is_empty(), "{}", text(&output.stderr));
        assert_eq!(std::fs::read_to_string(&manifest)?, written, "{target}");
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generate_crls_needs_the_certificates() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("generate_crls_needs_the_certificates", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let before = std::fs::read_to_string(&manifest)?;
    let output = run(&[
        "generate",
        "crls",
        "--manifest",
        &manifest.to_string_lossy(),
    ])?;
    assert_eq!(output.status.code(), Some(1));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("\"pki/root-ca\""), "{stderr}");
    assert_eq!(std::fs::read_to_string(&manifest)?, before);
    assert!(!dir.join("crl").exists());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

#[test]
fn generate_crls_prunes_stale_crls_and_the_links_to_them() -> Result<(), Box<dyn std::error::Error>>
{
    let manifest = corpus("generate_crls_prunes_stale_crls", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let path = manifest.to_string_lossy().into_owned();
    let output = run(&["generate", "pki", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let entry = |id: &str, path: &str, kind: &str, links: &str| {
        format!(
            "\n[[artefact]]\nid = \"{id}\"\npath = \"{path}\"\nsha256 = \"0000000000000000000000000000000000000000000000000000000000000000\"\nkind = \"{kind}\"\npurpose = \"Other\"\nexpected-openssl = \"not-applicable\"\nexpected-dss = \"not-applicable\"\n{links}"
        )
    };
    let extra = [
        // A CRL the generator no longer produces: removed, with the links to it.
        entry("crl/old", "crl/old.crl", "crl", ""),
        // A revocation artefact of another generator: kept, with its links.
        entry(
            "ocsp/signer-p256",
            "ocsp/signer-p256.der",
            "ocsp-response",
            "",
        ),
        entry(
            "doc/a",
            "doc/a.txt",
            "document",
            "links = { revocation = [\"crl/old\", \"ocsp/signer-p256\"] }\n",
        ),
    ]
    .concat();
    let mut text_before = std::fs::read_to_string(&manifest)?;
    text_before.push_str(&extra);
    std::fs::write(&manifest, &text_before)?;
    std::fs::create_dir_all(dir.join("crl"))?;
    std::fs::write(dir.join("crl/old.crl"), "")?;
    std::fs::write(dir.join("crl/stray.crl"), "")?;
    let output = run(&["generate", "crls", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("generate crls: removed the manifest entry crl/old"),
        "{stderr}"
    );
    assert!(
        stderr.contains("no manifest entry names crl/old.crl"),
        "{stderr}"
    );
    assert!(
        stderr.contains("no manifest entry names crl/stray.crl"),
        "{stderr}"
    );
    let parsed = load(&manifest)?;
    assert!(parsed.artefacts.iter().all(|a| a.id != "crl/old"));
    let doc = parsed
        .artefacts
        .iter()
        .find(|a| a.id == "doc/a")
        .ok_or("no doc/a")?;
    assert_eq!(doc.links.revocation, ["ocsp/signer-p256"]);
    assert!(dir.join("crl/old.crl").is_file());
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// generate crls keeps the revocation links of the CRL entries it
/// replaces, as generate pki does for certificates.
#[test]
fn generate_crls_keeps_the_revocation_links_of_its_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("generate_crls_keeps_the_revocation_links", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let path = manifest.to_string_lossy().into_owned();
    for target in ["pki", "crls"] {
        let output = run(&["generate", target, "--manifest", &path])?;
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    }
    let mut parsed = load(&manifest)?;
    let crl = parsed
        .artefacts
        .iter_mut()
        .find(|a| a.id == "crl/ca-rsa")
        .ok_or("no crl/ca-rsa")?;
    crl.links.revocation = vec!["crl/root-ca".to_owned()];
    std::fs::write(&manifest, parsed.to_toml())?;
    let output = run(&["generate", "crls", "--manifest", &path])?;
    assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
    let crl = load(&manifest)?
        .artefacts
        .into_iter()
        .find(|a| a.id == "crl/ca-rsa")
        .ok_or("no crl/ca-rsa")?;
    assert_eq!(crl.links.revocation, ["crl/root-ca"]);
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// The three generators, run in the documented order on a manifest with
/// only a header, reproduce the committed manifest byte for byte.
#[test]
fn the_generators_in_order_reproduce_the_committed_manifest()
-> Result<(), Box<dyn std::error::Error>> {
    let manifest = corpus("the_generators_in_order_reproduce_the_manifest", "")?;
    let dir = manifest.parent().ok_or("no parent")?.to_path_buf();
    let path = manifest.to_string_lossy().into_owned();
    for target in ["pki", "crls", "timestamps"] {
        let output = run(&["generate", target, "--manifest", &path])?;
        assert_eq!(output.status.code(), Some(0), "{}", text(&output.stderr));
        assert!(text(&output.stderr).is_empty(), "{}", text(&output.stderr));
    }
    assert_eq!(
        std::fs::read_to_string(&manifest)?,
        std::fs::read_to_string(committed_manifest())?
    );
    let committed = committed_manifest();
    let testdata = committed.parent().ok_or("no parent")?;
    for artefact in &load(&manifest)?.artefacts {
        assert_eq!(
            std::fs::read(dir.join(&artefact.path))?,
            std::fs::read(testdata.join(&artefact.path))?,
            "{}",
            artefact.id
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}
