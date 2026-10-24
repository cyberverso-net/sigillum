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
        ("tsa", "--tsa-cert"),
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
    assert!(text(&output.stdout).contains("wrote 54 files"));
    let written = std::fs::read_to_string(&manifest)?;
    let parsed = sigillum_testpki::manifest::Manifest::parse(&written)?;
    assert_eq!(parsed.artefacts.len(), 54);
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
            .map(|a| (a.id.clone(), a.clone()))
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
    assert_eq!(parsed.artefacts.len(), 55);
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
        run(&["generate", "crls", "--manifest", &manifest])?
            .status
            .code(),
        Some(2)
    );
    let output = run(&["generate", "pki", "--manifest", "no/such/manifest.toml"])?;
    assert_eq!(output.status.code(), Some(1));
    assert!(text(&output.stderr).contains("the manifest cannot be read"));
    Ok(())
}

#[test]
fn tsa_takes_its_time_key_and_certificate_explicitly() -> std::io::Result<()> {
    let output = run(&[
        "tsa",
        "--time",
        "2030-01-15T09:00:00Z",
        "--tsa-key",
        "tsa.test-key.pem",
        "--tsa-cert",
        "tsa.pem",
    ])?;
    assert_eq!(output.status.code(), Some(3));
    assert!(text(&output.stderr).contains("2030-01-15T09:00:00Z"));
    for missing in ["--time", "--tsa-key", "--tsa-cert"] {
        let mut args = vec![
            "tsa",
            "--time",
            "2030-01-15T09:00:00Z",
            "--tsa-key",
            "k",
            "--tsa-cert",
            "c",
        ];
        let at = args.iter().position(|a| *a == missing).unwrap_or(1);
        args.drain(at..at + 2);
        assert_eq!(run(&args)?.status.code(), Some(2), "{missing}");
    }
    let output = run(&["tsa", "--time", "soon", "--tsa-key", "k", "--tsa-cert", "c"])?;
    assert_eq!(output.status.code(), Some(2));
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
