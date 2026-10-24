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
fn corpus_subcommands_read_the_validation_time_from_the_manifest() -> std::io::Result<()> {
    let manifest = committed_manifest();
    for subcommand in ["generate", "verify"] {
        let output = run(&[subcommand, "--manifest", &manifest.to_string_lossy()])?;
        assert_eq!(output.status.code(), Some(3), "{subcommand}");
        let stderr = text(&output.stderr);
        assert!(
            stderr.contains("2030-01-15T10:00:00Z"),
            "{subcommand}: {stderr}"
        );
        assert!(stderr.contains("not implemented"), "{subcommand}: {stderr}");
    }
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
    let output = run(&["generate", "--manifest", &path.to_string_lossy()])?;
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
