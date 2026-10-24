//! `sigillum-testpki` must not depend on any `sigillum-*` crate, because
//! those are the code under test (ADR-0014).

use std::process::Command;

#[test]
fn depends_on_no_sigillum_crate() -> std::io::Result<()> {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--locked",
            "--target",
            "all",
            "--all-features",
            "--package",
            "sigillum-testpki",
            "--edges",
            "normal,build,dev",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let tree = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = tree
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert!(packages.contains(&"sigillum-testpki"), "{tree}");
    assert!(
        packages.contains(&"toml"),
        "the tree looks incomplete:\n{tree}"
    );
    let offending: Vec<&&str> = packages
        .iter()
        .filter(|name| name.starts_with("sigillum") && **name != "sigillum-testpki")
        .collect();
    assert!(
        offending.is_empty(),
        "sigillum crates in the dependency tree: {offending:?}"
    );
    Ok(())
}
