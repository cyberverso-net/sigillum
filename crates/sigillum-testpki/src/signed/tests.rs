use std::cell::RefCell;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use time::macros::datetime;

use super::*;
use crate::manifest::Indication;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const VALIDATION_TIME: OffsetDateTime = datetime!(2030-01-15 10:00:00 UTC);

fn fixture(id: &str) -> Result<Fixture, String> {
    plan()
        .into_iter()
        .find(|fixture| fixture.id() == id)
        .ok_or_else(|| format!("{id} is not planned"))
}

fn strings(arguments: &[OsString]) -> Vec<String> {
    arguments
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn the_plan_covers_every_combination_of_the_story() {
    let fixtures = plan();
    // CAdES enveloping and detached, PAdES, JAdES flattened and general at three
    // levels, and JAdES compact at B-B only, for four signers; then the three
    // documents prepared for shadow attacks, at B-B by one signer (issue #112).
    assert_eq!(fixtures.len(), (5 * 3 + 1) * 4 + 3);
    let mut ids: Vec<String> = fixtures.iter().map(Fixture::id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), fixtures.len());
    for fixture in &fixtures {
        if matches!(
            fixture.variant,
            Variant::JadesCompact
                | Variant::PadesShadowHide
                | Variant::PadesShadowReplace
                | Variant::PadesShadowHideAndReplace
        ) {
            assert_eq!(fixture.level, Level::B, "{}", fixture.id());
        }
        assert!(fixture.id().starts_with("signed/"), "{}", fixture.id());
    }
    let labels: Vec<&str> = SIGNERS.iter().map(|signer| signer.label).collect();
    assert_eq!(labels, ["rsa", "rsa-pss", "p256", "ed25519"]);
}

#[test]
fn identifiers_and_paths_follow_the_fixture() -> TestResult {
    let cases = [
        (
            "signed/cades-enveloping-b-b-rsa",
            "signed/cades-enveloping-b-b-rsa.p7m",
        ),
        (
            "signed/cades-detached-b-t-p256",
            "signed/cades-detached-b-t-p256.p7s",
        ),
        ("signed/pades-b-lt-ed25519", "signed/pades-b-lt-ed25519.pdf"),
        (
            "signed/jades-compact-b-b-rsa-pss",
            "signed/jades-compact-b-b-rsa-pss.jws",
        ),
        (
            "signed/jades-flattened-b-t-rsa",
            "signed/jades-flattened-b-t-rsa.json",
        ),
        (
            "signed/jades-general-b-lt-p256",
            "signed/jades-general-b-lt-p256.json",
        ),
    ];
    for (id, path) in cases {
        assert_eq!(fixture(id)?.path(), PathBuf::from(path));
    }
    Ok(())
}

#[test]
fn the_arguments_of_a_baseline_b_signature() -> TestResult {
    let root = Path::new("corpus");
    let arguments = fixture("signed/cades-enveloping-b-b-rsa-pss")?.arguments(
        root,
        Path::new("testpki"),
        VALIDATION_TIME,
        Path::new("out/file"),
    )?;
    let corpus = |path: &str| root.join(path).to_string_lossy().into_owned();
    assert_eq!(
        strings(&arguments),
        [
            "--format".to_owned(),
            "cades".to_owned(),
            "--level".to_owned(),
            "B-B".to_owned(),
            "--key".to_owned(),
            corpus("pki/keys/signer-rsa-pss-sha256.test-key.pem"),
            "--certificate".to_owned(),
            corpus("pki/signer-rsa-pss-sha256.pem"),
            "--chain".to_owned(),
            corpus("pki/ca-rsa-pss.pem"),
            "--chain".to_owned(),
            corpus("pki/root-ca.pem"),
            "--signing-time".to_owned(),
            "2029-12-16T10:00:00Z".to_owned(),
            "--document".to_owned(),
            corpus("documents/text.txt"),
            "--signature-algorithm".to_owned(),
            "RSA_SSA_PSS_SHA256_MGF1".to_owned(),
            "--packaging".to_owned(),
            "enveloping".to_owned(),
            "--out".to_owned(),
            "out/file".to_owned(),
        ]
    );
    Ok(())
}

#[test]
fn the_arguments_of_a_baseline_lt_signature() -> TestResult {
    let root = Path::new("corpus");
    let arguments = fixture("signed/jades-general-b-lt-p256")?.arguments(
        root,
        Path::new("bin/testpki"),
        VALIDATION_TIME,
        Path::new("out/file"),
    )?;
    let corpus = |path: &str| root.join(path).to_string_lossy().into_owned();
    let arguments = strings(&arguments);
    let tail: Vec<String> = arguments
        .iter()
        .skip_while(|argument| *argument != "--document")
        .cloned()
        .collect();
    assert_eq!(
        tail,
        [
            "--document".to_owned(),
            corpus("documents/payload.json"),
            "--serialisation".to_owned(),
            "general".to_owned(),
            "--tsa-program".to_owned(),
            "bin/testpki".to_owned(),
            "--tsa-key".to_owned(),
            corpus("pki/keys/tsa.test-key.pem"),
            "--tsa-cert".to_owned(),
            corpus("pki/tsa.pem"),
            "--timestamp-time".to_owned(),
            "2029-12-16T10:00:00Z".to_owned(),
            "--tsa-chain".to_owned(),
            corpus("pki/ca-ecdsa.pem"),
            "--trust-anchor".to_owned(),
            corpus("pki/root-ca.pem"),
            "--ocsp".to_owned(),
            corpus("ocsp/signer-p256.der"),
            "--ocsp".to_owned(),
            corpus("ocsp/tsa.der"),
            "--crl".to_owned(),
            corpus("crl/root-ca.crl"),
            "--validation-time".to_owned(),
            "2030-01-15T10:00:00Z".to_owned(),
            "--out".to_owned(),
            "out/file".to_owned(),
        ]
    );
    assert!(!arguments.contains(&"--signature-algorithm".to_owned()));
    Ok(())
}

#[test]
fn pades_has_no_packaging_and_jades_compact_no_timestamp() -> TestResult {
    let root = Path::new("corpus");
    for (id, absent) in [
        ("signed/pades-b-t-rsa", "--packaging"),
        ("signed/pades-b-t-rsa", "--serialisation"),
        ("signed/jades-compact-b-b-p256", "--tsa-program"),
        ("signed/cades-detached-b-t-ed25519", "--validation-time"),
    ] {
        let arguments = strings(&fixture(id)?.arguments(
            root,
            Path::new("t"),
            VALIDATION_TIME,
            Path::new("o"),
        )?);
        assert!(!arguments.contains(&absent.to_owned()), "{id} {absent}");
    }
    let detached = strings(&fixture("signed/cades-detached-b-t-ed25519")?.arguments(
        root,
        Path::new("t"),
        VALIDATION_TIME,
        Path::new("o"),
    )?);
    assert!(
        detached
            .windows(2)
            .any(|w| w == ["--packaging", "detached"])
    );
    Ok(())
}

#[test]
fn a_fixture_records_its_manifest_entry() -> TestResult {
    let contents = b"signed bytes";
    let artefact = fixture("signed/cades-detached-b-t-p256")?.artefact(contents);
    assert_eq!(artefact.id, "signed/cades-detached-b-t-p256");
    assert_eq!(
        artefact.path,
        PathBuf::from("signed/cades-detached-b-t-p256.p7s")
    );
    assert_eq!(artefact.sha256, sha256_hex(contents));
    assert_eq!(artefact.kind, Kind::SignedDocument);
    assert_eq!(artefact.expected_openssl, OpensslResult::Verified);
    assert_eq!(
        artefact.expected_dss,
        DssResult::Indication {
            indication: Indication::TotalPassed,
            sub_indication: None
        }
    );
    assert_eq!(artefact.links.issuer.as_deref(), Some("pki/signer-p256"));
    assert_eq!(
        artefact.links.chain,
        ["pki/signer-p256", "pki/ca-ecdsa", "pki/root-ca"]
    );
    assert_eq!(
        artefact.links.revocation,
        ["ocsp/signer-p256", "crl/root-ca", "ocsp/tsa"]
    );
    assert_eq!(artefact.links.content.as_deref(), Some("documents/text"));
    assert_eq!(
        artefact.links.timestamp_chain,
        ["pki/tsa", "pki/ca-ecdsa", "pki/root-ca"]
    );
    assert!(artefact.purpose.contains("B-T"), "{}", artefact.purpose);
    assert!(artefact.notes.is_some());
    Ok(())
}

#[test]
fn only_detached_signatures_link_their_content_and_b_lt_needs_no_revocation_link() -> TestResult {
    for fixture in plan() {
        let artefact = fixture.artefact(b"x");
        assert_eq!(
            artefact.links.content.is_some(),
            fixture.variant == Variant::CadesDetached,
            "{}",
            fixture.id()
        );
        let expected: &[&str] = match fixture.level {
            Level::B => &["ocsp", "crl/root-ca"],
            Level::T => &["ocsp", "crl/root-ca", "ocsp/tsa"],
            Level::Lt => &[],
        };
        assert_eq!(
            artefact.links.revocation.len(),
            expected.len(),
            "{}",
            fixture.id()
        );
        let openssl = if matches!(
            fixture.variant,
            Variant::CadesEnveloping | Variant::CadesDetached
        ) {
            OpensslResult::Verified
        } else {
            OpensslResult::NotApplicable
        };
        assert_eq!(artefact.expected_openssl, openssl, "{}", fixture.id());
    }
    Ok(())
}

#[test]
fn ed25519_entries_note_the_default_policy_of_dss() -> TestResult {
    let ed25519 = fixture("signed/pades-b-b-ed25519")?.artefact(b"x");
    let notes = ed25519.notes.ok_or("no notes")?;
    assert!(
        notes.contains("CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),
        "{notes}"
    );
    let rsa = fixture("signed/pades-b-b-rsa")?.artefact(b"x");
    assert!(!rsa.notes.ok_or("no notes")?.contains("EdDSA"));
    let compact = fixture("signed/jades-compact-b-b-rsa")?.artefact(b"x");
    assert!(compact.notes.ok_or("no notes")?.contains("compact"));
    Ok(())
}

/// An oracle that writes a digest of its arguments as the signature, and
/// records every call.
struct FakeOracle {
    calls: RefCell<Vec<Vec<OsString>>>,
    fail_on: Option<&'static str>,
    write: bool,
}

impl FakeOracle {
    fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            fail_on: None,
            write: true,
        }
    }
}

impl Oracle for FakeOracle {
    fn sign(&self, arguments: &[OsString]) -> Result<(), String> {
        self.calls.borrow_mut().push(arguments.to_vec());
        let joined = strings(arguments).join(" ");
        if let Some(fail_on) = self.fail_on
            && joined.contains(fail_on)
        {
            return Err("DSS cannot create the signature".to_owned());
        }
        if self.write {
            let out = arguments.last().ok_or("no --out")?;
            std::fs::write(out, sha256_hex(joined.as_bytes())).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[test]
fn generate_runs_the_oracle_once_per_fixture() -> TestResult {
    let oracle = FakeOracle::new();
    let files = generate(
        Path::new("corpus"),
        VALIDATION_TIME,
        &oracle,
        Path::new("t"),
    )?;
    assert_eq!(files.len(), plan().len());
    assert_eq!(oracle.calls.borrow().len(), plan().len());
    for (file, fixture) in files.iter().zip(plan()) {
        assert_eq!(file.artefact, fixture.artefact(&file.contents));
        assert_eq!(file.contents.len(), 64);
    }
    // Every output goes to a fresh file in a directory of its own, removed afterwards.
    let calls = oracle.calls.borrow();
    let out = PathBuf::from(calls[0].last().ok_or("no --out")?);
    assert!(!out.exists());
    assert!(!out.parent().ok_or("no parent")?.exists());
    Ok(())
}

#[test]
fn generate_reports_the_fixture_that_failed() {
    let oracle = FakeOracle {
        fail_on: Some("signer-ed25519"),
        ..FakeOracle::new()
    };
    let error = generate(
        Path::new("corpus"),
        VALIDATION_TIME,
        &oracle,
        Path::new("t"),
    );
    assert_eq!(
        error,
        Err(SignedError::Oracle {
            id: "signed/cades-enveloping-b-b-ed25519".to_owned(),
            message: "DSS cannot create the signature".to_owned(),
        })
    );
}

#[test]
fn generate_reports_a_missing_output() {
    let oracle = FakeOracle {
        write: false,
        ..FakeOracle::new()
    };
    let result = generate(
        Path::new("corpus"),
        VALIDATION_TIME,
        &oracle,
        Path::new("t"),
    );
    assert!(
        matches!(&result, Err(SignedError::Io(message)) if message.contains("signed/cades-enveloping-b-b-rsa")),
        "{result:?}"
    );
}

#[test]
fn errors_are_described() {
    let cases = [
        (
            SignedError::NotInManifest("pki/tsa".to_owned()),
            "the manifest does not list pki/tsa, which the signed corpus needs",
        ),
        (
            SignedError::Oracle {
                id: "signed/x".to_owned(),
                message: "exit 1".to_owned(),
            },
            "tools/dss-oracle cannot sign signed/x: exit 1",
        ),
        (
            SignedError::Io("disk".to_owned()),
            "a file of the signed corpus cannot be read or written: disk",
        ),
        (SignedError::Time, "the signing time is out of range"),
    ];
    for (error, text) in cases {
        assert_eq!(error.to_string(), text);
    }
}

#[test]
fn a_java_program_that_cannot_run_is_reported() {
    let oracle = JavaOracle::new(
        PathBuf::from("no-such-java-program-for-sigillum"),
        PathBuf::from("dss-oracle.jar"),
    );
    let error = oracle.sign(&[OsString::from("--help")]);
    assert!(
        matches!(&error, Err(message) if message.contains("no-such-java-program-for-sigillum")),
        "{error:?}"
    );
}

#[test]
fn the_java_launcher_fixes_identity_hashes_before_the_jar() {
    let oracle = JavaOracle::new(PathBuf::from("java"), PathBuf::from("dss-oracle.jar"));
    let argv = oracle.arguments(&[OsString::from("--level"), OsString::from("B-LT")]);
    assert_eq!(
        argv,
        [
            "-XX:+UnlockExperimentalVMOptions",
            "-XX:hashCode=2",
            "-jar",
            "dss-oracle.jar",
            "sign",
            "--level",
            "B-LT"
        ]
        .map(OsString::from)
    );
}

#[test]
fn owns_every_entry_under_its_directory() -> TestResult {
    let mut artefact = fixture("signed/pades-b-b-rsa")?.artefact(b"x");
    assert!(generated_here(&artefact));
    artefact.id = "signedx/a".to_owned();
    assert!(!generated_here(&artefact));
    Ok(())
}

#[test]
fn the_corpus_must_list_what_the_fixtures_link_and_read() -> TestResult {
    let mut manifest = Manifest::parse(
        "[header]\nformat-version = 3\nvalidation-time = \"2030-01-15T10:00:00Z\"\nopenssl-version = \"3.0.13\"\ndss-version = \"6.5.1\"\n",
    )?;
    assert_eq!(
        check_listed(&manifest),
        Err(SignedError::NotInManifest("pki/signer-rsa-2048".to_owned()))
    );
    // Another artefact does not stand in for a missing one.
    manifest
        .artefacts
        .push(crate::documents::generate().remove(0).artefact);
    assert_eq!(
        check_listed(&manifest),
        Err(SignedError::NotInManifest("pki/signer-rsa-2048".to_owned()))
    );
    for id in required_ids() {
        manifest
            .artefacts
            .push(crate::documents::generate().remove(0).artefact);
        if let Some(last) = manifest.artefacts.last_mut() {
            last.id = id;
        }
    }
    assert_eq!(check_listed(&manifest), Ok(()));
    Ok(())
}

#[test]
fn purposes_describe_each_variant() -> TestResult {
    let cases = [
        (
            "signed/cades-enveloping-b-b-rsa",
            "CAdES baseline signature, enveloping, at B-B, over documents/text, by pki/signer-rsa-2048 with RSA PKCS#1 v1.5 and SHA-256, created by DSS: the legacy-key-size case.",
        ),
        (
            "signed/cades-detached-b-t-rsa-pss",
            "CAdES baseline signature, detached, at B-T, over documents/text, by pki/signer-rsa-pss-sha256 with RSASSA-PSS and SHA-256, created by DSS.",
        ),
        (
            "signed/pades-b-lt-p256",
            "PAdES baseline signature, invisible, at B-LT, over documents/simple, by pki/signer-p256 with ECDSA on P-256 and SHA-256, created by DSS.",
        ),
        (
            "signed/jades-compact-b-b-ed25519",
            "JAdES baseline signature in the JWS compact serialisation, at B-B, over documents/payload, by pki/signer-ed25519 with Ed25519, created by DSS.",
        ),
        (
            "signed/jades-flattened-b-b-rsa",
            "JAdES baseline signature in the flattened JWS JSON serialisation, at B-B, over documents/payload, by pki/signer-rsa-2048 with RSA PKCS#1 v1.5 and SHA-256, created by DSS: the legacy-key-size case.",
        ),
        (
            "signed/jades-general-b-b-rsa",
            "JAdES baseline signature in the general JWS JSON serialisation, at B-B, over documents/payload, by pki/signer-rsa-2048 with RSA PKCS#1 v1.5 and SHA-256, created by DSS: the legacy-key-size case.",
        ),
    ];
    for (id, purpose) in cases {
        assert_eq!(fixture(id)?.artefact(b"x").purpose, purpose);
    }
    Ok(())
}

#[test]
fn only_jades_notes_mention_x5c() -> TestResult {
    for fixture in plan() {
        let notes = fixture.artefact(b"x").notes.ok_or("no notes")?;
        assert_eq!(
            notes.contains("x5c"),
            fixture.variant.format() == "jades",
            "{}",
            fixture.id()
        );
    }
    Ok(())
}

#[test]
fn the_tsa_chain_is_passed_at_b_lt_only() -> TestResult {
    for fixture in plan() {
        let arguments = strings(&fixture.arguments(
            Path::new("corpus"),
            Path::new("/bin/testpki"),
            VALIDATION_TIME,
            Path::new("o"),
        )?);
        assert_eq!(
            arguments.contains(&"--tsa-chain".to_owned()),
            fixture.level == Level::Lt,
            "{}",
            fixture.id()
        );
    }
    Ok(())
}

#[test]
fn b_t_notes_rest_on_the_linked_files() -> TestResult {
    let notes = fixture("signed/cades-enveloping-b-t-p256")?
        .artefact(b"x")
        .notes
        .ok_or("no notes")?;
    assert!(notes.contains("timestamp-chain"), "{notes}");
    assert!(
        notes.contains("with the linked files, the signature timestamp passes"),
        "{notes}"
    );
    assert!(!notes.contains("not decided"), "{notes}");
    Ok(())
}

#[test]
fn only_timestamped_signatures_link_the_chain_of_the_tsa() {
    for fixture in plan() {
        let artefact = fixture.artefact(b"x");
        let expected: &[&str] = if fixture.level == Level::B {
            &[]
        } else {
            &["pki/tsa", "pki/ca-ecdsa", "pki/root-ca"]
        };
        assert_eq!(artefact.links.timestamp_chain, expected, "{}", fixture.id());
    }
}

/// The argument that makes [`child_process`] act, when the test binary
/// runs itself as a child: libtest takes it as a second filter, which
/// matches no test.
const CHILD: &str = "sigillum-testpki-child";

/// Does nothing in a normal run. Run as a child with [`CHILD`] and a mode,
/// it sleeps, writes much more than the limit to both outputs, fails with
/// a message, or starts a sleeping child that keeps its outputs open and
/// exits at once.
#[test]
fn child_process() -> TestResult {
    let args: Vec<String> = std::env::args().collect();
    let Some(at) = args.iter().position(|a| a == CHILD) else {
        return Ok(());
    };
    match args.get(at + 1).map(String::as_str) {
        Some("sleep") => std::thread::sleep(Duration::from_secs(30)),
        Some("flood") => {
            let block = vec![b'x'; 1 << 20];
            for _ in 0..4 {
                let _ = std::io::Write::write_all(&mut std::io::stdout(), &block);
                let _ = std::io::Write::write_all(&mut std::io::stderr(), &block);
            }
        }
        Some("fail") => {
            eprintln!("DSS cannot sign this");
            std::process::exit(3);
        }
        Some("hold") => {
            // The child inherits both outputs and outlives this process.
            Command::new(std::env::current_exe()?)
                .args(child_args("sleep"))
                .spawn()?;
        }
        _ => {}
    }
    Ok(())
}

fn child_args(mode: &str) -> Vec<OsString> {
    [
        "--exact",
        "signed::tests::child_process",
        "--nocapture",
        "--test-threads=1",
        CHILD,
        mode,
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// The oracle of the tests: this test binary as the launcher.
fn test_oracle(timeout: Duration) -> Result<JavaOracle, Box<dyn std::error::Error>> {
    Ok(JavaOracle {
        java: std::env::current_exe()?,
        jar: PathBuf::from("dss-oracle.jar"),
        timeout,
    })
}

/// The launcher runs in the current directory, with the time limit of the
/// oracle and 1 MiB for each output (issue #164).
#[test]
fn the_launcher_is_limited_to_one_mebibyte_of_output() -> TestResult {
    let java = std::env::current_exe()?;
    let timeout = Duration::from_secs(7);
    assert_eq!(
        test_oracle(timeout)?.program(),
        Program::new(&java, ".").with_limits(timeout, 1_048_576)
    );
    Ok(())
}

#[test]
fn a_launcher_that_runs_too_long_is_stopped() -> TestResult {
    let started = std::time::Instant::now();
    let result = run_oracle(
        &test_oracle(Duration::from_secs(1))?.program(),
        &child_args("sleep"),
    );
    assert!(
        matches!(&result, Err(message) if message.contains("ran longer than 1 s")),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    Ok(())
}

#[test]
fn a_launcher_that_exits_while_a_child_holds_its_outputs_is_stopped_at_the_deadline() -> TestResult
{
    let started = std::time::Instant::now();
    let result = run_oracle(
        &test_oracle(Duration::from_secs(2))?.program(),
        &child_args("hold"),
    );
    assert!(
        matches!(&result, Err(message) if message.contains("ran longer than 2 s")),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(20));
    Ok(())
}

#[test]
fn a_launcher_that_writes_too_much_is_stopped() -> TestResult {
    let result = run_oracle(
        &test_oracle(Duration::from_secs(60))?.program(),
        &child_args("flood"),
    );
    assert!(
        matches!(&result, Err(message) if message.contains("wrote more than")),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn a_launcher_that_fails_reports_its_error_output() -> TestResult {
    let result = run_oracle(
        &test_oracle(Duration::from_secs(60))?.program(),
        &child_args("fail"),
    );
    assert_eq!(result, Err("failed: DSS cannot sign this".to_owned()));
    assert_eq!(
        run_oracle(
            &test_oracle(Duration::from_secs(60))?.program(),
            &child_args("none")
        ),
        Ok(())
    );
    Ok(())
}

#[test]
fn jades_notes_describe_x5c_at_each_level() -> TestResult {
    for fixture in plan().into_iter().filter(|f| f.variant.format() == "jades") {
        let notes = fixture.artefact(b"x").notes.ok_or("no notes")?;
        if fixture.level == Level::Lt {
            assert!(
                notes.contains(
                    "x5c holds the signing certificate and the chain below the trust anchor"
                ),
                "{notes}"
            );
            assert!(notes.contains("pki/root-ca"), "{notes}");
        } else {
            assert!(
                notes.contains("x5c holds the signing certificate and the chain up to pki/root-ca"),
                "{notes}"
            );
        }
    }
    Ok(())
}

/// Issue #156: the signatures of the signer rsa, made with a 2048-bit key,
/// are the legacy-key-size case, with the reasoning of ETSI TS 119 312
/// V2.1.1 and the result of DSS in their notes, and unchanged predictions.
#[test]
fn the_rsa_signatures_are_the_legacy_key_size_case() -> TestResult {
    let mut count = 0;
    for fixture in plan() {
        let artefact = fixture.artefact(b"x");
        let notes = artefact.notes.ok_or("no notes")?;
        let legacy = fixture.signer.label == "rsa";
        assert_eq!(
            artefact.purpose.contains("legacy-key-size case"),
            legacy,
            "{}",
            artefact.id
        );
        assert_eq!(notes.contains("Table 6"), legacy, "{}", artefact.id);
        if legacy {
            count += 1;
            for wanted in [
                "2048 bits",
                "ETSI TS 119 312 V2.1.1, Table 6",
                "clause 8.4",
                "TOTAL_PASSED",
                "ASCCM_AR_ANS_AKSNR",
                "level WARN",
                "ADR-0023",
                "phase 2",
                "class 1 divergence (ADR-0019)",
            ] {
                assert!(notes.contains(wanted), "{wanted}: {notes}");
            }
        }
        assert_eq!(
            artefact.expected_dss,
            DssResult::Indication {
                indication: Indication::TotalPassed,
                sub_indication: None,
            },
            "{}",
            artefact.id
        );
        assert_eq!(artefact.dss_divergence, None, "{}", artefact.id);
    }
    assert_eq!(count, 16);
    Ok(())
}

/// Issue #112: the documents prepared for the three classes of shadow
/// attack are signed at B-B by pki/signer-p256 only, after the rest of the
/// plan, as PAdES signatures of their own base documents.
#[test]
fn the_shadow_documents_are_signed_at_b_b_by_one_signer() -> TestResult {
    let shadows: Vec<Fixture> = plan()
        .into_iter()
        .filter(|fixture| fixture.id().starts_with("signed/pades-shadow-"))
        .collect();
    let ids: Vec<String> = shadows.iter().map(Fixture::id).collect();
    assert_eq!(
        ids,
        [
            "signed/pades-shadow-hide-b-b-p256",
            "signed/pades-shadow-replace-b-b-p256",
            "signed/pades-shadow-hide-and-replace-b-b-p256",
        ]
    );
    assert_eq!(
        plan()[plan().len() - 3..]
            .iter()
            .map(Fixture::id)
            .collect::<Vec<_>>(),
        ids
    );
    let root = Path::new("corpus");
    for (fixture, document) in shadows.iter().zip([
        "documents/shadow-hide",
        "documents/shadow-replace",
        "documents/shadow-hide-and-replace",
    ]) {
        assert_eq!(
            fixture.path(),
            PathBuf::from(format!("{}.pdf", fixture.id()))
        );
        let arguments =
            strings(&fixture.arguments(root, Path::new("t"), VALIDATION_TIME, Path::new("o"))?);
        let at = arguments
            .iter()
            .position(|a| a == "--document")
            .ok_or("no --document")?;
        assert_eq!(
            arguments[at + 1],
            root.join(format!("{document}.pdf")).to_string_lossy()
        );
        let format = arguments
            .iter()
            .position(|a| a == "--format")
            .ok_or("no --format")?;
        assert_eq!(arguments[format + 1], "pades");
        assert!(!arguments.contains(&"--tsa-program".to_owned()));
        let artefact = fixture.artefact(b"x");
        assert_eq!(artefact.expected_openssl, OpensslResult::NotApplicable);
        assert_eq!(
            artefact.expected_dss,
            DssResult::Indication {
                indication: Indication::TotalPassed,
                sub_indication: None
            }
        );
        assert_eq!(artefact.attack_class, None);
        assert_eq!(artefact.links.issuer.as_deref(), Some("pki/signer-p256"));
        assert!(
            artefact.purpose.contains(&format!("over {document},")),
            "{}",
            artefact.purpose
        );
        let notes = artefact.notes.ok_or("no notes")?;
        assert!(notes.contains("mutations/pades-shadow-"), "{notes}");
    }
    let required = required_ids();
    for document in [
        "documents/shadow-hide",
        "documents/shadow-replace",
        "documents/shadow-hide-and-replace",
    ] {
        assert!(required.contains(&document.to_owned()), "{document}");
    }
    Ok(())
}

#[test]
fn shadow_purposes_name_the_class() -> TestResult {
    assert_eq!(
        fixture("signed/pades-shadow-hide-and-replace-b-b-p256")?
            .artefact(b"x")
            .purpose,
        "PAdES baseline signature, invisible, of a document prepared for a shadow attack of the hide-and-replace class, at B-B, over documents/shadow-hide-and-replace, by pki/signer-p256 with ECDSA on P-256 and SHA-256, created by DSS."
    );
    Ok(())
}

/// Issue #112: the signer of the shadow documents is an entry of SIGNERS,
/// taken by reference, so a missing signer cannot leave them unsigned.
#[test]
fn the_shadow_signer_is_the_p256_signer_of_the_corpus() {
    assert_eq!(SHADOW_SIGNER.label, "p256");
    assert!(SIGNERS.contains(SHADOW_SIGNER));
}
