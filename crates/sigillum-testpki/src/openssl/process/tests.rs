//! Tests of the child process runner. Except for the first, they run
//! programs that every Unix system has, in place of `openssl`.

use std::ffi::OsString;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use super::*;

fn args(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn a_missing_program_cannot_be_started() {
    let program = Program::new("sigillum-testpki-no-such-program", ".");
    let result = program.run(&args(&["version"]));
    let message = match result {
        Err(RunError::Spawn(message)) => message,
        Ok(_) | Err(_) => String::new(),
    };
    assert!(
        message.contains("sigillum-testpki-no-such-program"),
        "{message}"
    );
}

#[cfg(unix)]
#[test]
fn the_arguments_reach_the_program_unchanged_and_its_output_is_returned() -> Result<(), RunError> {
    let output = Program::new("echo", ".").run(&args(&["a b", "$HOME", "*", ";", "|x"]))?;
    assert!(output.success);
    assert_eq!(output.stdout, "a b $HOME * ; |x\n");
    assert_eq!(output.stderr, "");
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_failing_program_is_reported_with_its_error_output() -> Result<(), RunError> {
    let output = Program::new("ls", ".").run(&args(&["sigillum-testpki-no-such-file"]))?;
    assert!(!output.success);
    assert!(
        output.stderr.contains("sigillum-testpki-no-such-file"),
        "{}",
        output.stderr
    );
    let output = Program::new("false", ".").run(&[])?;
    assert!(!output.success);
    Ok(())
}

#[cfg(unix)]
#[test]
fn the_program_runs_in_the_given_directory() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().canonicalize()?;
    let output = Program::new("pwd", &dir).run(&args(&["-P"]))?;
    assert_eq!(output.stdout.trim_end(), dir.to_string_lossy());
    Ok(())
}

#[cfg(unix)]
#[test]
fn the_configuration_is_passed_in_openssl_conf() -> Result<(), RunError> {
    let output = Program::new("env", ".")
        .with_config("/sigillum/empty.cnf")
        .run(&[])?;
    assert!(
        output
            .stdout
            .lines()
            .any(|line| line == "OPENSSL_CONF=/sigillum/empty.cnf"),
        "{}",
        output.stdout
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn standard_input_is_empty() -> Result<(), RunError> {
    let output = Program::new("cat", ".")
        .with_limits(Duration::from_secs(10), 1024)
        .run(&[])?;
    assert!(output.success);
    assert_eq!(output.stdout, "");
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_program_that_runs_too_long_is_stopped() {
    let start = Instant::now();
    let limit = Duration::from_millis(200);
    let result = Program::new("sleep", ".")
        .with_limits(limit, 1024)
        .run(&args(&["30"]));
    assert_eq!(result, Err(RunError::TimedOut(limit)));
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[cfg(unix)]
#[test]
fn a_program_that_writes_too_much_is_stopped() {
    let start = Instant::now();
    let result = Program::new("yes", ".")
        .with_limits(Duration::from_secs(30), 4096)
        .run(&[]);
    assert_eq!(result, Err(RunError::OutputTooLarge(4096)));
    assert!(start.elapsed() < Duration::from_secs(10));
}

#[cfg(unix)]
#[test]
fn the_output_limit_is_inclusive_and_applies_to_each_output() -> Result<(), RunError> {
    let at_limit = Program::new("printf", ".")
        .with_limits(Duration::from_secs(10), 4)
        .run(&args(&["abcd"]))?;
    assert_eq!(at_limit.stdout, "abcd");
    let over = Program::new("printf", ".")
        .with_limits(Duration::from_secs(10), 3)
        .run(&args(&["abcd"]));
    assert_eq!(over, Err(RunError::OutputTooLarge(3)));
    let error_output = Program::new("ls", ".")
        .with_limits(Duration::from_secs(10), 3)
        .run(&args(&["sigillum-testpki-no-such-file"]));
    assert_eq!(error_output, Err(RunError::OutputTooLarge(3)));
    Ok(())
}

#[test]
fn the_errors_say_what_happened() {
    assert_eq!(
        RunError::TimedOut(Duration::from_secs(60)).to_string(),
        "ran longer than 60 s and was stopped"
    );
    assert_eq!(
        RunError::TimedOut(Duration::from_millis(200)).to_string(),
        "ran longer than 0.2 s and was stopped"
    );
    assert_eq!(
        RunError::OutputTooLarge(1024).to_string(),
        "wrote more than 1024 bytes to an output and was stopped"
    );
    assert_eq!(
        RunError::Spawn("x: not found".to_owned()).to_string(),
        "cannot be started: x: not found"
    );
    assert_eq!(
        RunError::Io("broken pipe".to_owned()).to_string(),
        "cannot be run: broken pipe"
    );
}

/// A wrapper that exits while a background child still writes to its
/// outputs for a moment: the run waits for them within the time limit.
#[cfg(unix)]
#[test]
fn outputs_closed_after_the_program_exits_are_collected() -> Result<(), RunError> {
    let output = Program::new("sh", ".")
        .with_limits(Duration::from_secs(30), 1024)
        .run(&args(&["-c", "(sleep 1; echo late) & echo early"]))?;
    assert!(output.success);
    assert_eq!(output.stdout, "early\nlate\n");
    Ok(())
}

/// A wrapper that leaves a background child holding its outputs, and then
/// exits: the run must still end at the time limit.
#[cfg(unix)]
#[test]
fn a_background_child_holding_the_outputs_cannot_block_a_run()
-> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let limit = Duration::from_millis(500);
    let result = Program::new("sh", ".")
        .with_limits(limit, 1024)
        .run(&args(&["-c", "sleep 30 & echo started"]));
    assert_eq!(result, Err(RunError::TimedOut(limit)));
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    Ok(())
}

/// A wrapper that runs too long, with a background child holding its
/// outputs: the run ends at the time limit, and the whole process group,
/// the background child included, is killed.
#[cfg(unix)]
#[test]
fn a_timed_out_run_kills_its_process_group() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "sigillum-testpki-process-group-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let start = Instant::now();
    // Long enough for the wrapper to record the background child under load.
    let limit = Duration::from_secs(5);
    let result = Program::new("sh", &dir)
        .with_limits(limit, 1024)
        .run(&args(&[
            "-c",
            "sleep 30 & echo $! > background.pid; sleep 30",
        ]));
    assert_eq!(result, Err(RunError::TimedOut(limit)));
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "{:?}",
        start.elapsed()
    );
    let pid = std::fs::read_to_string(dir.join("background.pid"))?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ends(pid.trim())?,
        "the background child {} survived",
        pid.trim()
    );
    Ok(())
}

/// A wrapper that writes too much, with a background child holding its
/// outputs: the run ends at once with the output error, and the whole
/// process group, the background child included, is killed.
#[cfg(unix)]
#[test]
fn a_run_that_writes_too_much_kills_its_process_group() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "sigillum-testpki-process-group-output-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let start = Instant::now();
    let result = Program::new("sh", &dir)
        .with_limits(Duration::from_secs(30), 4096)
        .run(&args(&["-c", "sleep 30 & echo $! > background.pid; yes"]));
    assert_eq!(result, Err(RunError::OutputTooLarge(4096)));
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    let pid = std::fs::read_to_string(dir.join("background.pid"))?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ends(pid.trim())?,
        "the background child {} survived",
        pid.trim()
    );
    Ok(())
}

/// A wrapper that exits at once, leaving a background child that holds its
/// outputs and a subshell that writes too much a moment later: the run
/// still ends at once with the output error, and the whole process group is
/// killed.
#[cfg(unix)]
#[test]
fn a_run_that_writes_too_much_after_it_exits_kills_its_process_group()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "sigillum-testpki-process-group-late-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    let start = Instant::now();
    let result = Program::new("sh", &dir)
        .with_limits(Duration::from_secs(30), 4096)
        .run(&args(&[
            "-c",
            "sleep 30 & echo $! > background.pid; (sleep 1; head -c 100000 /dev/zero) & exit 0",
        ]));
    assert_eq!(result, Err(RunError::OutputTooLarge(4096)));
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    let pid = std::fs::read_to_string(dir.join("background.pid"))?;
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        ends(pid.trim())?,
        "the background child {} survived",
        pid.trim()
    );
    Ok(())
}

/// Whether the process `pid` ends within ten seconds. A killed process
/// that has left the group stays a zombie until its new parent reaps it,
/// and `kill -0` still finds it then, so on Linux a zombie counts as ended.
#[cfg(unix)]
fn ends(pid: &str) -> Result<bool, std::io::Error> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let probe = std::process::Command::new("kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()?;
        if !probe.success() || zombie(pid) {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(false)
}

/// Whether `/proc` shows the process `pid` as a zombie. The state follows
/// the command name, which is in parentheses and may contain any byte.
#[cfg(unix)]
fn zombie(pid: &str) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
    })
}
