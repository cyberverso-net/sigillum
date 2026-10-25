//! Runs the `openssl` program as a child process, with explicit
//! arguments and no shell, a bounded output and a time limit.

use std::ffi::OsString;
use std::io::Read;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use super::{Output, RunError, Runner};

/// The default time limit of one run.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// The default limit of each output of one run, in bytes.
pub const DEFAULT_OUTPUT_LIMIT: usize = 1024 * 1024;

/// The `openssl` program, run in the directory of the corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    program: PathBuf,
    dir: PathBuf,
    config: Option<PathBuf>,
    timeout: Duration,
    output_limit: usize,
}

impl Program {
    /// The program `program`, found on `PATH` when it is a bare name, run
    /// in `dir`, with the default limits and the default configuration.
    pub fn new(program: impl Into<PathBuf>, dir: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            dir: dir.into(),
            config: None,
            timeout: DEFAULT_TIMEOUT,
            output_limit: DEFAULT_OUTPUT_LIMIT,
        }
    }

    /// Runs the program with `OPENSSL_CONF` set to `config`.
    #[must_use]
    pub fn with_config(mut self, config: impl Into<PathBuf>) -> Self {
        self.config = Some(config.into());
        self
    }

    /// Stops a run after `timeout`, or when one of its outputs exceeds
    /// `output_limit` bytes.
    #[must_use]
    pub fn with_limits(mut self, timeout: Duration, output_limit: usize) -> Self {
        self.timeout = timeout;
        self.output_limit = output_limit;
        self
    }
}

impl Runner for Program {
    /// Runs the program with `args` and an empty standard input, and
    /// collects both outputs. A run that exceeds the time limit, or writes
    /// more than the output limit to either output, is killed.
    ///
    /// The time limit covers the reading of the outputs too: a run whose
    /// outputs stay open after the program exits, held by a process it
    /// started, ends with [`RunError::TimedOut`] at the limit. On Unix the
    /// program runs in a process group of its own, which is killed then,
    /// with every process it started. On other platforms only the program
    /// itself is killed, and the threads reading the outputs are left to
    /// end when the outputs close.
    fn run(&self, args: &[OsString]) -> Result<Output, RunError> {
        let mut command = Command::new(&self.program);
        command
            .args(args)
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(config) = &self.config {
            command.env("OPENSSL_CONF", config);
        }
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
        let deadline = Instant::now() + self.timeout;
        let mut child = command
            .spawn()
            .map_err(|e| RunError::Spawn(format!("{}: {e}", self.program.display())))?;
        let overflow = Arc::new(AtomicBool::new(false));
        let stdout = child
            .stdout
            .take()
            .map(|pipe| self.reader(pipe, Arc::clone(&overflow)));
        let stderr = child
            .stderr
            .take()
            .map(|pipe| self.reader(pipe, Arc::clone(&overflow)));
        let success = match self.wait(&mut child, &overflow, deadline) {
            Ok(success) => success,
            Err(error) => {
                stop_group(&child);
                return Err(error);
            }
        };
        let outputs = collect(stdout, deadline)
            .and_then(|stdout| collect(stderr, deadline).map(|stderr| (stdout, stderr)));
        let (stdout, stderr) = match outputs {
            Ok(outputs) => outputs,
            Err(Collect::TimedOut) => {
                stop_group(&child);
                return Err(RunError::TimedOut(self.timeout));
            }
            Err(Collect::Failed(error)) => return Err(error),
        };
        if overflow.load(Ordering::Relaxed) {
            return Err(RunError::OutputTooLarge(self.output_limit));
        }
        Ok(Output {
            success,
            stdout,
            stderr,
        })
    }
}

impl Program {
    /// Reads `pipe` on its own thread, keeping at most the output limit,
    /// and sends the result. Beyond the limit, the reader sets `overflow`
    /// and discards the rest, so that the child never blocks on a full
    /// pipe before it is killed.
    fn reader(
        &self,
        pipe: impl Read + Send + 'static,
        overflow: Arc<AtomicBool>,
    ) -> Receiver<std::io::Result<Vec<u8>>> {
        let limit = self.output_limit;
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let read = || {
                let mut pipe = pipe;
                let mut bytes = Vec::new();
                (&mut pipe)
                    .take(u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1))
                    .read_to_end(&mut bytes)?;
                if bytes.len() > limit {
                    overflow.store(true, Ordering::Relaxed);
                    bytes.truncate(limit);
                    std::io::copy(&mut pipe, &mut std::io::sink())?;
                }
                Ok(bytes)
            };
            // The receiver is gone when the run has ended at its limit.
            let _ = sender.send(read());
        });
        receiver
    }

    /// Waits for the child to exit, and kills it when it runs past
    /// `deadline` or writes too much. Returns whether it exited with 0.
    fn wait(
        &self,
        child: &mut Child,
        overflow: &AtomicBool,
        deadline: Instant,
    ) -> Result<bool, RunError> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status.success()),
                Ok(None) if overflow.load(Ordering::Relaxed) => {
                    stop(child);
                    return Ok(false);
                }
                Ok(None) if Instant::now() >= deadline => {
                    stop(child);
                    return Err(RunError::TimedOut(self.timeout));
                }
                Ok(None) => std::thread::sleep(POLL_INTERVAL),
                Err(error) => {
                    stop(child);
                    return Err(RunError::Io(error.to_string()));
                }
            }
        }
    }
}

/// How often a running child is polled.
const POLL_INTERVAL: Duration = Duration::from_millis(5);

/// Kills the child and reaps it. Either may fail when it has just exited.
fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Kills the process group of the child, which `run` makes the child
/// lead, so that the processes it started end too. The standard library
/// has no call for this without unsafe code, which the crate forbids, so
/// the `kill` program does it, found in `PATH` and run without a shell.
#[cfg(unix)]
fn stop_group(child: &Child) {
    let _ = Command::new("kill")
        .args(["-s", "KILL", "--", &format!("-{}", child.id())])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Other platforms have no process group to kill.
#[cfg(not(unix))]
fn stop_group(_child: &Child) {}

/// Why an output could not be collected.
enum Collect {
    /// The deadline passed first.
    TimedOut,
    /// The reader failed.
    Failed(RunError),
}

/// The output that a reader thread collected, as text, if it arrives
/// before `deadline`.
fn collect(
    reader: Option<Receiver<std::io::Result<Vec<u8>>>>,
    deadline: Instant,
) -> Result<String, Collect> {
    let Some(reader) = reader else {
        return Ok(String::new());
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    let bytes = match reader.recv_timeout(remaining) {
        Ok(read) => read.map_err(|e| Collect::Failed(RunError::Io(e.to_string())))?,
        Err(RecvTimeoutError::Timeout) => return Err(Collect::TimedOut),
        Err(RecvTimeoutError::Disconnected) => {
            return Err(Collect::Failed(RunError::Io(
                "the thread reading an output failed".to_owned(),
            )));
        }
    };
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests;
