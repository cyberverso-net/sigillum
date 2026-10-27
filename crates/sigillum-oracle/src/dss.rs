//! The runs of the real `tools/dss-oracle` with Java, behind the feature
//! `dss` (ADR-0013). The tool runs as `java -Xmx512m -XX:+UseSerialGC -jar
//! <jar> <mode> ...`, without a shell, with the limits that
//! `sigillum-testpki verify --dss` gives it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sigillum_testpki::dss::{DssError, TIMEOUT, check_version};
use sigillum_testpki::openssl::{RunError, Scratch};
use sigillum_testpki::signed::JavaOracle;

use crate::summary::Summary;
use crate::validation::{OracleError, Validation, run};

/// The variable that names the executable JAR of `tools/dss-oracle`.
pub const JAR_VARIABLE: &str = "SIGILLUM_ORACLE_JAR";

/// The variable that names the Java launcher.
pub const JAVA_VARIABLE: &str = "SIGILLUM_ORACLE_JAVA";

/// The JAR that `mvn -B package` builds in `tools/dss-oracle`, in this
/// repository.
pub fn default_jar() -> PathBuf {
    let jar =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/dss-oracle/target/dss-oracle.jar");
    std::path::absolute(&jar).unwrap_or(jar)
}

/// `tools/dss-oracle`, run by a Java launcher, for at most
/// [`sigillum_testpki::dss::TIMEOUT`] per run: the time limit of the
/// validation and one minute for the JVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dss {
    oracle: JavaOracle,
}

impl Dss {
    /// The tool in `jar`, run by the launcher `java`.
    pub fn new(java: impl Into<PathBuf>, jar: impl Into<PathBuf>) -> Self {
        let mut oracle = JavaOracle::new(java.into(), jar.into());
        oracle.timeout = TIMEOUT;
        Self { oracle }
    }

    /// The tool that the environment names: the JAR of [`JAR_VARIABLE`], or
    /// [`default_jar`], run by the launcher of [`JAVA_VARIABLE`], or else
    /// `bin/java` under `JAVA_HOME`, or else `java` from the `PATH`.
    ///
    /// # Errors
    ///
    /// Returns a message when the JAR does not exist.
    pub fn from_env() -> Result<Self, String> {
        Self::from_variables(
            std::env::var_os(JAR_VARIABLE),
            std::env::var_os(JAVA_VARIABLE),
            std::env::var_os("JAVA_HOME"),
        )
    }

    /// The tool that the values of [`JAR_VARIABLE`], [`JAVA_VARIABLE`] and
    /// `JAVA_HOME` name, as [`Dss::from_env`] reads them. An empty value
    /// counts as none.
    ///
    /// # Errors
    ///
    /// Returns a message when the JAR does not exist.
    pub fn from_variables(
        jar: Option<OsString>,
        java: Option<OsString>,
        java_home: Option<OsString>,
    ) -> Result<Self, String> {
        let given = |value: Option<OsString>| value.filter(|value| !value.is_empty());
        let jar = given(jar).map_or_else(default_jar, PathBuf::from);
        let jar = std::path::absolute(&jar).unwrap_or(jar);
        if !jar.is_file() {
            return Err(format!(
                "the JAR of tools/dss-oracle, {}, does not exist; build it with mvn -B package in tools/dss-oracle, or name it with {JAR_VARIABLE}",
                jar.display()
            ));
        }
        let java = match (given(java), given(java_home)) {
            (Some(java), _) => PathBuf::from(java),
            (None, Some(home)) => Path::new(&home).join("bin").join("java"),
            (None, None) => PathBuf::from("java"),
        };
        Ok(Self::new(java, jar))
    }

    /// The runner of the tool, for [`crate::run`] and
    /// [`crate::validate_corpus`].
    pub fn oracle(&self) -> &JavaOracle {
        &self.oracle
    }

    /// Checks that the tool is built against the DSS version `expected`,
    /// and returns that version.
    ///
    /// # Errors
    ///
    /// Returns a [`DssError`] when the tool cannot be run, does not print
    /// its version line, or is built against another version of DSS.
    pub fn check_version(&self, expected: &str) -> Result<String, DssError> {
        check_version(&self.oracle, expected)
    }

    /// Runs `validation` in a temporary directory, removed afterwards, and
    /// returns its summary.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`crate::run`], and [`OracleError::Run`] when
    /// no temporary directory can be created.
    pub fn validate(&self, validation: &Validation) -> Result<Summary, OracleError> {
        let scratch =
            Scratch::create().map_err(|e| OracleError::Run(RunError::Io(e.to_string())))?;
        run(&self.oracle, validation, &scratch.path().join("run"))
    }
}

#[cfg(test)]
mod tests;
