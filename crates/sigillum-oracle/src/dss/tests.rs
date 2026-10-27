//! Tests of the location of the tool, without running it.

use std::path::Path;

use super::*;

fn os(value: &str) -> Option<OsString> {
    Some(OsString::from(value))
}

/// A file that exists, standing for the JAR.
fn existing() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
}

#[test]
fn the_default_jar_is_the_one_that_maven_builds_here() {
    let jar = default_jar();
    assert!(jar.is_absolute(), "{}", jar.display());
    assert!(jar.ends_with(Path::new("tools/dss-oracle/target/dss-oracle.jar")));
    assert!(
        jar.parent()
            .and_then(Path::parent)
            .is_some_and(|tool| tool.join("pom.xml").is_file()),
        "{}",
        jar.display()
    );
}

#[test]
fn the_variables_name_the_jar_and_the_launcher() -> Result<(), String> {
    let jar = existing().into_os_string();
    let dss = Dss::from_variables(Some(jar.clone()), os("/opt/java/bin/java"), os("/jdk"))?;
    assert_eq!(dss.oracle().jar, PathBuf::from(&jar));
    assert_eq!(dss.oracle().java, PathBuf::from("/opt/java/bin/java"));
    assert_eq!(dss.oracle().timeout, sigillum_testpki::dss::TIMEOUT);
    let home = Dss::from_variables(Some(jar.clone()), None, os("/jdk"))?;
    assert_eq!(
        home.oracle().java,
        Path::new("/jdk").join("bin").join("java")
    );
    let empty = Dss::from_variables(Some(jar.clone()), os(""), os(""))?;
    assert_eq!(empty.oracle().java, PathBuf::from("java"));
    let path = Dss::from_variables(Some(jar), None, None)?;
    assert_eq!(path.oracle().java, PathBuf::from("java"));
    Ok(())
}

#[test]
fn a_relative_jar_is_made_absolute() -> Result<(), String> {
    let dss = Dss::from_variables(os("Cargo.toml"), None, None)?;
    assert!(dss.oracle().jar.is_absolute());
    Ok(())
}

#[test]
fn a_missing_jar_says_how_to_build_it() {
    let missing = existing().with_file_name("no-such.jar").into_os_string();
    let error = Dss::from_variables(Some(missing), None, None)
        .err()
        .unwrap_or_default();
    assert!(error.contains("no-such.jar"), "{error}");
    assert!(error.contains("mvn -B package"), "{error}");
    assert!(error.contains(JAR_VARIABLE), "{error}");
    let empty = Dss::from_variables(os(""), None, None);
    match empty {
        Ok(dss) => assert_eq!(dss.oracle().jar, default_jar()),
        Err(error) => assert!(error.contains("dss-oracle.jar"), "{error}"),
    }
}

#[test]
fn a_launcher_that_cannot_start_is_a_run_error() -> Result<(), crate::TimeError> {
    let dss = Dss::new("/no/such/java", existing());
    let validation = Validation::certificate(existing(), time::OffsetDateTime::UNIX_EPOCH)?;
    assert!(matches!(
        dss.validate(&validation),
        Err(OracleError::Run(_))
    ));
    assert!(matches!(dss.check_version("6.5.1"), Err(DssError::Run(_))));
    Ok(())
}
