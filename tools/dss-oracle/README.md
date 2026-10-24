# dss-oracle

A small Java command-line tool that runs [DSS](https://github.com/esig/dss), the European Commission's Digital Signature Service library, offline and deterministically. sigillum uses it as an external test oracle: `sigillum-oracle` and `sigillum-testpki` run it as a separate process to validate signatures and test PKI artefacts and to produce signed fixtures. The design is recorded in [ADR-0013](../../docs/design/adr/0013-dss-oracle-command-line-tool.md).

## Licensing

The code of this tool is written for sigillum and licensed like the rest of the repository, under Apache-2.0 OR MIT. It is not adapted from the DSS cookbook or demonstration code.

DSS is licensed under LGPL-2.1. It is a build-time and test-time dependency, resolved by Maven from Maven Central at the version pinned in `pom.xml` (property `dss.version`). No artefact that contains DSS, including the executable JAR built here, is committed, published or distributed, so the distribution conditions of LGPL-2.1 do not arise. The Maven dependencies fall outside the licence policy that `cargo deny` enforces for Rust, so they are listed below and checked by hand whenever they change.

## Building and running

The tool needs Java 21 or later and Maven.

```
mvn -B verify
java -jar target/dss-oracle.jar --version
```

Usage: `dss-oracle <mode> [options]`, or `dss-oracle --version` or `--help` on their own, with the modes `validate-document`, `validate-certificate`, `validate-timestamp` and `sign`, and the common options:

| Option | Meaning |
| --- | --- |
| `--validation-time <time>` | Fixed validation or signing time, as an RFC 3339 time with an offset |
| `--trust-anchor <file>` | Trust anchor certificate; repeatable |
| `--certificate <file>` | Certificate supplied offline; repeatable |
| `--crl <file>` | CRL supplied offline; repeatable |
| `--ocsp <file>` | OCSP response supplied offline; repeatable |
| `--out <directory>` | Output directory |

Exit codes: 0 success, 1 failure, 2 usage error, 3 mode not implemented yet, 4 network access attempted.

No mode may access the network, and three layers enforce it:

1. **Proxy selector.** The tool replaces the JVM's default proxy selector, which `java.net.URLConnection`, plain sockets and `java.net.http.HttpClient` consult before connecting unless a proxy is given explicitly.
2. **Name resolution.** A resolver registered as a `java.net.spi.InetAddressResolverProvider` service refuses every name lookup made through `java.net.InetAddress`, forward or reverse, during a run.
3. **No network in CI.** Continuous integration builds the tool with network access, then runs it in a network namespace without any. This covers only the jobs that run the tool that way: the check of this tool does, and the planned differential-test and fixture-verification jobs must do the same. The Maven tests run with network access.

The first two layers record every attempt, and a run with any attempt fails with exit code 4, even if the code that made the attempt ignored the error. In process, they do not see:

- NIO socket channels and UDP datagram sockets to an IP address;
- the JNDI DNS provider, which sends its own queries;
- connections to an IP address opened with an explicit `Proxy.NO_PROXY`;
- a `java.net.http.HttpClient` built with its own proxy selector, or built before the guard, connecting to an IP address.

Connections to a host name are caught by the second layer. The third layer covers the remaining gaps in the jobs that run the tool without network. The modes, once implemented, will configure DSS with offline sources only.

## Maven dependencies

Runtime dependencies of the tool, as reported by `license-maven-plugin` for DSS 6.5.1. Test-only dependencies (JUnit) are not included. "GNU Lesser General Public License" is the plugin's wording for DSS, which is licensed under LGPL-2.1.

| Artefact | Version | Licence |
| --- | --- | --- |
| `com.sun.activation:jakarta.activation` | 2.0.1 | EDL 1.0 |
| `com.sun.istack:istack-commons-runtime` | 4.0.1 | Eclipse Distribution License - v 1.0 |
| `eu.europa.ec.joinup.sd-dss:dss-alert` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-crl-parser` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-detailed-report-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-diagnostic-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-enumerations` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-i18n` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-jaxb-common` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-jaxb-parsers` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-model` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-simple-certificate-report-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-simple-report-jaxb` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-spi` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-utils` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-validation` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:dss-xml-common` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-trusted-list-v211` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-validation-report` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-xades` | 6.5.1 | GNU Lesser General Public License |
| `eu.europa.ec.joinup.sd-dss:specs-xmldsig` | 6.5.1 | GNU Lesser General Public License |
| `jakarta.xml.bind:jakarta.xml.bind-api` | 3.0.1 | Eclipse Distribution License - v 1.0 |
| `org.bouncycastle:bcpkix-jdk18on` | 1.86 | Bouncy Castle Licence |
| `org.bouncycastle:bcprov-jdk18on` | 1.86 | Bouncy Castle Licence |
| `org.bouncycastle:bcutil-jdk18on` | 1.86 | Bouncy Castle Licence |
| `org.glassfish.jaxb:jaxb-core` | 3.0.2 | Eclipse Distribution License - v 1.0 |
| `org.glassfish.jaxb:jaxb-runtime` | 3.0.2 | Eclipse Distribution License - v 1.0 |
| `org.glassfish.jaxb:txw2` | 3.0.2 | Eclipse Distribution License - v 1.0 |
| `org.slf4j:slf4j-api` | 2.0.20 | MIT |

On every change to `pom.xml`, regenerate the list with the command below and compare it with this table. Then update the table, and state in the pull request that the licences were checked.

```
mvn org.codehaus.mojo:license-maven-plugin:2.7.1:add-third-party -Dlicense.excludedScopes=test
```

The list is written to `target/generated-sources/license/THIRD-PARTY.txt`.
