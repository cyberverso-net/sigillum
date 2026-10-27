# Security policy

## Status

sigillum is pre-alpha. No version is supported for production use, and no security guarantees are offered for any current code. This policy nevertheless applies from the start, because signature software is security-critical by nature.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting for this repository: <https://github.com/cyberverso-net/sigillum/security/advisories/new> (Security tab, "Report a vulnerability"). Do not open a public issue.

Please include the affected component and version or commit, a description of the issue and its impact, and, where possible, a test vector or steps to reproduce.

## What to expect

- Acknowledgement within 7 days.
- An initial assessment within 30 days.
- Coordinated disclosure: a fix and an advisory are published together; reporters are credited unless they prefer otherwise.

## Scope

Of particular interest are issues that could lead to:

- acceptance of a forged, altered or otherwise invalid signature;
- a signature that appears to cover content it does not cover, including PDF shadow and incremental-update attacks;
- crashes, excessive resource use or memory-safety issues on malformed input;
- leakage of signing material through the signer or fetcher interfaces, or through the evidence requests and responses exchanged with the caller.

Vulnerabilities in third-party dependencies should be reported to their maintainers; please also let us know if sigillum is affected.
