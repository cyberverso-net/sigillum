# ADR-0001: Record architecture decisions

- **Status:** Accepted
- **Date:** 2026-10-22

## Context

sigillum implements security-critical standards over several years, with contributors who may join long after a choice was made. Decisions about dependencies, scope and API shape are easy to forget and hard to reconstruct from code alone.

## Decision

Significant decisions are recorded as architecture decision records in `docs/design/adr/`, following the process in the [ADR index](README.md). Each ADR has a status, a date, the context, the decision, the alternatives considered and the consequences.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Decisions in issues only | No extra files | Hard to find; mixed with discussion; lost when issues are closed |
| A single design document | One place to read | Grows unwieldy; history of changes is unclear |
| ADRs in the repository | Versioned with the code; one decision per file; superseding keeps history | Requires discipline to write them |

## Consequences

Contributors read the relevant ADRs before proposing changes in those areas. Pull requests that make a significant decision include an ADR.
