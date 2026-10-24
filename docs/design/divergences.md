# Recorded divergences from DSS

This register lists every case in which sigillum intentionally produces a different result from DSS. The process is described in [conformance.md](conformance.md).

| Id | Format | Description | Standard clause | Test vector | Upstream report | Status |
| --- | --- | --- | --- | --- | --- | --- |
| DIV-1 | JAdES | DSS accepts detached signatures with the `ObjectIdByURI` mechanism over more than one object. sigillum reports INDETERMINATE with "not supported", because the boundary between objects is not signed. Class 3, intentional restriction ([ADR-0019](adr/0019-divergence-classes-and-intentional-restrictions.md)), decided in [ADR-0018](adr/0018-restrict-jades-payloads-and-detached-mechanisms.md) | ETSI TS 119 182-1 V1.2.1, clause 5.2.8.3.2 | To be added with the J5 fixture | None yet; a report to ETSI ESI is optional under ADR-0019 | Accepted; fixture pending (J5) |
