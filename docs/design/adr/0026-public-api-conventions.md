# ADR-0026: Set the conventions of the public signing API

- **Status:** Accepted
- **Date:** 2026-10-27
- **Issue:** #125

## Context

[ADR-0005](0005-two-step-signing.md) splits signature creation into `prepare` and `assemble`, with an external key holder in between. [ADR-0006](0006-no-network-access-in-core.md) keeps network access out of the core, behind a caller-supplied fetcher. [ADR-0011](0011-asn1-x509-cms-foundations.md) keeps third-party types out of the public API. [ADR-0017](0017-defensive-api-rules.md) adds eight defensive rules, and [ADR-0024](0024-bounded-decoding-of-untrusted-input.md) requires caller-configurable limits at every decoding entry point. These records fix principles. They do not fix the concrete shape of the API that the format crates share.

Phase 1 implements the signing API in three crates (`sigillum-cades`, `sigillum-pades` and `sigillum-jades`), then exposes it to Kotlin, Swift and JavaScript through `sigillum-ffi`. Without common conventions, each crate would settle the same questions differently, and the binding layer would have to reconcile them. The open questions are the following.

- **Waiting for the network.** Timestamp tokens, OCSP responses, CRLs and certificates are retrieved during `assemble`. A blocking fetcher cannot run in WebAssembly, where the browser only offers asynchronous requests. On Android and iOS, a blocking call on the user-interface thread is not acceptable. An asynchronous fetcher would bring an async runtime, or at least async traits, into every core crate and every binding.
- **Time.** Signed attributes carry a signing time, and B-LT checks revocation at a given time. The library could read the system clock. WebAssembly has no reliable clock of its own, and the test corpus needs fixed times to be reproducible.
- **Signature value encodings.** ECDSA values are DER-encoded `ECDSA-Sig-Value` structures in CMS, and fixed-length `r || s` in JWS ([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518), section 3.4). Key holders return either form: platform keystores usually return DER, while remote services and hardware tokens may return either.
- **What the key holder signs.** Remote services through the Cloud Signature Consortium API sign a digest. Some platform keystores sign the data and compute the digest themselves. Ed25519 signs the data itself, with no prior digest.
- **Errors and limits.** Errors must not reveal document content (threat R3), must distinguish unsupported input from malformed input ([ADR-0007](0007-asymmetric-scope.md)), and must map onto exceptions in the bindings.

The shared types are first used by CAdES B-B. If ADR-0027 (proposed, #133) is accepted, JAdES B-B uses them next, before PAdES, so that the API is tried on a binary and a JSON format before it is used more widely. Otherwise the order of the [roadmap](../../project/roadmap.md) applies.

## Decision

### 1. One shape for every format crate

Each format crate exposes the same functions, with the same parameters in the same order:

- `prepare(document, signer_chain, options, context) -> Prepared`
- `assemble(prepared_state, document, signer_chain, options, signature_value, context) -> Assembly`
- `resume(assembly_state, document, signer_chain, options, responses, context) -> Assembly`

`document` is the content to be signed, given in memory. For detached CAdES signatures, the caller may give the digest of the content instead, with its algorithm. That algorithm must be the digest algorithm of the chosen signature algorithm, because one digest algorithm of the `SignerInfo` computes both the `message-digest` attribute and the digest of the signed attributes ([ETSI EN 319 122-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf), clause 5.1.2, and [RFC 5652](https://www.rfc-editor.org/rfc/rfc5652), section 5.4); otherwise the call fails with `InvalidInput`. For JAdES, digests in place of the objects are allowed only with the `ObjectIdByURIHash` mechanism ([ETSI TS 119 182-1 V1.2.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf), clause 5.2.8.3.3). Its `sigD` carries, in `hashV`, one digest per object, computed over the base64url encoding of the object, because `b64` is never false ([ADR-0018](0018-restrict-jades-payloads-and-detached-mechanisms.md); clause 5.2.8.1), and names one digest algorithm for all objects in `hashM`. The caller then gives, for each object, the digest of its base64url encoding, all computed with that one algorithm. This differs from the CAdES case, where the digest is computed over the content itself. With `ObjectIdByURI`, the signing input includes the base64url encoding of the object itself (clause 5.2.8.3.2, and ADR-0018), so a digest is refused with `InvalidInput`.

`signer_chain` is the signing certificate followed by its issuers, as DER. `options` are the format's own choices: level, packaging, signature algorithm, and the attributes or header parameters the caller sets. `context` is shared by all formats and described in decision 4. `assemble` and `resume` receive the document, the signer chain and the options again, in the same form as `prepare`, and a context with the same signing time and the same supplied evidence, because they recompute everything that is signed (decision 6). The signature value is given to `assemble` only; the assembly state keeps it for `resume`.

`prepare` never retrieves anything. The `x5c` header parameter of JAdES carries the `signer_chain` as supplied. `prepare`, `assemble` and `resume` each validate the path of the re-supplied `signer_chain` to a trust anchor of the context at the validation time, at every level including B-B, without revocation checking, and check the key usage of the signing certificate (threat G4). The check is repeated at every call because CAdES and PAdES sign only a reference to the signing certificate, so a changed intermediate certificate would not change the signed data. A `signer_chain` that does not reach an anchor of the context, because a certificate is missing or invalid, is `InvalidInput`. The revocation status of the signing certificate is checked at B-LT, in `assemble` and `resume` ([ADR-0017](0017-defensive-api-rules.md), rule 7). Evidence that goes into signed attributes or protected header parameters, a CAdES content timestamp ([ETSI EN 319 122-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf), clause 5.2.8) or a JAdES `adoTst`, is used only when the caller supplies it in the context. It must be the same at every call, and each call validates it as rule 6 of ADR-0017 requires of fetched evidence. A token whose message imprint cannot be checked against the input given is `InvalidInput`: a content timestamp over the content when only a digest with another algorithm is given, and an `adoTst` with `ObjectIdByURIHash` and digest input, because it is computed over the objects (clause 5.2.8.3.3, NOTE 2). Without supplied evidence, these options are `NotSupported` in phase 1. `assemble` and `resume` collect the validation data for B-LT through the loop of decision 2. In CAdES they go into `SignedData.certificates` and `SignedData.crls`, because `certificate-values` and `revocation-values` shall not be present at B-LT ([ETSI EN 319 122-1 V1.3.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf), clause 6.3, Table 1). In PAdES they go into the DSS dictionary, added in an incremental update after the signed revision ([ETSI EN 319 142-1 V1.2.1](https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.02.01_60/en_31914201v010201p.pdf), clauses 5.4.1, 5.4.2.2 and 6.3). In JAdES they go into the `xVals` and `rVals` components of the `etsiU` unsigned header parameter (ETSI TS 119 182-1 V1.2.1, clauses 5.3.1 and 5.3.5).

The crates share their common types through `sigillum-pki`. No format crate depends on another, as [architecture.md](../architecture.md) requires. Encryption in `sigillum-cms` has no signer and no evidence loop; its API follows decisions 3, 4, 7 and 8 of this record, and its shape is decided when encryption is planned.

### 2. Network access without blocking: requests returned to the caller

This decision changes four earlier records. In [ADR-0005](0005-two-step-signing.md), `assemble` retrieved timestamps and revocation data itself; it now returns requests instead. In [ADR-0006](0006-no-network-access-in-core.md), all retrieval went through a caller-supplied `Fetcher`; for signature creation, the `Fetcher` now becomes a convenience over the loop described here. Retrieval during verification is decided in phase 2. The principle of ADR-0006, that the core performs no network access, is unchanged. In [ADR-0012](0012-certificate-path-validation.md), missing intermediate certificates were retrieved only through the caller's fetcher; during signature creation, those of the chains of evidence, such as the certificates of a TSA or an OCSP responder, are now requested through this loop. The `signer_chain` is never completed by retrieval (decision 1). In [ADR-0017](0017-defensive-api-rules.md), rules 3 and 8 restricted and bounded the fetcher interface; they now apply to the requests and responses of this loop. Rule 2 is met by recomputing everything that is signed from inputs supplied again at each call, instead of comparing them with the state, and rules 1, 2, 6 and 7 apply to `resume` as to `assemble` (decision 6).

The core never waits for the network. When `assemble` needs evidence from outside, it returns `Assembly::NeedsEvidence`, with a list of requests and an opaque state. Each request states:

- an identifier, unique within the operation;
- its kind: timestamp, OCSP, CRL or certificate;
- the URL, restricted to `http` and `https` ([ADR-0017](0017-defensive-api-rules.md), rule 3). A URL with another scheme is skipped, and the skipped URL is reported to the caller with the request list and in the final result, as rule 3 requires;
- the certificate extension it came from, when it came from one;
- the request body, for timestamp and OCSP requests;
- the maximum response size ([ADR-0017](0017-defensive-api-rules.md), rule 8).

The caller performs the requests in whatever way suits the platform, synchronous or asynchronous, then calls `resume` with the document, the signer chain, the options and the responses. The caller answers every pending request with exactly one response or one failure, each naming the identifier of its request. A missing, duplicate or unknown identifier is `StateMismatch`. A response of another kind than its request, such as a CRL for an OCSP request, is `EvidenceRejected`, as is a response that fails its checks (ADR-0017, rule 6). In addition to rule 6, a signature timestamp is accepted only if its `genTime`, widened by its stated accuracy, does not precede the signing time of the context; this check does not depend on the state. Evidence that cannot yet be validated because a certificate of its own chain is missing, such as the intermediate certificate of a TSA or an OCSP responder, is held as pending validation, distinct from rejected evidence. It may lead to requests for the missing certificates, within the limits, and it is never embedded nor counted for the level until it validates. A failure marks its request as unavailable. If another source can supply the same evidence, such as another URL of the same extension or a CRL in place of an OCSP response, `resume` requests it in a later round, within the limits of the context. If no source remains for evidence that the requested level needs, the operation ends with `EvidenceUnavailable`. The one exception is an undetermined revocation status of the signing certificate at B-LT: if the context accepts a lower level ([ADR-0017](0017-defensive-api-rules.md), rule 7), the operation completes at that level. A missing signature timestamp at B-T or above is always `EvidenceUnavailable`. `resume` returns either another `NeedsEvidence` or `Assembly::Complete`, which carries the signed object and the level reached. The request URLs and bodies, except the nonces of decision 9, and the set of evidence still needed for the level, are always derived from the re-supplied inputs and from the evidence that the current call has validated again; the pending requests kept in the state serve only to match the identifiers of responses. The level reached is computed from the evidence validated again by the last call. The limits of the context bound the number of requests and the response sizes of each call, and the number of rounds as far as the caller passes the state on unchanged (decision 6). The driver `sign_with` keeps its own count of rounds and requests outside the state. The core itself is therefore free of async code and of any runtime.

The `Fetcher` interface of ADR-0006 becomes a convenience layer for Rust callers with blocking network access. A function `sign_with(signer, fetcher, ...)` runs `prepare`, the signer, `assemble` and every `resume` round in sequence. This mirrors the `Signer` convenience of [ADR-0005](0005-two-step-signing.md). The bindings expose the stepwise functions directly, and each language may add its own asynchronous convenience on top.

`Signer` and `Fetcher` are public traits for Rust callers. Each format crate also implements a common signing-flow trait, defined in `sigillum-pki`, whose methods delegate to the crate's `prepare`, `assemble` and `resume`. `sign_with` is generic over that trait, so one driver serves every format. The free functions of decision 1 remain the primary API. The bindings do not use these traits (decision 10).

### 3. Explicit time

The library never reads a clock. The context carries:

- the signing time, which becomes the `signing-time` attribute in CAdES and the `iat` header parameter in JAdES ([ETSI TS 119 182-1 V1.2.1](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf), clause 5.1.11, which since 15 July 2025 replaces `sigT` in new signatures);
- the validation time, at which the signing certificate and the fetched evidence are checked before embedding ([ADR-0017](0017-defensive-api-rules.md), rules 6 and 7), and at which verification validates in phase 2.

Every signing operation requires the signing time, and every operation that validates requires the validation time. Signing validates the signer chain in `prepare` (decision 1), so it requires both. The signing time must be the same at every call of one signing operation, because it is part of what is signed (decision 6). The caller passes the current time in normal use, and fixed times in tests and in the corpus.

### 4. The context

`Context` is one structure shared by every format and by verification in phase 2. It carries:

- the times of decision 3, each required by the operations that use it;
- the trust anchors, as DER certificates, for checking the signing chain and the chains of fetched evidence;
- additional certificates and revocation data the caller already has, so that no request is made for them;
- evidence for signed attributes or protected header parameters that the caller supplies, such as a CAdES content timestamp or a JAdES `adoTst` (decision 1);
- the limits of [ADR-0024](0024-bounded-decoding-of-untrusted-input.md) and of threat P2: input sizes, nesting depth, number of rounds and requests, response sizes. Each has a documented default and a documented maximum;
- explicit choices that relax a defensive rule, such as accepting a lower level when the revocation status is unknown ([ADR-0017](0017-defensive-api-rules.md), rule 7). Every such choice is off by default.

`Context` and the options structures are `#[non_exhaustive]` and built through constructors with defaults, so that fields can be added before 1.0 without breaking callers.

### 5. What the key holder receives

`Prepared` gives the caller:

- the data to be signed, in full;
- its digest and the digest algorithm, when the signature algorithm uses one;
- the signature algorithm, as an identifier from a closed list defined by sigillum;
- the prepared state, as described in decision 6.

The caller passes to the key holder whichever of the data or the digest it accepts. For Ed25519, only the full data is offered.

The caller returns the signature value with its encoding stated: `Der` or `Raw` for ECDSA, and the single defined form for RSA and Ed25519. sigillum converts it into the form the format requires. It never guesses the encoding from the bytes, because a guess is a parser ambiguity (threat P3). A value stated as `Der` that does not parse as an `ECDSA-Sig-Value` is `Malformed`. `assemble` then verifies the value against the data and the certificate's public key ([ADR-0017](0017-defensive-api-rules.md), rule 1).

### 6. The prepared and assembly states

States are byte strings that the caller stores and returns unchanged. They are opaque to the caller, but not secret and not authenticated, as ADR-0017 records. A state is never authoritative: nothing in it decides what is signed or which evidence is accepted.

1. **Inputs supplied at every call.** `prepare`, `assemble` and `resume` each receive the document, the signer chain, the options and the context. The signing time and the evidence for signed elements are carried in the context (decisions 3 and 4) and must be the same at every call of one operation. Everything that is signed is recomputed from these inputs at every call and never copied from a state: the signed attributes, including `message-digest`, the protected header parameters, including `sigD` with `hashV`, and the PAdES revision up to the signature value. The unsigned parts are built in the same way from evidence validated again by the current call, never copied from the state: the PAdES revision with the DSS dictionary, any document timestamp, and the unsigned attributes or header parameters. The validation time, the trust anchors and the limits come from the context of the current call, and the path of the signer chain and the supplied evidence are validated again at every call (decision 1).
2. **Binding through the signature.** The signature value must verify over the data recomputed by the current call, with the public key of the first certificate of the re-supplied `signer_chain` ([ADR-0017](0017-defensive-api-rules.md), rule 1). `assemble` verifies the value it receives. `resume` accepts the value kept in the assembly state only if it verifies in the same way. Any change between `prepare` and a later call that alters what is signed or the signer therefore ends in an error, even for a signer with a valid certificate under a trusted anchor: `StateMismatch` when the early check of point 3 detects it, as for another signer chain, and `SignatureMismatch` otherwise, as for another document or another signing time. The value must verify over the recomputed data; it need not stay byte-identical. A change of the signature value that still verifies over the same data with the same key, such as the ECDSA value s replaced by n - s, is not detected and changes neither what is signed nor the signer. This meets rule 2 of ADR-0017 without trusting the state.
3. **Early consistency check.** Some inputs are not signed: the level, the CAdES packaging and the JAdES serialisation, among others. The prepared and assembly states therefore keep a digest of all the options, of the signer chain and of the evidence for signed elements supplied in the context. Each call compares it with the re-supplied inputs, and any difference is `StateMismatch`. Because the state is not authenticated, this check detects inconsistent inputs from the caller, not tampering with the state. It can only refuse, never accept: the signed data is still recomputed and the signature value still verified.
4. **What a state keeps.** Besides the digest of point 3, a state keeps only what cannot be recomputed: the format, the version and the step; in the assembly state, the signature value, the pending requests with their identifiers and nonces, the round counter, the evidence obtained in earlier rounds, including evidence pending validation, and the sources that failed. Skipped URLs are not kept: they are recomputed from the chain and the evidence. Evidence taken from the state is validated again before it is used, exactly like fresh evidence, with the trust anchors, the validation time and the limits of the current context (ADR-0017, rule 6). Replacing kept evidence with other valid evidence is therefore accepted, and harmless. Nonces and pending requests serve only to match responses to requests: a matching nonce is required where the state records one, but never makes a response acceptable on its own. Because the state is not trusted, a nonce removed or replaced in it lets a replayed timestamp or OCSP response pass the nonce check; the other checks of rule 6 and the `genTime` check of decision 2 still apply. The record of failed sources can only make the operation try another source or fail, never accept. A source wrongly marked as failed leads at worst to `EvidenceUnavailable`, or to a lower level only where ADR-0017, rule 7, allows it.
5. **Limits.** The limits of the context apply to each call. The round counter and the record of requests make them hold across rounds only as far as the caller passes the state on unchanged; without a trusted state, the library cannot enforce a bound across calls. A caller that alters the counter only runs more rounds of requests that it performs itself. The caller, or the driver `sign_with`, keeps the budget across calls. A value taken from the state never raises a limit of the current call.
6. **Checks on every call, in order.** `assemble` and every call of `resume` decode the state (point 7: `Malformed`, `LimitExceeded`), run the early consistency check (point 3: `StateMismatch`), validate the signer chain, recompute the signed data and verify the signature value (point 2: `SignatureMismatch`), and validate the evidence held so far. They do all this before they issue any request or return any object.
7. **Decoding.** A state is encoded in DER by sigillum, with a format identifier, a version number and the step. It is decoded with the size limit and length walk that apply to any untrusted input, because the caller may have altered it (threat G1). A state that does not decode is `Malformed`. A state larger than the limit of the context is `LimitExceeded`. A state of another format, version or step, or one that fails the early consistency check, is `StateMismatch`.

States are not guaranteed to be readable by a different version of sigillum. A caller that stores them across an upgrade must finish or restart the operation.

### 7. Inputs and outputs are bytes and sigillum types

Public functions take and return byte slices, byte vectors and types defined by sigillum. No type from `der`, `x509-cert`, `cms`, `serde_json` or a cryptographic crate appears in the public API ([ADR-0011](0011-asn1-x509-cms-foundations.md)). Certificates are passed as DER. Outputs are complete encoded objects: a CMS structure, a PDF file, a JWS in the requested serialisation.

Documents are held in memory in phase 1. Streaming input for large documents is deferred. The stories that create the format crates record this limitation in their rustdoc. The digest option of decision 1 covers the largest detached contents.

### 8. Errors

`sigillum-pki` defines one error type used by every library crate. It is `#[non_exhaustive]` and offers a `kind()` method with these categories at least:

- `Malformed`: input that does not follow its encoding;
- `LimitExceeded`: a limit of the context was reached;
- `NotSupported`: a valid input or option outside the scope ([ADR-0007](0007-asymmetric-scope.md));
- `InvalidInput`: inconsistent arguments, such as a key type that does not match the signature algorithm, or a key usage that forbids signing (threat G4);
- `StateMismatch`: a state from another format, version or step, or one that fails the early consistency check with the re-supplied inputs, and responses that do not match the pending requests by identifier;
- `SignatureMismatch`: a signature value that does not verify (threat G2);
- `EvidenceRejected`: fetched or supplied evidence that fails its checks, or a revoked signing certificate (threats G5 to G7);
- `EvidenceUnavailable`: evidence that the caller could not retrieve.

An error carries its kind, the location in the input where one applies (an offset, a JSON pointer or a PDF object number) and a fixed message. It never carries document content or key material (threat R3). The binding layer maps each kind to an exception or error class of the target language.

Errors are for operations that cannot complete. Verification results in phase 2 are values, not errors ([ADR-0017](0017-defensive-api-rules.md), rule 4).

### 9. Determinism

Given the same inputs, including the times, the signature value and the fetched responses, `prepare`, `assemble` and `resume` produce the same bytes. `prepare` must be deterministic, because `assemble` and `resume` recompute what it produced (decision 6). Nonces in timestamp and OCSP requests are the one source of randomness. They are drawn from the operating system through `getrandom`, or taken from the context when the caller supplies them, as the tests and the corpus do.

### 10. Bindings

The Rust API may use traits and borrowed data. `sigillum-ffi` wraps it in the records, enumerations and objects that UniFFI and `wasm-bindgen` support. The stepwise design of decision 2 and the byte-string states of decision 6 keep this wrapping thin: every call takes and returns plain data, and no callback crosses the language boundary.

## Alternatives considered

| Option | Advantages | Disadvantages |
| --- | --- | --- |
| Blocking `Fetcher` trait, as ADR-0006 first described | Simplest Rust API | Cannot run in WebAssembly; blocks threads on mobile; callbacks across the binding boundary |
| Asynchronous `Fetcher` (async traits) | Natural in async Rust | An async runtime or async traits in every core crate; harder bindings; less deterministic tests |
| Requests returned to the caller, with a blocking convenience layer (chosen) | No async in the core; fits every platform and binding; deterministic and testable with the corpus | The caller drives a short loop; one more public function per format |
| The library reads the system clock | Fewer parameters | Not available reliably in WebAssembly; tests and corpus not reproducible |
| Signature value encoding detected from the bytes | Simpler for callers | A parser ambiguity; a wrong guess produces a wrong signature |
| One error type per crate | Each crate free to evolve | Conversions between crates; several hierarchies to map in each binding |
| Authenticated states (MAC with a library key) | Detects tampering early | The library holds no secret by design (ADR-0005, ADR-0017) |
| States authenticated with a MAC key supplied by the caller | Detects tampering early; no secret in the library | Key management falls on every caller and every binding; the library still holds no secret to protect the key with (ADR-0005, ADR-0017) |
| States that bind digests of the inputs, compared with the re-supplied inputs | The caller keeps fewer inputs | The unauthenticated state still decides what is signed wherever no comparison rule covers it; one comparison rule per input form |
| States never authoritative: every signed element recomputed from re-supplied inputs, bound by verifying the signature value, with an early check of the unsigned inputs that can only refuse (chosen) | One rule for every format and input form; tampering that alters what is signed or the signer ends in `SignatureMismatch`, other changes of the inputs in `StateMismatch` | The caller supplies the document, chain and options at each call; `prepare` must be deterministic |

## Consequences

- ADR-0005, ADR-0006, ADR-0012 and ADR-0017 receive dated notes pointing to decision 2, and for ADR-0005 and ADR-0017 also to decision 6. The core still performs no network access. [architecture.md](../architecture.md) is updated to show the request and response loop, and the review checklist of [quality-gates.md](../../development/quality-gates.md) refers to it.
- The first stories of phase 1 create the shared types in `sigillum-pki`: `Context` with its limits, the error type, the signature algorithm identifiers, the request and response types, and the state encoding. CAdES B-B then uses them, and so does JAdES B-B before PAdES if ADR-0027 (proposed, #133) is accepted; otherwise the order of the roadmap applies. Each must fit them without format-specific exceptions. If one needs an exception, a new ADR superseding the affected part of this record is accepted before the next format starts.
- Every `assemble` and `resume` test drives the evidence loop from the corpus files, with the fixed times of the manifest. No test needs a network.
- Tests change each re-supplied input and each field of each state between calls, and expect `SignatureMismatch` or `StateMismatch`, including a swapped assembly state for another signer, a changed intermediate certificate and a changed level, packaging or serialisation.
- The bindings in `sigillum-ffi` expose the stepwise functions. Kotlin, Swift and JavaScript conveniences built on coroutines, `async`/`await` or promises are part of the binding work, not of the core.
- Streaming of large documents is to be recorded as a known limitation in the rustdoc of the format crates, by the stories that create them, and may be the subject of a later ADR.
