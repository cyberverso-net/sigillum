# Writing style guide

These rules apply to everything written in the project: documentation, rustdoc, comments, issues, pull requests, commit messages and release notes.

## Language

- British English: *licence* (noun) and *license* (verb), *organisation*, *behaviour*, *serialise*, *initialise*.
- Technical but plain. Use the exact term from the standard (signed attributes, document security store, trust anchor), and explain it the first time it appears in a document if the reader may not know it.
- No marketing language: avoid words such as *powerful*, *seamless*, *cutting-edge*, *robust* (unless describing a tested property).
- No emoji.

## Sentences and structure

- Lead with the point. The first sentence of a document or section states what it is for or what it concludes.
- Short sentences, ideally under 25 words. One idea per sentence.
- Active voice: "The verifier rejects…" rather than "…is rejected by the verifier".
- Use commas or full stops rather than long dashes.
- Use tables for comparisons and reference material, numbered lists for sequences, and bullets only for genuinely parallel items.
- State numbers with units, and dates in ISO 8601 format (2026-10-22).

## Referencing standards

Cite standards by number and clause: "ETSI EN 319 122-1, clause 5.2.3", "RFC 5652, section 5.3". Name the version when the difference matters. Link to the publicly available text where one exists.

## Rustdoc

- Every public item has a summary line that completes the sentence "This item…" without repeating its name.
- Document errors under an `# Errors` heading and panics (which should not exist in library code) under `# Panics`.
- Include an example for every public entry point once the API is stable.
- Cite the clause implemented, as above.

## Commit messages, issues and pull requests

- Commit summary: imperative mood, at most 72 characters, no trailing full stop ("Add CAdES signing-certificate-v2 attribute").
- Body: why the change was made, wrapped at 72 characters.
- Issue and pull request titles follow the same form as commit summaries.
- Content is factual and self-contained; a reader should not need any other conversation to understand it.
