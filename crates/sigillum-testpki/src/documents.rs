//! The unsigned base documents of the signed corpus, under `documents/`
//! (ADR-0014): a small PDF, a PDF with an empty signature field, a text
//! payload and a JSON payload.
//!
//! The PDF files are written directly from ISO 32000-1:2008, without a PDF
//! library: a header and binary comment (clause 7.5.2), the objects of the
//! body (clause 7.5.3), a cross-reference table of one subsection
//! (clause 7.5.4), and a trailer with the file identifiers of clause 14.4
//! (clause 7.5.5). Every byte is fixed, so the documents are reproduced
//! byte for byte, and they do not depend on the validation time.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::manifest::{Artefact, DssResult, Kind, Links, OpensslResult};
use crate::pki::{self, GenerateError, GeneratedFile, Summary, sha256_hex};

/// The directory of the base documents, relative to the manifest.
pub const DIRECTORY: &str = "documents";

/// The identifier of the small PDF.
pub const SIMPLE_PDF_ID: &str = "documents/simple";
/// The identifier of the PDF with an empty signature field.
pub const SIGNATURE_FIELD_PDF_ID: &str = "documents/signature-field";
/// The identifier of the text payload.
pub const TEXT_ID: &str = "documents/text";
/// The identifier of the JSON payload.
pub const JSON_ID: &str = "documents/payload";

/// The text payload.
const TEXT: &[u8] = b"sigillum test corpus: the text payload of the signed corpus under signed/.\n";

/// The JSON payload (RFC 8259), on one line.
const JSON: &[u8] = b"{\"corpus\":\"sigillum\",\"purpose\":\"the JSON payload of the signed corpus under signed/\",\"version\":1}\n";

/// The content stream of the single page: one line of text in Helvetica,
/// a standard Type 1 font (clause 9.6.2.2), with the text operators of
/// clause 9.4.
const PAGE_CONTENT: &str = "BT /F1 12 Tf 72 770 Td (sigillum test document) Tj ET";

/// The name of the signature field of the PDF with a signature field.
pub const SIGNATURE_FIELD_NAME: &str = "Signature1";

/// Generates the base documents, in the order of the manifest.
pub fn generate() -> Vec<GeneratedFile> {
    vec![
        file(
            SIMPLE_PDF_ID,
            "pdf",
            pdf("simple", false),
            "A small PDF of one page with one line of text, the base document of the PAdES signatures.",
        ),
        file(
            SIGNATURE_FIELD_PDF_ID,
            "pdf",
            pdf("signature-field", true),
            "A small PDF of one page with an empty, invisible signature field named Signature1 in its interactive form, an unsigned input reserved for signing into an existing field.",
        ),
        file(
            TEXT_ID,
            "txt",
            TEXT.to_vec(),
            "A line of text, the signed content of the CAdES signatures.",
        ),
        file(
            JSON_ID,
            "json",
            JSON.to_vec(),
            "A JSON object on one line, the payload of the JAdES signatures.",
        ),
    ]
}

fn file(id: &str, extension: &str, contents: Vec<u8>, purpose: &str) -> GeneratedFile {
    GeneratedFile {
        artefact: Artefact {
            id: id.to_owned(),
            path: PathBuf::from(format!("{id}.{extension}")),
            sha256: sha256_hex(&contents),
            kind: Kind::Document,
            purpose: purpose.to_owned(),
            expected_openssl: OpensslResult::NotApplicable,
            expected_dss: DssResult::NotApplicable,
            links: Links::default(),
            attack_class: None,
            dss_divergence: None,
            notes: None,
        },
        contents,
    }
}

/// Writes a PDF 1.7 file of one page. With `signature_field`, the catalog
/// holds an interactive form (clause 12.7.2) with one signature field
/// without a value (clause 12.7.4.5), merged with its widget annotation
/// (clause 12.5.6.19), which a rectangle of zero size makes invisible.
fn pdf(name: &str, signature_field: bool) -> Vec<u8> {
    let mut objects: Vec<String> = Vec::new();
    // Clause 7.7.2: the document catalog.
    objects.push(if signature_field {
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] >> >>".to_owned()
    } else {
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned()
    });
    // Clause 7.7.3: the page tree, with one page of A4 size in points.
    objects.push("<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned());
    let annotations = if signature_field {
        " /Annots [6 0 R]"
    } else {
        ""
    };
    objects.push(format!(
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R{annotations} >>"
    ));
    objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_owned());
    // Clause 7.3.8: a stream whose Length counts the bytes between the end-of-line marker after
    // "stream" and the one before "endstream".
    objects.push(format!(
        "<< /Length {} >>\nstream\n{PAGE_CONTENT}\nendstream",
        PAGE_CONTENT.len()
    ));
    if signature_field {
        // The annotation flag Print (bit 3, clause 12.5.3) is set, as for a visible annotation; the
        // empty rectangle keeps the field invisible.
        objects.push(format!(
            "<< /FT /Sig /T ({SIGNATURE_FIELD_NAME}) /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /F 4 /P 3 0 R >>"
        ));
    }

    // Clause 7.5.2: the header, then a comment of four bytes of 128 or more, which marks the
    // file as binary.
    let mut out: Vec<u8> = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{object}\nendobj\n", index + 1).as_bytes());
    }
    let xref = out.len();
    // Clause 7.5.4: one subsection from object 0, each entry exactly 20 bytes long, ending with
    // a two-character end-of-line marker.
    out.extend_from_slice(format!("xref\n0 {}\n", objects.len() + 1).as_bytes());
    out.extend_from_slice(b"0000000000 65535 f\r\n");
    for offset in offsets {
        out.extend_from_slice(format!("{offset:010} 00000 n\r\n").as_bytes());
    }
    // Clause 14.4: the two identifiers are equal in a file that was never updated. They are
    // derived from the name of the document, so that they are fixed.
    let identifier =
        hex(&Sha256::digest(format!("sigillum test document {name}").as_bytes())[..16]);
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /ID [<{identifier}> <{identifier}>] >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn hex(bytes: &[u8]) -> String {
    let text: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
    if text.len() != bytes.len() * 2 {
        return String::new();
    }
    text
}

/// Reports whether an entry belongs to what `generate documents`
/// produces: any entry whose identifier is under [`DIRECTORY`].
fn generated_here(artefact: &Artefact) -> bool {
    artefact.id.starts_with(&format!("{DIRECTORY}/"))
}

/// Writes the base documents under the directory of the manifest at
/// `manifest_path`, and records each in the manifest, following the
/// regeneration rules of [`pki::write_into_corpus`]. Every entry under
/// [`DIRECTORY`] belongs to this generator. The documents do not depend on
/// the validation time or on any other entry.
///
/// # Errors
///
/// Returns a [`GenerateError`] if the manifest cannot be read or updated,
/// or a file cannot be written.
pub fn write_into_corpus(manifest_path: &Path) -> Result<Summary, GenerateError> {
    pki::write_generated(
        manifest_path,
        DIRECTORY,
        generated_here,
        |_| Ok(generate()),
        |_, _| {},
    )
}

#[cfg(test)]
mod tests;
