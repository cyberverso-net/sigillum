//! The unsigned base documents of the signed corpus, under `documents/`
//! (ADR-0014): a small PDF, a PDF with an empty signature field, a text
//! payload, a JSON payload, and three PDFs prepared for the shadow attacks
//! of threat D2 of the threat model, one per class (issue #112).
//!
//! A shadow attack prepares content in the document before it is signed
//! and shows it through a later incremental update (*Shadow Attacks:
//! Hiding and Replacing Content in Signed PDFs*, NDSS 2021). The prepared
//! documents are signed by DSS like the small PDF, and `generate mutations`
//! appends the later change ([`crate::mutations`]):
//!
//! - hide: a line of text drawn under a white rectangle, a separate content
//!   stream that the update empties;
//! - replace: a text field whose value and appearance the update replaces;
//! - hide-and-replace: a second page tree, which no object in use refers
//!   to, that the update makes the page tree of the catalog.
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
/// The identifier of the PDF prepared for a shadow attack of the hide class.
pub const SHADOW_HIDE_PDF_ID: &str = "documents/shadow-hide";
/// The identifier of the PDF prepared for a shadow attack of the replace class.
pub const SHADOW_REPLACE_PDF_ID: &str = "documents/shadow-replace";
/// The identifier of the PDF prepared for a shadow attack of the
/// hide-and-replace class.
pub const SHADOW_HIDE_AND_REPLACE_PDF_ID: &str = "documents/shadow-hide-and-replace";

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

/// The content stream of the page of the hide document: the line of the
/// small PDF, and a second line that [`OVERLAY`] covers.
const HIDE_CONTENT: &str = "BT /F1 12 Tf 72 770 Td (sigillum test document) Tj ET\nBT /F1 12 Tf 72 740 Td (shadow content, covered when signed) Tj ET";

/// The second content stream of the page of the hide document: a white
/// rectangle, filled (ISO 32000-1:2008, clauses 8.6.8 and 8.5.3.1), over
/// the second line of [`HIDE_CONTENT`]. The page draws it last.
const OVERLAY: &str = "1 g 66 734 300 20 re f";

/// The content stream of the page of the replace document: the line of the
/// small PDF, and the label of the text field.
const REPLACE_CONTENT: &str =
    "BT /F1 12 Tf 72 770 Td (sigillum test document) Tj ET\nBT /F1 12 Tf 72 726 Td (Amount:) Tj ET";

/// The value of the text field of the replace document when it is signed.
pub(crate) const AMOUNT_SIGNED: &str = "100 EUR";

/// The second page tree of the hide-and-replace document, object 6, with
/// its page, object 7, which no object in use refers to.
pub(crate) const HIDDEN_PAGES: &str = "<< /Type /Pages /Kids [7 0 R] /Count 1 >>";

/// The content stream of the page of the second page tree.
const HIDDEN_PAGE_CONTENT: &str =
    "BT /F1 12 Tf 72 770 Td (sigillum shadow document, shown after signing) Tj ET";

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
        file(
            SHADOW_HIDE_PDF_ID,
            "pdf",
            write_pdf("shadow-hide", &shadow_hide_objects()),
            "A small PDF of one page prepared for a shadow attack of the hide class: a second line of text under a white rectangle drawn by a content stream of its own, which mutations/pades-shadow-hide empties after signing.",
        ),
        file(
            SHADOW_REPLACE_PDF_ID,
            "pdf",
            write_pdf("shadow-replace", &shadow_replace_objects()),
            "A small PDF of one page prepared for a shadow attack of the replace class: a text field named Amount with the value 100 EUR and its appearance, which mutations/pades-shadow-replace replaces after signing.",
        ),
        file(
            SHADOW_HIDE_AND_REPLACE_PDF_ID,
            "pdf",
            write_pdf(
                "shadow-hide-and-replace",
                &shadow_hide_and_replace_objects(),
            ),
            "A small PDF of one page prepared for a shadow attack of the hide-and-replace class: a second page tree with a page of other text, which no object in use refers to and which mutations/pades-shadow-hide-and-replace makes the page tree of the catalog after signing.",
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

/// A stream object (clause 7.3.8) with `content` and the entries `entries`
/// before its `/Length`, which counts the bytes between the end-of-line
/// marker after `stream` and the one before `endstream`.
pub(crate) fn stream(entries: &str, content: &str) -> String {
    format!(
        "<<{entries} /Length {} >>\nstream\n{content}\nendstream",
        content.len()
    )
}

/// The page dictionary of one page of A4 size in points, with Helvetica as
/// /F1, under the page tree `parent`, with `contents` as its Contents entry
/// and `rest` after it (clause 7.7.3.3).
fn page(parent: u32, contents: &str, rest: &str) -> String {
    format!(
        "<< /Type /Page /Parent {parent} 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents {contents}{rest} >>"
    )
}

/// The font of every page: Helvetica, a standard Type 1 font (clause 9.6.2.2).
const FONT: &str = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

/// The overlay of the hide document, object 6.
pub(crate) fn overlay_object() -> String {
    stream("", OVERLAY)
}

/// The text field of the replace document, object 6: a field of type Tx
/// with `value` (clause 12.7.4.3), merged with its widget annotation
/// (clause 12.5.6.19), whose normal appearance is the object `appearance`
/// (clause 12.5.5). It uses the font /Helv of the default resources of the
/// interactive form.
pub(crate) fn amount_field(value: &str, appearance: u32) -> String {
    format!(
        "<< /FT /Tx /T (Amount) /V ({value}) /DA (/Helv 12 Tf 0 g) /Type /Annot /Subtype /Widget /Rect [130 720 330 740] /F 4 /P 3 0 R /AP << /N {appearance} 0 R >> >>"
    )
}

/// The normal appearance of the text field showing `value`: a form
/// XObject (clause 8.10) of the size of the field, with the marked content
/// /Tx of a variable text field (clause 12.7.3.3).
pub(crate) fn amount_appearance(value: &str) -> String {
    stream(
        " /Type /XObject /Subtype /Form /BBox [0 0 200 20] /Resources << /Font << /Helv 4 0 R >> >>",
        &format!("/Tx BMC BT /Helv 12 Tf 2 6 Td ({value}) Tj ET EMC"),
    )
}

/// The objects of the hide document: the page draws [`HIDE_CONTENT`] and
/// then [`OVERLAY`], in the order of its Contents array.
fn shadow_hide_objects() -> Vec<String> {
    vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        page(2, "[5 0 R 6 0 R]", ""),
        FONT.to_owned(),
        stream("", HIDE_CONTENT),
        overlay_object(),
    ]
}

/// The objects of the replace document: an interactive form with one text
/// field and default resources (clause 12.7.2), shown on the page.
fn shadow_replace_objects() -> Vec<String> {
    vec![
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R] /DA (/Helv 12 Tf 0 g) /DR << /Font << /Helv 4 0 R >> >> >> >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        page(2, "5 0 R", " /Annots [6 0 R]"),
        FONT.to_owned(),
        stream("", REPLACE_CONTENT),
        amount_field(AMOUNT_SIGNED, 7),
        amount_appearance(AMOUNT_SIGNED),
    ]
}

/// The objects of the hide-and-replace document: the page tree of the
/// small PDF, and a second one, objects 6 to 8, that no object in use
/// refers to.
fn shadow_hide_and_replace_objects() -> Vec<String> {
    vec![
        "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
        page(2, "5 0 R", ""),
        FONT.to_owned(),
        stream("", PAGE_CONTENT),
        HIDDEN_PAGES.to_owned(),
        page(6, "8 0 R", ""),
        stream("", HIDDEN_PAGE_CONTENT),
    ]
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
    objects.push(page(2, "5 0 R", annotations));
    objects.push(FONT.to_owned());
    objects.push(stream("", PAGE_CONTENT));
    if signature_field {
        // The annotation flag Print (bit 3, clause 12.5.3) is set, as for a visible annotation; the
        // empty rectangle keeps the field invisible.
        objects.push(format!(
            "<< /FT /Sig /T ({SIGNATURE_FIELD_NAME}) /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /F 4 /P 3 0 R >>"
        ));
    }

    write_pdf(name, &objects)
}

/// Writes a PDF 1.7 file with `objects`, numbered from 1, its catalog first.
fn write_pdf(name: &str, objects: &[String]) -> Vec<u8> {
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
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
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
