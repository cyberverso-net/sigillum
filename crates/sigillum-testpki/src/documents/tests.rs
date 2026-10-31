use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn find<'a>(files: &'a [GeneratedFile], id: &str) -> Result<&'a GeneratedFile, String> {
    files
        .iter()
        .find(|file| file.artefact.id == id)
        .ok_or_else(|| format!("{id} is not generated"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The position of `needle` in `haystack`.
fn position(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn generates_the_seven_base_documents() -> TestResult {
    let files = generate();
    let ids: Vec<&str> = files.iter().map(|f| f.artefact.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "documents/simple",
            "documents/signature-field",
            "documents/text",
            "documents/payload",
            "documents/shadow-hide",
            "documents/shadow-replace",
            "documents/shadow-hide-and-replace"
        ]
    );
    let paths: Vec<String> = files
        .iter()
        .map(|f| f.artefact.path.to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        paths,
        [
            "documents/simple.pdf",
            "documents/signature-field.pdf",
            "documents/text.txt",
            "documents/payload.json",
            "documents/shadow-hide.pdf",
            "documents/shadow-replace.pdf",
            "documents/shadow-hide-and-replace.pdf"
        ]
    );
    for file in &files {
        let artefact = &file.artefact;
        assert_eq!(artefact.kind, Kind::Document);
        assert_eq!(artefact.expected_openssl, OpensslResult::NotApplicable);
        assert_eq!(artefact.expected_dss, DssResult::NotApplicable);
        assert_eq!(artefact.sha256, sha256_hex(&file.contents));
        assert_eq!(artefact.links, Links::default());
        assert!(!artefact.purpose.trim().is_empty());
    }
    Ok(())
}

#[test]
fn generation_is_deterministic() {
    assert_eq!(generate(), generate());
}

#[test]
fn the_payloads_are_fixed_text() -> TestResult {
    let files = generate();
    assert_eq!(
        find(&files, "documents/text")?.contents,
        b"sigillum test corpus: the text payload of the signed corpus under signed/.\n"
    );
    assert_eq!(
        text(&find(&files, "documents/payload")?.contents),
        "{\"corpus\":\"sigillum\",\"purpose\":\"the JSON payload of the signed corpus under signed/\",\"version\":1}\n"
    );
    Ok(())
}

/// Checks the file structure of ISO 32000-1:2008, clause 7.5: the header,
/// a cross-reference table whose offsets point at each object, the
/// trailer, `startxref` and the end-of-file marker.
fn check_structure(pdf: &[u8], objects: usize) -> TestResult {
    assert!(pdf.starts_with(b"%PDF-1.7\n%"), "header");
    // Clause 7.5.2: the comment after the header holds at least four bytes of 128 or more.
    assert!(
        pdf[10..14].iter().all(|byte| *byte >= 128),
        "binary comment"
    );
    assert!(pdf.ends_with(b"%%EOF\n"), "end-of-file marker");
    let start = position(pdf, b"startxref\n").ok_or("no startxref")?;
    let offset: usize = text(&pdf[start + 10..pdf.len() - 6]).trim().parse()?;
    assert!(pdf[offset..].starts_with(b"xref\n"), "startxref offset");
    let header = format!("xref\n0 {}\n", objects + 1);
    assert!(pdf[offset..].starts_with(header.as_bytes()), "subsection");
    let mut entry = offset + header.len();
    // Clause 7.5.4: each entry is exactly 20 bytes, the free head first.
    assert_eq!(&pdf[entry..entry + 20], b"0000000000 65535 f\r\n");
    for number in 1..=objects {
        entry += 20;
        let line = text(&pdf[entry..entry + 20]);
        assert!(line.ends_with(" 00000 n\r\n"), "{line:?}");
        let object: usize = line[..10].parse()?;
        let expected = format!("{number} 0 obj\n");
        assert!(
            pdf[object..].starts_with(expected.as_bytes()),
            "object {number} at {object}"
        );
    }
    let trailer = text(&pdf[entry + 20..start]);
    assert!(trailer.starts_with("trailer\n<<"), "{trailer}");
    assert!(
        trailer.contains(&format!("/Size {}", objects + 1)),
        "{trailer}"
    );
    assert!(trailer.contains("/Root 1 0 R"), "{trailer}");
    // Clause 14.4: two file identifiers of 16 bytes each.
    let id = trailer.find("/ID [<").ok_or("no /ID")?;
    assert_eq!(&trailer[id + 38..id + 41], "> <", "{trailer}");
    assert_eq!(&trailer[id + 73..id + 75], ">]", "{trailer}");
    Ok(())
}

#[test]
fn the_simple_pdf_has_a_valid_file_structure() -> TestResult {
    let files = generate();
    let pdf = &find(&files, "documents/simple")?.contents;
    check_structure(pdf, 5)?;
    let body = text(pdf);
    assert!(body.contains("/Type /Catalog /Pages 2 0 R"), "{body}");
    assert!(
        body.contains("/Type /Pages /Kids [3 0 R] /Count 1"),
        "{body}"
    );
    assert!(body.contains("/MediaBox [0 0 595 842]"), "{body}");
    assert!(body.contains("/BaseFont /Helvetica"), "{body}");
    assert!(!body.contains("/AcroForm"), "{body}");
    Ok(())
}

#[test]
fn the_content_stream_length_is_exact() -> TestResult {
    let files = generate();
    for id in [
        "documents/simple",
        "documents/signature-field",
        "documents/shadow-hide",
        "documents/shadow-replace",
        "documents/shadow-hide-and-replace",
    ] {
        let pdf = &find(&files, id)?.contents;
        let body = text(pdf);
        let mut streams = 0;
        let mut from = 0;
        // Every stream of the file, each after its own /Length.
        while let Some(found) = body[from..].find("/Length ") {
            let length_at = from + found;
            let length: usize = body[length_at + 8..]
                .split(' ')
                .next()
                .ok_or("no length")?
                .parse()?;
            let stream =
                length_at + position(&pdf[length_at..], b"stream\n").ok_or("no stream")? + 7;
            // Clause 7.3.8.1: the end-of-line marker before endstream is not counted.
            assert_eq!(
                &pdf[stream + length..stream + length + 10],
                b"\nendstream",
                "{id}"
            );
            streams += 1;
            from = stream + length;
        }
        assert!(streams >= 1, "{id}");
    }
    Ok(())
}

/// The object `number` of a PDF written by this module, without its
/// `obj` and `endobj` lines.
fn object(pdf: &[u8], number: usize) -> Result<String, String> {
    let body = text(pdf);
    let start = body
        .find(&format!("\n{number} 0 obj\n"))
        .ok_or(format!("no object {number}"))?
        + format!("\n{number} 0 obj\n").len();
    let end = start + body[start..].find("\nendobj\n").ok_or("no endobj")?;
    Ok(body[start..end].to_owned())
}

/// The content of the stream object `number`.
fn stream_content(pdf: &[u8], number: usize) -> Result<String, String> {
    let object = object(pdf, number)?;
    let start = object.find("\nstream\n").ok_or("no stream")? + 8;
    let end = object.rfind("\nendstream").ok_or("no endstream")?;
    Ok(object[start..end].to_owned())
}

#[test]
fn the_shadow_hide_document_covers_a_line_with_an_overlay() -> TestResult {
    let files = generate();
    let pdf = &find(&files, "documents/shadow-hide")?.contents;
    check_structure(pdf, 6)?;
    assert_eq!(object(pdf, 1)?, "<< /Type /Catalog /Pages 2 0 R >>");
    // The page draws its content and then the overlay, in that order
    // (ISO 32000-1:2008, clause 7.7.3.3, Table 30, Contents).
    assert!(object(pdf, 3)?.contains("/Contents [5 0 R 6 0 R]"));
    let content = stream_content(pdf, 5)?;
    assert!(content.contains("(sigillum test document)"), "{content}");
    assert!(
        content.contains("72 740 Td (shadow content, covered when signed) Tj"),
        "{content}"
    );
    // A white rectangle, filled, over the second line (clauses 8.6.8 and 8.5.3).
    assert_eq!(stream_content(pdf, 6)?, "1 g 66 734 300 20 re f");
    assert_eq!(object(pdf, 6)?, overlay_object());
    Ok(())
}

#[test]
fn the_shadow_replace_document_has_a_filled_text_field() -> TestResult {
    let files = generate();
    let pdf = &find(&files, "documents/shadow-replace")?.contents;
    check_structure(pdf, 7)?;
    let catalog = object(pdf, 1)?;
    assert!(
        catalog.contains("/AcroForm << /Fields [6 0 R] /DA (/Helv 12 Tf 0 g) /DR << /Font << /Helv 4 0 R >> >> >>"),
        "{catalog}"
    );
    assert!(object(pdf, 3)?.contains("/Annots [6 0 R]"));
    // Clause 12.7.4.3: a text field with its value, merged with its widget,
    // whose normal appearance shows the value.
    assert_eq!(object(pdf, 6)?, amount_field(AMOUNT_SIGNED, 7));
    assert!(object(pdf, 6)?.contains("/FT /Tx /T (Amount) /V (100 EUR)"));
    assert_eq!(object(pdf, 7)?, amount_appearance(AMOUNT_SIGNED));
    assert_eq!(
        stream_content(pdf, 7)?,
        "/Tx BMC BT /Helv 12 Tf 2 6 Td (100 EUR) Tj ET EMC"
    );
    assert!(object(pdf, 7)?.starts_with("<< /Type /XObject /Subtype /Form /BBox [0 0 200 20]"));
    Ok(())
}

#[test]
fn the_shadow_hide_and_replace_document_holds_an_unused_page_tree() -> TestResult {
    let files = generate();
    let pdf = &find(&files, "documents/shadow-hide-and-replace")?.contents;
    check_structure(pdf, 8)?;
    assert_eq!(object(pdf, 1)?, "<< /Type /Catalog /Pages 2 0 R >>");
    assert_eq!(object(pdf, 6)?, HIDDEN_PAGES);
    assert!(object(pdf, 7)?.contains("/Parent 6 0 R"));
    assert!(object(pdf, 7)?.contains("/Contents 8 0 R"));
    assert!(stream_content(pdf, 8)?.contains("(sigillum shadow document, shown after signing)"));
    // No object of the document in use refers to the second page tree.
    for number in 1..=5 {
        assert!(!object(pdf, number)?.contains("6 0 R"), "{number}");
        assert!(!object(pdf, number)?.contains("7 0 R"), "{number}");
    }
    Ok(())
}

#[test]
fn the_shadow_documents_have_their_own_identifiers() -> TestResult {
    let files = generate();
    let pdfs: Vec<&GeneratedFile> = files
        .iter()
        .filter(|file| file.artefact.path.extension().is_some_and(|e| e == "pdf"))
        .collect();
    assert_eq!(pdfs.len(), 5);
    let mut identifiers: Vec<String> = Vec::new();
    for file in pdfs {
        let body = text(&file.contents);
        let at = body.find("/ID [<").ok_or("no /ID")?;
        identifiers.push(body[at..at + 75].to_owned());
    }
    identifiers.sort();
    identifiers.dedup();
    assert_eq!(identifiers.len(), 5);
    Ok(())
}

#[test]
fn the_signature_field_pdf_has_an_empty_signature_field() -> TestResult {
    let files = generate();
    let pdf = &find(&files, "documents/signature-field")?.contents;
    check_structure(pdf, 6)?;
    let body = text(pdf);
    // Clause 12.7.2: the interactive form dictionary lists the field.
    assert!(body.contains("/AcroForm << /Fields [6 0 R] >>"), "{body}");
    // Clause 12.7.4.5: a signature field without a value, merged with its widget.
    assert!(
        body.contains(
            "/FT /Sig /T (Signature1) /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /F 4 /P 3 0 R"
        ),
        "{body}"
    );
    assert!(!body.contains("/V "), "{body}");
    assert!(body.contains("/Annots [6 0 R]"), "{body}");
    Ok(())
}

#[test]
fn the_pdfs_differ_in_their_identifiers() -> TestResult {
    let files = generate();
    let id = |pdf: &[u8]| -> Result<String, String> {
        let body = text(pdf);
        let at = body.find("/ID [<").ok_or("no /ID")?;
        Ok(body[at..at + 75].to_owned())
    };
    assert_ne!(
        id(&find(&files, "documents/simple")?.contents)?,
        id(&find(&files, "documents/signature-field")?.contents)?
    );
    Ok(())
}

#[test]
fn owns_every_entry_under_its_directory() {
    let mut artefact = generate().remove(0).artefact;
    assert!(generated_here(&artefact));
    artefact.id = "documentsx/simple".to_owned();
    assert!(!generated_here(&artefact));
    artefact.id = "timestamps/content".to_owned();
    assert!(!generated_here(&artefact));
}
