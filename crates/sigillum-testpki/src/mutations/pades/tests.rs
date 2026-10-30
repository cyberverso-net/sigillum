use std::path::PathBuf;

use super::*;
use crate::documents;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata")
}

/// The committed PAdES signature at B-B by pki/signer-p256.
fn signed() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(std::fs::read(testdata().join("signed/pades-b-b-p256.pdf"))?)
}

/// A base document of the corpus, by identifier.
fn document(id: &str) -> Result<Vec<u8>, String> {
    documents::generate()
        .into_iter()
        .find(|file| file.artefact.id == id)
        .map(|file| file.contents)
        .ok_or_else(|| format!("{id} is not generated"))
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The update appended to `source`, as text, after checking that the
/// output keeps every byte of `source` (ISO 32000-1:2008, clause 7.5.6).
fn update(source: &[u8], output: &[u8]) -> Result<String, String> {
    if !output.starts_with(source) {
        return Err("the source is not kept intact".to_owned());
    }
    Ok(text(&output[source.len()..]))
}

/// Checks the structure of an update read on its own, without the reader
/// under test: each object at the offset of its cross-reference entry, the
/// trailer with `/Size`, the entries of the previous trailer and `/Prev`,
/// and `startxref` at the cross-reference section. Returns the object
/// numbers of the update in the order of its cross-reference section.
fn check_update(output: &[u8], update: &str, size: u32, prev: usize) -> Result<Vec<u32>, String> {
    let base = output.len() - update.len();
    let xref = update.rfind("\nxref\n").ok_or("no xref")? + 1;
    let trailer = update.find("trailer\n").ok_or("no trailer")?;
    let mut numbers = Vec::new();
    // Split at line feeds only: each entry ends with a carriage return and a line feed.
    let mut lines = update[xref + 5..trailer].split_terminator('\n');
    while let Some(header) = lines.next() {
        let mut parts = header.split(' ');
        let first: u32 = parts
            .next()
            .ok_or("no first")?
            .parse()
            .map_err(|_| header.to_owned())?;
        let count: u32 = parts
            .next()
            .ok_or("no count")?
            .parse()
            .map_err(|_| header.to_owned())?;
        for number in first..first + count {
            let entry = lines.next().ok_or("no entry")?;
            if !entry.ends_with(" 00000 n\r") {
                return Err(format!("entry {entry:?}"));
            }
            let offset: usize = entry[..10].parse().map_err(|_| entry.to_owned())?;
            let expected = format!("{number} 0 obj\n");
            if !output[offset..].starts_with(expected.as_bytes()) || offset < base {
                return Err(format!("object {number} at {offset}"));
            }
            numbers.push(number);
        }
    }
    let tail = &update[trailer..];
    let expected_tail = format!(
        "trailer\n<< /Size {size} {} /Prev {prev} >>\nstartxref\n{}\n%%EOF\n",
        "/Root 1 0 R /ID",
        base + xref
    );
    let id_start = tail.find("/ID ").ok_or("no /ID")?;
    let id_end = tail[id_start..].find(']').ok_or("no ]")? + id_start + 1;
    let without_id = format!("{}/ID{}", &tail[..id_start], &tail[id_end..]);
    if without_id != expected_tail {
        return Err(format!("{tail:?}"));
    }
    Ok(numbers)
}

/// The object `number` of the update, without its `obj` and `endobj` lines.
fn updated_object(update: &str, number: u32) -> Result<String, String> {
    let header = format!("{number} 0 obj\n");
    let start = update.find(&header).ok_or(format!("no object {number}"))? + header.len();
    let end = start + update[start..].find("\nendobj\n").ok_or("no endobj")?;
    Ok(update[start..end].to_owned())
}

/// The /ID entry of the last trailer of `pdf`, as written.
fn last_id(pdf: &[u8]) -> Result<String, String> {
    let body = text(pdf);
    let trailer = body.rfind("trailer").ok_or("no trailer")?;
    let start = trailer + body[trailer..].find("/ID [").ok_or("no /ID")?;
    let end = start + body[start..].find(']').ok_or("no ]")? + 1;
    Ok(body[start..end].to_owned())
}

#[test]
fn the_reader_finds_the_latest_copy_of_each_object() -> TestResult {
    let source = signed()?;
    let pdf = Pdf::parse(&source)?;
    // The signature dictionary of DSS ends the file with Size 10.
    assert_eq!(pdf.size, 10);
    assert_eq!(pdf.startxref, 20_373);
    // Object 3, the page, was written again by the update of DSS, and
    // object 4, the font, only in the first revision.
    let page = text(pdf.object(3)?);
    assert!(page.contains("/Annots [6 0 R]"), "{page}");
    assert_eq!(
        text(pdf.object(4)?),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
    );
    assert!(text(pdf.object(1)?).contains("/AcroForm"));
    assert!(pdf.object(10).is_err());
    assert!(pdf.object(0).is_err());
    Ok(())
}

#[test]
fn an_incremental_update_adds_content_to_the_signed_page() -> TestResult {
    let source = signed()?;
    let output = add_page_content(&source)?;
    let update = update(&source, &output)?;
    let numbers = check_update(&output, &update, 11, 20_373)?;
    assert_eq!(numbers, [3, 10]);
    let page = updated_object(&update, 3)?;
    assert!(page.contains("/Contents [5 0 R 10 0 R]"), "{page}");
    // The rest of the page written by DSS is kept, with its signature widget.
    assert!(page.contains("/Annots [6 0 R]"), "{page}");
    let pdf = Pdf::parse(&source)?;
    assert_eq!(
        page.replace("/Contents [5 0 R 10 0 R]", "/Contents 5 0 R"),
        text(pdf.object(3)?)
    );
    assert_eq!(
        updated_object(&update, 10)?,
        documents::stream("", ADDED_CONTENT)
    );
    assert!(ADDED_CONTENT.contains("(text added after signing)"));
    assert_eq!(last_id(&output)?, last_id(&source)?);
    assert_eq!(add_page_content(&source)?, output);
    // The page of the output no longer holds the single content stream.
    assert!(add_page_content(&output).is_err());
    Ok(())
}

#[test]
fn the_hide_variant_empties_the_overlay() -> TestResult {
    let source = document(documents::SHADOW_HIDE_PDF_ID)?;
    let output = remove_overlay(&source)?;
    let update = update(&source, &output)?;
    let start = text(&source);
    let prev: usize = start[start.rfind("startxref\n").ok_or("no startxref")? + 10..]
        .trim_end_matches("\n%%EOF\n")
        .parse()?;
    assert_eq!(check_update(&output, &update, 7, prev)?, [6]);
    assert_eq!(
        updated_object(&update, 6)?,
        "<< /Length 0 >>\nstream\n\nendstream"
    );
    assert_eq!(remove_overlay(&source)?, output);
    assert!(remove_overlay(&output).is_err());
    Ok(())
}

#[test]
fn the_replace_variant_changes_the_value_and_appearance_of_the_field() -> TestResult {
    let source = document(documents::SHADOW_REPLACE_PDF_ID)?;
    let output = replace_field_value(&source)?;
    let update = update(&source, &output)?;
    let start = text(&source);
    let prev: usize = start[start.rfind("startxref\n").ok_or("no startxref")? + 10..]
        .trim_end_matches("\n%%EOF\n")
        .parse()?;
    assert_eq!(check_update(&output, &update, 9, prev)?, [6, 8]);
    assert_eq!(
        updated_object(&update, 6)?,
        documents::amount_field(AMOUNT_REPLACED, 8)
    );
    assert_eq!(
        updated_object(&update, 8)?,
        documents::amount_appearance(AMOUNT_REPLACED)
    );
    assert_eq!(AMOUNT_REPLACED, "900 EUR");
    assert_eq!(replace_field_value(&source)?, output);
    assert!(replace_field_value(&output).is_err());
    Ok(())
}

#[test]
fn the_hide_and_replace_variant_switches_to_the_prepared_page_tree() -> TestResult {
    let source = document(documents::SHADOW_HIDE_AND_REPLACE_PDF_ID)?;
    let output = switch_page_tree(&source)?;
    let update = update(&source, &output)?;
    let start = text(&source);
    let prev: usize = start[start.rfind("startxref\n").ok_or("no startxref")? + 10..]
        .trim_end_matches("\n%%EOF\n")
        .parse()?;
    assert_eq!(check_update(&output, &update, 9, prev)?, [1]);
    assert_eq!(
        updated_object(&update, 1)?,
        "<< /Type /Catalog /Pages 6 0 R >>"
    );
    assert_eq!(switch_page_tree(&source)?, output);
    assert!(switch_page_tree(&output).is_err());
    Ok(())
}

/// The four integers of the first `/ByteRange` of `pdf`, the one in use:
/// the copy appended by the wrapping holds the old one again.
fn byte_range(pdf: &[u8]) -> Result<[usize; 4], Box<dyn std::error::Error>> {
    let start = find(pdf, b"/ByteRange [").ok_or("no /ByteRange")? + 12;
    let end = start + find(&pdf[start..], b"]").ok_or("no ]")?;
    let values: Vec<usize> = std::str::from_utf8(&pdf[start..end])?
        .split(' ')
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    Ok(values.try_into().map_err(|_| "not four integers")?)
}

#[test]
fn the_wrapped_byte_range_skips_the_live_signature_dictionary() -> TestResult {
    let source = signed()?;
    let [_, a, b, c] = byte_range(&source)?;
    assert_eq!(b + c, source.len());
    let output = wrap_byte_range(&source)?;
    let length = source.len();
    // The live file keeps its length, and a copy of the second signed range
    // follows it.
    assert_eq!(output.len(), length + c);
    assert_eq!(&output[length..], &source[b..]);
    assert_eq!(byte_range(&output)?, [0, a, length, c]);
    // The bytes that the new ByteRange covers are the bytes that were signed.
    let signed_bytes = [&source[..a], &source[b..]].concat();
    let covered = [&output[..a], &output[length..length + c]].concat();
    assert_eq!(covered, signed_bytes);
    // Outside the ByteRange value, the live file is the source.
    let differing: Vec<usize> = (0..length).filter(|&i| output[i] != source[i]).collect();
    let value = find(&source, b"/ByteRange [").ok_or("no /ByteRange")? + 11;
    assert!(!differing.is_empty());
    assert!(
        differing.iter().all(|&i| (value..value + 40).contains(&i)),
        "{differing:?}"
    );
    // The gap between the two ranges holds more than the Contents string.
    assert!(length - a > b - a);
    assert_eq!(wrap_byte_range(&source)?, output);
    // The output's ByteRange no longer ends the file at its second range of
    // the source, so the mutation does not apply twice.
    assert!(wrap_byte_range(&output).is_err());
    Ok(())
}

#[test]
fn a_byte_range_that_is_not_of_one_signature_ending_the_file_is_refused() -> TestResult {
    let source = signed()?;
    let at = find(&source, b"/ByteRange [0 932 19878 827]").ok_or("no /ByteRange")?;
    let with = |value: &str| -> Vec<u8> {
        let mut out = source.clone();
        out[at..at + value.len()].copy_from_slice(value.as_bytes());
        out
    };
    for (name, input) in [
        ("does not start at 0", with("/ByteRange [1 932 19878 827]")),
        (
            "does not end the file",
            with("/ByteRange [0 932 19878 826]"),
        ),
        ("ranges overlap", with("/ByteRange [0 932 00932 827]")),
        ("not integers", with("/ByteRange [0 932 19878 82x]")),
        ("three integers", with("/ByteRange [0 932 19878]   ")),
        ("not a range", with("/ByteRangf [0 932 19878 827]")),
    ] {
        assert!(wrap_byte_range(&input).is_err(), "{name}");
    }
    let mut twice = source.clone();
    twice.extend_from_slice(b"/ByteRange [0 932 19878 827]");
    assert!(wrap_byte_range(&twice).is_err());
    // The gap must be the Contents string, between < and >.
    let mut gap = source.clone();
    gap[932] = b'(';
    assert!(wrap_byte_range(&gap).is_err());
    Ok(())
}

#[test]
fn files_that_are_not_of_the_expected_structure_are_refused() -> TestResult {
    let source = signed()?;
    let mut no_eof = source.clone();
    no_eof.truncate(source.len() - 1);
    let mut far = source.clone();
    let at = rfind(&far, b"startxref\n20373").ok_or("no startxref")? + 10;
    far[at..at + 5].copy_from_slice(b"99999");
    let mut not_xref = source.clone();
    not_xref[at..at + 5].copy_from_slice(b"20372");
    let cases: [(&str, Vec<u8>); 5] = [
        ("empty", Vec::new()),
        ("no end-of-file marker", no_eof),
        ("startxref past the end", far),
        ("startxref not at a section", not_xref),
        ("text", b"startxref\n0\n%%EOF\n".to_vec()),
    ];
    for (name, input) in cases {
        assert!(Pdf::parse(&input).is_err(), "{name}");
        for mutate in MUTATIONS {
            assert!(mutate(&input).is_err(), "{name}");
        }
    }
    Ok(())
}

#[test]
fn a_previous_section_must_come_earlier_in_the_file() -> TestResult {
    let source = signed()?;
    // The update of DSS points back to the first section at 420. One that
    // points at itself would loop; the trailer follows the section, so the
    // section keeps its offset.
    let at = rfind(&source, b"/Prev 420").ok_or("no /Prev")?;
    let cycle = [&source[..at], b"/Prev 20373", &source[at + 9..]].concat();
    let pdf = Pdf::parse(&cycle)?;
    assert!(pdf.object(3).is_ok());
    assert!(pdf.object(4).is_err());
    // One that points at a later offset is refused in the same way.
    let later = [&source[..at], b"/Prev 20374", &source[at + 9..]].concat();
    assert!(Pdf::parse(&later)?.object(4).is_err());
    // And the earlier section is still read when it is where /Prev says.
    assert!(Pdf::parse(&source)?.object(4).is_ok());
    Ok(())
}

#[test]
fn each_mutation_needs_its_prepared_object() -> TestResult {
    // The simple document has no overlay, no field and no second page tree.
    let simple = document(documents::SIMPLE_PDF_ID)?;
    assert!(remove_overlay(&simple).is_err());
    assert!(replace_field_value(&simple).is_err());
    assert!(switch_page_tree(&simple).is_err());
    assert!(wrap_byte_range(&simple).is_err());
    // The base documents of the shadow attacks are not signed.
    for id in [
        documents::SHADOW_HIDE_PDF_ID,
        documents::SHADOW_REPLACE_PDF_ID,
        documents::SHADOW_HIDE_AND_REPLACE_PDF_ID,
    ] {
        assert!(wrap_byte_range(&document(id)?).is_err(), "{id}");
    }
    // The page of the hide document holds two content streams.
    assert!(add_page_content(&document(documents::SHADOW_HIDE_PDF_ID)?).is_err());
    Ok(())
}

#[test]
fn inputs_are_read_up_to_the_limit() {
    let mut over = vec![b' '; MAX_PDF_LEN + 1];
    over.extend_from_slice(b"%%EOF\n");
    assert!(matches!(Pdf::parse(&over), Err(Unsupported(message)) if message.contains("4 MiB")));
    for mutate in MUTATIONS {
        assert!(mutate(&over).is_err());
    }
}

/// A mutation of this module.
type Mutate = fn(&[u8]) -> Result<Vec<u8>, Unsupported>;

/// The five mutations of this module.
const MUTATIONS: [Mutate; 5] = [
    add_page_content,
    remove_overlay,
    replace_field_value,
    switch_page_tree,
    wrap_byte_range,
];

#[test]
fn prepared_objects_compare_with_white_space_collapsed() -> TestResult {
    assert_eq!(
        collapsed("<<\n/FT /Tx\n/V (100 EUR)\r\n>>\n"),
        "<< /FT /Tx /V (100 EUR) >>"
    );
    assert_eq!(collapsed("  a\t\x0c b  "), "a b");
    assert_eq!(collapsed(""), "");
    // The field as DSS writes it again, one entry per line, is the field
    // as signed; another value is not.
    let source = document(documents::SHADOW_REPLACE_PDF_ID)?;
    let pdf = Pdf::parse(&source)?;
    let field = documents::amount_field(documents::AMOUNT_SIGNED, 7);
    let one_per_line = field
        .replace(" /", "\n/")
        .replace("<< ", "<<\n")
        .replace(" >>", "\n>>");
    let rewritten = pdf.update(&[(6, one_per_line)]);
    assert!(replace_field_value(&rewritten).is_ok());
    let other = pdf.update(&[(6, documents::amount_field("100 EUX", 7))]);
    assert!(replace_field_value(&other).is_err());
    Ok(())
}
