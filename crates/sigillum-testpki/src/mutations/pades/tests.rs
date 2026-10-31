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
    // The output is still read, through the last section of the copy, which
    // is the last section of the source.
    let read = Pdf::parse(&output)?;
    assert_eq!(read.startxref, Pdf::parse(&source)?.startxref);
    assert_eq!(read.object(3)?, Pdf::parse(&source)?.object(3)?);
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
    let rewritten = pdf.update(&[(6, one_per_line)], &[])?;
    assert!(replace_field_value(&rewritten).is_ok());
    let other = pdf.update(&[(6, documents::amount_field("100 EUX", 7))], &[])?;
    assert!(replace_field_value(&other).is_err());
    Ok(())
}

#[test]
fn trailer_entries_are_read_as_written() -> TestResult {
    assert_eq!(
        trailer_entries("<< /Size 6 /Root 1 0 R /ID [<AB> <CD>] >>\n")?,
        [("Size", "6"), ("Root", "1 0 R"), ("ID", "[<AB> <CD>]")]
    );
    assert_eq!(
        trailer_entries("<<\n/Size 10\n/Root 1 0 R\n/ID [<AB> <CD>]\n/Prev 420\n>>\n")?,
        [
            ("Size", "10"),
            ("Root", "1 0 R"),
            ("ID", "[<AB> <CD>]"),
            ("Prev", "420")
        ]
    );
    // Names end at a delimiter, and values may be hexadecimal strings.
    assert_eq!(
        trailer_entries("<</Size 6/ID[<AB> <CD>]/X <0F>/Info 12 3 R>>")?,
        [
            ("Size", "6"),
            ("ID", "[<AB> <CD>]"),
            ("X", "<0F>"),
            ("Info", "12 3 R")
        ]
    );
    assert_eq!(trailer_entries("<<>>")?, []);
    for refused in [
        "/Size 6",
        "<< Size 6 >>",
        "<< / 6 >>",
        "<< /X (text) >>",
        "<< /X true >>",
        "<< /X << /A 1 >> >>",
        "<< /X [(a)] >>",
        "<< /X [[1]] >>",
        "<< /X [<< /A 1 >>] >>",
        "<< /X [1 2 >>",
        "<< /X <AB >>",
    ] {
        assert!(trailer_entries(refused).is_err(), "{refused}");
    }
    Ok(())
}

#[test]
fn integers_are_decimal_digits_only() {
    assert_eq!(integer("0000020214"), Ok(20_214));
    assert_eq!(integer("0"), Ok(0));
    for refused in ["", "12345678901", "1a", "+1", "-1", " 1"] {
        assert!(integer(refused).is_err(), "{refused:?}");
    }
}

#[test]
fn a_keyword_line_ends_with_any_end_of_line_marker() {
    assert_eq!(line_after(b"xref\r\n0", 0, b"xref"), Ok(6));
    assert_eq!(line_after(b"xref\n0", 0, b"xref"), Ok(5));
    assert_eq!(line_after(b"xref\r0", 0, b"xref"), Ok(5));
    assert_eq!(line_after(b"..xref\n", 2, b"xref"), Ok(7));
    assert!(line_after(b"xref 0", 0, b"xref").is_err());
    assert!(line_after(b"xref", 0, b"xref").is_err());
    assert!(line_after(b"xref\n", 9, b"xref").is_err());
}

#[test]
fn a_file_of_the_limit_is_read_and_a_hybrid_file_is_refused() -> TestResult {
    let mut at_limit = vec![b' '; MAX_PDF_LEN - 6];
    at_limit.extend_from_slice(b"%%EOF\n");
    assert_eq!(at_limit.len(), MAX_PDF_LEN);
    assert_eq!(Pdf::parse(&at_limit).err(), Some(NOT_READ));
    // A trailer with /XRefStm, of a hybrid-reference file, is not read. The
    // trailer follows the section, which keeps its offset.
    let source = document(documents::SIMPLE_PDF_ID)?;
    let at = find(&source, b"/Root 1 0 R").ok_or("no /Root")?;
    let hybrid = [&source[..at], b"/XRefStm 9 ", &source[at..]].concat();
    assert_eq!(Pdf::parse(&hybrid).err(), Some(NOT_READ));
    Ok(())
}

#[test]
fn a_missing_object_is_reported_as_such() -> TestResult {
    let source = signed()?;
    let at = rfind(&source, b"/Prev 420").ok_or("no /Prev")?;
    for prev in [&b"/Prev 20373"[..], b"/Prev 20374"] {
        let looped = [&source[..at], prev, &source[at + 9..]].concat();
        assert_eq!(
            Pdf::parse(&looped)?.object(4).err(),
            Some(Unsupported("the object is not in the file"))
        );
    }
    Ok(())
}

#[test]
fn an_update_has_one_subsection_per_run_of_numbers() -> TestResult {
    let source = document(documents::SIMPLE_PDF_ID)?;
    let pdf = Pdf::parse(&source)?;
    // Objects 4 and 1 written again, and three new objects, 6 to 8.
    let output = pdf.update(
        &[(4, "<< >>".to_owned()), (1, "<< >>".to_owned())],
        &[
            "<< /A 1 >>".to_owned(),
            "<< /A 2 >>".to_owned(),
            "<< /A 3 >>".to_owned(),
        ],
    )?;
    let update = update(&source, &output)?;
    let offset = |number: u32| -> Result<String, String> {
        let header = format!("{number} 0 obj\n");
        let at = update.find(&header).ok_or("no object")? + source.len();
        Ok(format!("{at:010} 00000 n\r\n"))
    };
    let expected = format!(
        "xref\n1 1\n{}4 1\n{}6 3\n{}{}{}trailer\n",
        offset(1)?,
        offset(4)?,
        offset(6)?,
        offset(7)?,
        offset(8)?
    );
    assert!(update.contains(&expected), "{update}");
    assert_eq!(
        check_update(&output, &update, 9, pdf.startxref)?,
        [1, 4, 6, 7, 8]
    );
    assert_eq!(updated_object(&update, 8)?, "<< /A 3 >>");
    Ok(())
}

#[test]
fn only_an_entry_not_followed_by_a_digit_is_replaced() -> TestResult {
    assert_eq!(
        replace_once("/Contents 5 0 R1 /Contents 5 0 R", "/Contents 5 0 R", "X")?,
        "/Contents 5 0 R1 X"
    );
    assert_eq!(replace_once("/Pages 2 0 R", "/Pages 2 0 R", "Y")?, "Y");
    assert!(replace_once("/Pages 2 0 R /Pages 2 0 R", "/Pages 2 0 R", "Y").is_err());
    assert!(replace_once("/Pages 2 0 R0", "/Pages 2 0 R", "Y").is_err());
    Ok(())
}

/// The simple document with a signature dictionary added in an update,
/// object 6, whose `ByteRange` excludes its `Contents` of `hex` zeros and
/// ends the file, followed by `pad` spaces and then a delimiter; before
/// `Contents` when `before` holds. The integers are written without leading zeros.
fn synthetic(hex: usize, pad: usize, before: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let base = document(documents::SIMPLE_PDF_ID)?;
    let pdf = Pdf::parse(&base)?;
    let contents = format!("/Contents <{}>", "0".repeat(hex));
    let build = |range: &str| {
        let body = if before {
            format!("<< /ByteRange {range}{}{contents} >>", " ".repeat(pad))
        } else {
            format!("<< {contents} /ByteRange {range}{}>>", " ".repeat(pad))
        };
        pdf.update(&[], &[body])
    };
    // The lengths of the integers change the length of the file: find the
    // fixed point.
    let mut range = "[0 0 0 0]".to_owned();
    for _ in 0..8 {
        let file = build(&range)?;
        let a = find(&file, b"/Contents <").ok_or("no /Contents")? + 10;
        let b = a + hex + 2;
        let next = format!("[0 {a} {b} {}]", file.len() - b);
        if next == range {
            return Ok(file);
        }
        range = next;
    }
    Err("no fixed point".into())
}

#[test]
fn the_new_byte_range_must_fit_where_the_old_one_was() -> TestResult {
    // A Contents that ends the first range just below 10000, so that the
    // length of the file, the new start of the second range, has one more
    // digit than the old start.
    let probe = synthetic(9_000, 0, false)?;
    let a = find(&probe, b"/Contents <").ok_or("no /Contents")? + 10;
    let hex = 9_990 - a;
    let tight = synthetic(hex, 0, false)?;
    let [_, _, b, _] = byte_range(&tight)?;
    assert!(b < 10_000 && tight.len() >= 10_000, "{b} {}", tight.len());
    assert_eq!(
        wrap_byte_range(&tight).err(),
        Some(Unsupported(
            "the new ByteRange does not fit in the space of the old one"
        ))
    );
    // One space after the value is enough.
    let spaced = synthetic(hex, 1, false)?;
    let output = wrap_byte_range(&spaced)?;
    let length = spaced.len();
    let [_, a, b, c] = byte_range(&spaced)?;
    assert_eq!(byte_range(&output)?, [0, a, length, c]);
    let value = find(&spaced, b"/ByteRange [").ok_or("no /ByteRange")? + 11;
    let new = format!("[0 {a} {length} {c}]");
    assert_eq!(&output[value..value + new.len()], new.as_bytes());
    assert_eq!(
        &output[value + new.len()..length],
        &spaced[value + new.len()..]
    );
    assert_eq!(&output[length..], &spaced[b..]);
    // With room to spare, the value is padded with spaces to the old end.
    let roomy = synthetic(hex, 4, false)?;
    let output = wrap_byte_range(&roomy)?;
    let value = find(&roomy, b"/ByteRange [").ok_or("no /ByteRange")? + 11;
    let [_, a, _, c] = byte_range(&roomy)?;
    let new = format!("[0 {a} {} {c}]   ", roomy.len());
    assert_eq!(&output[value..value + new.len()], new.as_bytes());
    assert_eq!(
        &output[value + new.len()..roomy.len()],
        &roomy[value + new.len()..]
    );
    Ok(())
}

#[test]
fn a_byte_range_in_the_first_range_is_refused() -> TestResult {
    let after = synthetic(64, 2, false)?;
    assert!(wrap_byte_range(&after).is_ok());
    let before = synthetic(64, 2, true)?;
    assert_eq!(
        wrap_byte_range(&before).err(),
        Some(Unsupported(
            "the ranges of the ByteRange do not end the file around the signature dictionary"
        ))
    );
    Ok(())
}

/// The simple document with the cross-reference entry of object 3
/// replaced by `entry`, of 20 bytes.
fn with_entry_of_object_3(entry: &[u8; 20]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut pdf = document(documents::SIMPLE_PDF_ID)?;
    let xref = rfind(&pdf, b"xref\n0 6\n").ok_or("no xref")? + 9;
    let at = xref + 3 * 20;
    assert!(pdf[at..at + 20].ends_with(b" 00000 n\r\n"));
    pdf[at..at + 20].copy_from_slice(entry);
    Ok(pdf)
}

/// Issue #112: a malformed entry, with a character of two bytes across the
/// fields, is refused without a panic.
#[test]
fn a_malformed_cross_reference_entry_is_refused() -> TestResult {
    let mut multibyte = *b"000000000xx00000 n\r\n";
    multibyte[9..11].copy_from_slice("\u{e9}".as_bytes());
    for (name, entry) in [
        ("a character of two bytes", multibyte),
        ("a letter in the offset", *b"00000000a9 00000 n\r\n"),
        ("a letter in the generation", *b"0000000009 0000a n\r\n"),
        ("no space after the offset", *b"0000000009000000 n\r\n"),
        ("no space before the type", *b"0000000009 000000n\r\n"),
    ] {
        let pdf = with_entry_of_object_3(&entry)?;
        let parsed = Pdf::parse(&pdf)?;
        assert_eq!(parsed.object(3).err(), Some(NOT_READ), "{name}");
        assert!(add_page_content(&pdf).is_err(), "{name}");
    }
    // An entry of another generation is refused, as offset reads generation 0.
    let pdf = with_entry_of_object_3(b"0000000009 00001 n\r\n")?;
    assert_eq!(
        Pdf::parse(&pdf)?.object(3).err(),
        Some(Unsupported("the object is not of generation 0"))
    );
    let free = with_entry_of_object_3(b"0000000009 00000 f\r\n")?;
    assert_eq!(
        Pdf::parse(&free)?.object(3).err(),
        Some(Unsupported("the object is not in use"))
    );
    Ok(())
}

/// Issue #112: the end of the entries of a subsection is computed without
/// overflow, and a count beyond the file is refused.
#[test]
fn a_subsection_longer_than_the_file_is_refused() -> TestResult {
    assert_eq!(subsection_end(10, 2), Some(50));
    assert_eq!(subsection_end(usize::MAX - 10, 1), None);
    assert_eq!(subsection_end(0, usize::MAX / 20 + 1), None);
    let source = document(documents::SIMPLE_PDF_ID)?;
    let at = rfind(&source, b"xref\n0 6\n").ok_or("no xref")? + 5;
    let long = [&source[..at], b"0 999999999", &source[at + 3..]].concat();
    let parsed = Pdf::parse(&long);
    assert!(parsed.is_err());
    Ok(())
}

/// The simple document with its trailer giving `/Size size`.
fn with_size(id: &str, size: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let source = document(id)?;
    let at = rfind(&source, b"/Size ").ok_or("no /Size")?;
    let end = at
        + 6
        + source[at + 6..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .count();
    Ok([
        &source[..at],
        format!("/Size {size}").as_bytes(),
        &source[end..],
    ]
    .concat())
}

/// Issue #112: /Size is at most one more than the largest number of
/// indirect objects of ISO 32000-1:2008, Annex C, Table C.1, and a new
/// object never takes a number past it.
#[test]
fn the_size_is_bounded_by_the_limit_on_indirect_objects() -> TestResult {
    assert_eq!(MAX_SIZE, 8_388_608);
    assert!(Pdf::parse(&with_size(documents::SIMPLE_PDF_ID, 8_388_608)?).is_ok());
    for size in [8_388_609, u32::MAX] {
        assert!(
            Pdf::parse(&with_size(documents::SIMPLE_PDF_ID, size)?).is_err(),
            "{size}"
        );
    }
    // One new object fits under the limit, and none past it.
    let last = add_page_content(&with_size(documents::SIMPLE_PDF_ID, 8_388_607)?)?;
    assert!(last.ends_with(b"%%EOF\n"));
    assert!(text(&last).contains("/Contents [5 0 R 8388607 0 R]"));
    assert!(text(&last).contains("/Size 8388608"));
    assert_eq!(
        add_page_content(&with_size(documents::SIMPLE_PDF_ID, 8_388_608)?).err(),
        Some(Unsupported("the update needs more objects than the limit"))
    );
    // A mutation that adds no object works at the limit.
    assert!(remove_overlay(&with_size(documents::SHADOW_HIDE_PDF_ID, 8_388_608)?).is_ok());
    Ok(())
}

/// Issue #112: an object read or written again must be below /Size, so that
/// a new object, which takes the number /Size, never takes the number of
/// another.
#[test]
fn objects_at_or_past_the_size_are_refused() -> TestResult {
    // With /Size 3, the page, object 3, is past the last object.
    let small = with_size(documents::SIMPLE_PDF_ID, 3)?;
    assert_eq!(
        Pdf::parse(&small)?.object(3).err(),
        Some(Unsupported("the object number is not below /Size"))
    );
    assert!(add_page_content(&small).is_err());
    // With /Size 6, object 6 of the replace document is past the last object.
    let six = with_size(documents::SHADOW_REPLACE_PDF_ID, 6)?;
    assert!(replace_field_value(&six).is_err());
    let six = with_size(documents::SHADOW_HIDE_PDF_ID, 6)?;
    assert!(remove_overlay(&six).is_err());
    let six = with_size(documents::SHADOW_HIDE_AND_REPLACE_PDF_ID, 6)?;
    assert!(switch_page_tree(&six).is_err());
    // An update refuses to write an object at or past /Size again, or one
    // object twice.
    let source = document(documents::SIMPLE_PDF_ID)?;
    let pdf = Pdf::parse(&source)?;
    assert_eq!(
        pdf.update(&[(6, String::new())], &[]).err(),
        Some(Unsupported("the object number is not below /Size"))
    );
    assert_eq!(
        pdf.update(&[(3, String::new()), (3, String::new())], &[])
            .err(),
        Some(Unsupported("the update writes an object twice"))
    );
    Ok(())
}
