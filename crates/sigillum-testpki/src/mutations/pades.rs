//! The PAdES variants of `generate mutations`: the attacks on PDF
//! signatures of threats D1 to D3 of the threat model, applied to PAdES
//! signatures that DSS created.
//!
//! Four variants append an incremental update to the signed file (ISO
//! 32000-1:2008, clause 7.5.6), which leaves every signed byte intact: the
//! incremental saving attack of *1 Trillion Dollar Refund: How To Spoof
//! PDF Signatures* (ACM CCS 2019), and one shadow attack of each class of
//! *Shadow Attacks: Hiding and Replacing Content in Signed PDFs* (NDSS
//! 2021), whose content [`crate::documents`] prepares before signing. The
//! fifth moves the second range of the `ByteRange` of the signature, the
//! signature wrapping attack of the CCS 2019 paper. No signature value is
//! computed again.
//!
//! The files are read by a scan of their cross-reference tables (clause
//! 7.5.4), not by a PDF library: the sources are the committed corpus,
//! whose digests [`super::generate`] checks first, written by
//! [`crate::documents`] and by DSS with cross-reference tables, not
//! streams. Every function refuses a file of another structure.

use super::Unsupported;
use crate::documents;

/// The largest PDF file that the PAdES mutations read, in bytes. The
/// PAdES signatures of the corpus are a few tens of kilobytes long.
pub const MAX_PDF_LEN: usize = 4 * 1024 * 1024;

/// The largest `/Size`: one more than the largest number of indirect
/// objects, 8,388,607, of ISO 32000-1:2008, Annex C, clause C.2, Table C.1,
/// within which conforming writers should remain. It keeps every object
/// number, and `/Size` itself, far from the limit of `u32`.
pub(crate) const MAX_SIZE: u32 = 8_388_608;

/// The most cross-reference sections that are followed through `/Prev`.
const MAX_SECTIONS: usize = 64;

/// The content stream that the incremental update adds to the page.
pub(crate) const ADDED_CONTENT: &str = "BT /F1 12 Tf 72 740 Td (text added after signing) Tj ET";

/// The value of the text field of the replace variant after signing.
pub(crate) const AMOUNT_REPLACED: &str = "900 EUR";

/// The notes of the incremental update.
pub(crate) const INCREMENTAL_UPDATE_NOTES: &str = "An incremental update (ISO 32000-1:2008, clause 7.5.6) appended after the signed revision adds a content stream, object 10, which draws the text added after signing, and writes the page, object 3, again with it in its Contents. The signature and its ByteRange cover the signed revision, which is intact. The variant follows the incremental saving attack of 1 Trillion Dollar Refund (ACM CCS 2019), threat D1 of the threat model. DSS 6.5.1 gives TOTAL-PASSED in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only, and reports the change after signing as the warnings BBB_FC_IVDBSFR_ANS, a visual difference on page 1, and BBB_FC_DSCNUOM_ANS, undefined object modifications after the signature revision; the aligned policy is not changed for it. The result that sigillum gives for the change after signing is decided by the phase 2 ADR on revision analysis (ADR-0015): TOTAL-FAILED, or TOTAL-PASSED for the signed revision with a conformance finding for the change (ADR-0017, rule 4). The difference from DSS is the provisional divergence DIV-7 of docs/design/divergences.md, withdrawn under the second option.";

/// The notes of the shadow attack of the hide class.
pub(crate) const SHADOW_HIDE_NOTES: &str = "The signed document, documents/shadow-hide, draws a second line of text, shadow content, covered when signed, and then a white rectangle over it, object 6, a content stream of its own. An incremental update (ISO 32000-1:2008, clause 7.5.6) appended after the signed revision writes object 6 again as an empty stream, which shows the line. The variant follows the hide class of the shadow attacks of Shadow Attacks: Hiding and Replacing Content in Signed PDFs (NDSS 2021), threat D2 of the threat model. The DSS result is a prediction: the signature and its ByteRange cover the signed revision, which is intact, clause 7.5.6 lets a signed file be updated, and ETSI EN 319 102-1 V1.4.1 sets no check of the changes in later revisions, so the signature validates as its source does. DSS 6.5.1 gives this result in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only, with the warnings BBB_FC_IVDBSFR_ANS, a visual difference on page 1, and BBB_FC_DSCNUOM_ANS, undefined object modifications after the signature revision. The result that sigillum gives for the change after signing is decided by the phase 2 ADR on revision analysis (ADR-0015), as for the incremental update: the provisional divergence DIV-7 of docs/design/divergences.md covers this variant.";

/// The notes of the shadow attack of the replace class.
pub(crate) const SHADOW_REPLACE_NOTES: &str = "The signed document, documents/shadow-replace, holds a text field, Amount, object 6, with the value 100 EUR and an appearance that shows it, object 7. An incremental update (ISO 32000-1:2008, clause 7.5.6) appended after the signed revision writes object 6 again with the value 900 EUR and a new appearance that shows it. The variant follows the replace class of the shadow attacks of Shadow Attacks: Hiding and Replacing Content in Signed PDFs (NDSS 2021), threat D2 of the threat model. The DSS result is a prediction: the signature and its ByteRange cover the signed revision, which is intact, clause 7.5.6 lets a signed file be updated, and ETSI EN 319 102-1 V1.4.1 sets no check of the changes in later revisions, so the signature validates as its source does. DSS 6.5.1 gives this result in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only, with the warning BBB_FC_IVDBSFR_ANS, a visual difference on page 1. The result that sigillum gives for the change after signing is decided by the phase 2 ADR on revision analysis (ADR-0015), as for the incremental update: the provisional divergence DIV-7 of docs/design/divergences.md covers this variant.";

/// The notes of the shadow attack of the hide-and-replace class.
pub(crate) const SHADOW_HIDE_AND_REPLACE_NOTES: &str = "The signed document, documents/shadow-hide-and-replace, holds a second page tree, object 6, with a page of other text, which no object in use refers to. An incremental update (ISO 32000-1:2008, clause 7.5.6) appended after the signed revision writes the catalog, object 1, again with that page tree as its Pages, and adds no other object: the content shown after signing was signed. The variant follows the hide-and-replace class of the shadow attacks of Shadow Attacks: Hiding and Replacing Content in Signed PDFs (NDSS 2021), threat D2 of the threat model. The DSS result is a prediction: the signature and its ByteRange cover the signed revision, which is intact, clause 7.5.6 lets a signed file be updated, and ETSI EN 319 102-1 V1.4.1 sets no check of the changes in later revisions, so the signature validates as its source does. DSS 6.5.1 gives this result in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only, with the warnings BBB_FC_IVDBSFR_ANS, a visual difference on page 1, and BBB_FC_DSCNUOM_ANS, undefined object modifications after the signature revision. The result that sigillum gives for the change after signing is decided by the phase 2 ADR on revision analysis (ADR-0015), as for the incremental update: the provisional divergence DIV-7 of docs/design/divergences.md covers this variant.";

/// The notes of the partial `ByteRange`.
pub(crate) const PARTIAL_BYTE_RANGE_NOTES: &str = "The second range of the ByteRange of the signature dictionary starts at the end of the source file, where a copy of the second signed range of the source is appended: the bytes that the ByteRange covers are those that were signed, and their SHA-256 digest is the value of the message-digest attribute. The ByteRange no longer covers the signature dictionary in use, nor the rest of the signed revision after the Contents string, and the digits of the value of the ByteRange are the only bytes changed in the file before the copy. The variant follows the signature wrapping attack of 1 Trillion Dollar Refund (ACM CCS 2019), threat D3 of the threat model. The bytes between the two ranges are no longer the Contents string of the signature dictionary in use, so the ByteRange no longer marks out the signed data of that dictionary, and the signature cannot be processed as its base format defines it: ISO 32000-1:2008, clause 12.8.1, Table 252, has the ByteRange describe the exact byte range for the digest calculation, which excludes the Contents entry, and recommends that it cover the entire file. ETSI EN 319 142-1 V1.2.1, clause 6.3, item k), requires the ByteRange to cover the entire file, including the Signature Dictionary but excluding the entry with key Contents, but that is a requirement of the baseline profile, and ETSI EN 319 102-1 V1.4.1, clause 5.2.2.1, NOTE, leaves conformance to a profile out of the format checking. The DSS result is therefore a prediction that rests on the reading of DSS for its base format: the format checking (clause 5.2.2) fails and the validation process for basic signatures returns FAILED with FORMAT_FAILURE (clause 5.3.4, step 1), reported as TOTAL-FAILED with FORMAT_FAILURE (clause 5.1.3, Table 6). DSS 6.5.1 gives this result in the validate-document mode of tools/dss-oracle under the aligned policy (ADR-0023), with the linked files only, with the errors BBB_FC_IBRV_ANS, the ByteRange is not consistent, and BBB_CV_IRDOI_ANS, the reference data object is not intact. DSS reads the bytes between the two ranges as the hexadecimal value of Contents; they differ from it here, so DSS marks the ByteRange not valid in its diagnostic data and validates the signature over an empty signed content instead, whose digest does not match the message-digest attribute: its diagnostic data gives that digest matcher as found but not intact, and the signature as not intact.";

/// A PDF file of the corpus, read through its last cross-reference
/// section and the sections that `/Prev` leads to.
pub(crate) struct Pdf<'a> {
    /// The whole file.
    pub(crate) bytes: &'a [u8],
    /// The offset of the last cross-reference section.
    pub(crate) startxref: usize,
    /// `/Size` of the last trailer.
    pub(crate) size: u32,
    /// The entries of the last trailer other than `/Size` and `/Prev`, as
    /// written, in their order.
    entries: Vec<(&'a str, &'a str)>,
}

/// The reason given for a file that is not of the structure read here.
const NOT_READ: Unsupported =
    Unsupported("the file is not a PDF with cross-reference tables of the form read here");

/// Parses a non-negative decimal integer of at most ten digits.
fn integer(text: &str) -> Result<usize, Unsupported> {
    if text.is_empty() || text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(NOT_READ);
    }
    text.parse().map_err(|_| NOT_READ)
}

/// Reports whether `byte` is white space (ISO 32000-1:2008, clause 7.2.2,
/// Table 1).
fn is_white(byte: u8) -> bool {
    matches!(byte, 0 | b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// Reports whether `byte` is a delimiter (clause 7.2.2, Table 2).
fn is_delimiter(byte: u8) -> bool {
    matches!(
        byte,
        b'(' | b')' | b'<' | b'>' | b'[' | b']' | b'{' | b'}' | b'/' | b'%'
    )
}

/// The most entries that a trailer dictionary may hold. The trailers of the
/// corpus hold four at most.
pub(crate) const MAX_TRAILER_ENTRIES: usize = 32;

/// The entries of a trailer dictionary, from `<<` to `>>`: names with
/// values that are integers, indirect references, hexadecimal strings or
/// arrays without nested arrays, dictionaries or literal strings, as the
/// trailers of the corpus hold, and at most [`MAX_TRAILER_ENTRIES`] of
/// them. The text is read once, from left to right, with the white space
/// of ISO 32000-1:2008, clause 7.2.2, Table 1: an indirect reference is
/// read token by token, and no step looks past the token it reads.
fn trailer_entries(text: &str) -> Result<Vec<(&str, &str)>, Unsupported> {
    let inner = text
        .trim_matches(|c: char| c.is_ascii() && is_white(c as u8))
        .strip_prefix("<<")
        .and_then(|t| t.strip_suffix(">>"))
        .ok_or(NOT_READ)?;
    let bytes = inner.as_bytes();
    let mut entries = Vec::new();
    let mut at = 0;
    let skip = |mut at: usize| {
        while bytes.get(at).is_some_and(|&b| is_white(b)) {
            at += 1;
        }
        at
    };
    let digits = |mut at: usize| {
        while bytes.get(at).is_some_and(u8::is_ascii_digit) {
            at += 1;
        }
        at
    };
    loop {
        at = skip(at);
        if at == bytes.len() {
            return Ok(entries);
        }
        if entries.len() == MAX_TRAILER_ENTRIES {
            return Err(Unsupported("the trailer has more entries than the limit"));
        }
        if bytes[at] != b'/' {
            return Err(NOT_READ);
        }
        let name_start = at + 1;
        at = name_start;
        while bytes
            .get(at)
            .is_some_and(|&b| !is_white(b) && !is_delimiter(b))
        {
            at += 1;
        }
        let name = &inner[name_start..at];
        at = skip(at);
        let value_start = at;
        match bytes.get(at) {
            Some(b'[') => {
                let end = inner[at..].find(']').ok_or(NOT_READ)? + at;
                if inner[at + 1..end].contains(['[', '(', ')']) || inner[at + 1..end].contains("<<")
                {
                    return Err(NOT_READ);
                }
                at = end + 1;
            }
            Some(b'<') if bytes.get(at + 1) != Some(&b'<') => {
                at = inner[at..].find('>').ok_or(NOT_READ)? + at + 1;
            }
            Some(byte) if byte.is_ascii_digit() => {
                // An integer, or an indirect reference (clause 7.3.10): two
                // integers and R, separated by white space, R followed by
                // white space, a delimiter or the end.
                let first_end = digits(at);
                let second = skip(first_end);
                let second_end = digits(second);
                let r = skip(second_end);
                let reference = second > first_end
                    && second_end > second
                    && r > second_end
                    && bytes.get(r) == Some(&b'R')
                    && bytes
                        .get(r + 1)
                        .is_none_or(|&b| is_white(b) || is_delimiter(b))
                    && integer(&inner[at..first_end]).is_ok()
                    && integer(&inner[second..second_end]).is_ok();
                at = if reference { r + 1 } else { first_end };
            }
            _ => return Err(NOT_READ),
        }
        if name.is_empty() {
            return Err(NOT_READ);
        }
        entries.push((name, &inner[value_start..at]));
    }
}

/// One cross-reference section and its trailer (clauses 7.5.4 and 7.5.5).
struct Section<'a> {
    /// The subsections: the first object number, and the 20-byte entries.
    subsections: Vec<(usize, &'a [u8])>,
    /// The trailer dictionary, as written.
    trailer: &'a str,
}

impl<'a> Section<'a> {
    /// Reads the section at `offset`.
    fn read(bytes: &'a [u8], offset: usize) -> Result<Self, Unsupported> {
        let rest = bytes.get(offset..).ok_or(NOT_READ)?;
        let mut at = line_after(rest, 0, b"xref")?;
        let mut subsections = Vec::new();
        loop {
            let end = rest[at..]
                .iter()
                .position(|&b| b == b'\n')
                .ok_or(NOT_READ)?
                + at;
            let line = std::str::from_utf8(&rest[at..end])
                .map_err(|_| NOT_READ)?
                .trim_end_matches('\r');
            if line == "trailer" {
                let body = &rest[end + 1..];
                let close = find(body, b"startxref").ok_or(NOT_READ)?;
                let trailer = std::str::from_utf8(&body[..close]).map_err(|_| NOT_READ)?;
                return Ok(Self {
                    subsections,
                    trailer,
                });
            }
            let mut words = line.split(' ');
            let (Some(first), Some(count), None) = (words.next(), words.next(), words.next())
            else {
                return Err(NOT_READ);
            };
            let (first, count) = (integer(first)?, integer(count)?);
            let start = end + 1;
            let stop = subsection_end(start, count).ok_or(NOT_READ)?;
            let entries = rest.get(start..stop).ok_or(NOT_READ)?;
            subsections.push((first, entries));
            at = stop;
        }
    }

    /// The offset of the object `number` if this section gives it in use,
    /// or `Err` if it gives it free, or `None` if it does not list it.
    fn find(&self, number: usize) -> Option<Result<usize, Unsupported>> {
        for &(first, entries) in &self.subsections {
            let listed = number
                .checked_sub(first)
                .filter(|index| *index < entries.len() / 20);
            let Some(index) = listed else {
                continue;
            };
            return Some(entry_offset(&entries[index * 20..(index + 1) * 20]));
        }
        None
    }

    /// The value of `/Prev`, if any.
    fn prev(&self) -> Result<Option<usize>, Unsupported> {
        trailer_entries(self.trailer)?
            .into_iter()
            .find(|(name, _)| *name == "Prev")
            .map(|(_, value)| integer(value))
            .transpose()
    }
}

/// The position after the entries of a subsection of `count` entries of 20
/// bytes that start at `start`, or `None` if it overflows.
fn subsection_end(start: usize, count: usize) -> Option<usize> {
    count.checked_mul(20)?.checked_add(start)
}

/// The offset that a cross-reference entry of 20 bytes gives (clause
/// 7.5.4): ten digits of offset, a space, five digits of generation, a
/// space and `n`, each field read from its own bytes, so that no character
/// spans two of them. An entry of type `f`, or of a generation
/// other than 0, is refused.
fn entry_offset(entry: &[u8]) -> Result<usize, Unsupported> {
    if entry.len() != 20 {
        return Err(NOT_READ);
    }
    let field = |range: std::ops::Range<usize>| {
        std::str::from_utf8(&entry[range])
            .map_err(|_| NOT_READ)
            .and_then(integer)
    };
    let offset = field(0..10)?;
    let generation = field(11..16)?;
    if entry[10] != b' ' {
        return Err(NOT_READ);
    }
    if entry[16] != b' ' {
        return Err(NOT_READ);
    }
    match entry[17] {
        b'n' => {}
        b'f' => return Err(Unsupported("the object is not in use")),
        _ => return Err(NOT_READ),
    }
    if generation != 0 {
        return Err(Unsupported("the object is not of generation 0"));
    }
    Ok(offset)
}

/// The position after the line at `at` of `bytes`, which must be `word`
/// followed by an end-of-line marker.
fn line_after(bytes: &[u8], at: usize, word: &[u8]) -> Result<usize, Unsupported> {
    let rest = bytes.get(at..).ok_or(NOT_READ)?;
    let after = rest.strip_prefix(word).ok_or(NOT_READ)?;
    if after.starts_with(b"\r\n") {
        Ok(at + word.len() + 2)
    } else if after.starts_with(b"\n") || after.starts_with(b"\r") {
        Ok(at + word.len() + 1)
    } else {
        Err(NOT_READ)
    }
}

/// The position of the first `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The position of the last `needle` in `haystack`.
fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

impl<'a> Pdf<'a> {
    /// Reads the last cross-reference section of a file of at most
    /// [`MAX_PDF_LEN`] bytes that ends with `startxref`, its offset and
    /// the end-of-file marker, each on its own line (clause 7.5.5).
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, Unsupported> {
        if bytes.len() > MAX_PDF_LEN {
            return Err(Unsupported("the PDF is longer than the limit of 4 MiB"));
        }
        let body = bytes.strip_suffix(b"%%EOF\n").ok_or(NOT_READ)?;
        let tail = &body[body.len().saturating_sub(32)..];
        let start = rfind(tail, b"startxref\n").ok_or(NOT_READ)? + 10;
        let offset = std::str::from_utf8(&tail[start..])
            .map_err(|_| NOT_READ)?
            .strip_suffix('\n')
            .ok_or(NOT_READ)?;
        let startxref = integer(offset)?;
        let section = Section::read(bytes, startxref)?;
        let mut size = None;
        let mut entries = Vec::new();
        for (name, value) in trailer_entries(section.trailer)? {
            match name {
                "Size" => {
                    let value = u32::try_from(integer(value)?).map_err(|_| NOT_READ)?;
                    if value > MAX_SIZE {
                        return Err(Unsupported(
                            "/Size is larger than the limit of indirect objects",
                        ));
                    }
                    size = Some(value);
                }
                "Prev" => {}
                // A hybrid-reference file (clause 7.5.8.4) is not read here.
                "XRefStm" => return Err(NOT_READ),
                _ => entries.push((name, value)),
            }
        }
        Ok(Self {
            bytes,
            startxref,
            size: size.ok_or(NOT_READ)?,
            entries,
        })
    }

    /// The offset of the most recent copy of the object `number`, with
    /// generation 0: the first section that lists it, from the last one
    /// through `/Prev`, each earlier in the file than the one before.
    fn offset(&self, number: usize) -> Result<usize, Unsupported> {
        let mut at = self.startxref;
        for _ in 0..MAX_SECTIONS {
            let section = Section::read(self.bytes, at)?;
            if let Some(offset) = section.find(number) {
                return offset;
            }
            match section.prev()? {
                Some(prev) if prev < at => at = prev,
                _ => return Err(Unsupported("the object is not in the file")),
            }
        }
        Err(NOT_READ)
    }

    /// The most recent copy of the object `number`, between its
    /// `<number> 0 obj` line and the end-of-line marker before `endobj`.
    /// The number must be below `/Size`, which is one greater than the
    /// highest object number in the file (clause 7.5.5, Table 15).
    pub(crate) fn object(&self, number: u32) -> Result<&'a [u8], Unsupported> {
        if number >= self.size {
            return Err(Unsupported("the object number is not below /Size"));
        }
        let number = usize::try_from(number).map_err(|_| NOT_READ)?;
        if number == 0 {
            return Err(NOT_READ);
        }
        let offset = self.offset(number)?;
        let start = line_after(self.bytes, offset, format!("{number} 0 obj").as_bytes())?;
        let end = find(&self.bytes[start..], b"endobj").ok_or(NOT_READ)? + start;
        let mut object = &self.bytes[start..end];
        while let Some((last, rest)) = object.split_last()
            && is_white(*last)
        {
            object = rest;
        }
        Ok(object)
    }

    /// The most recent copy of the object `number`, as text.
    fn object_text(&self, number: u32) -> Result<&'a str, Unsupported> {
        std::str::from_utf8(self.object(number)?).map_err(|_| NOT_READ)
    }

    /// The file with an incremental update appended (clause 7.5.6): the
    /// objects `changed`, given by number with their content, which must
    /// be below `/Size`, each once, then the objects `added`, which take
    /// the numbers from `/Size` on, a cross-reference section with one
    /// subsection per run of consecutive numbers, and a trailer with the
    /// entries of the last one, `/Size` raised by the objects added, and
    /// `/Prev`. When `/Size` is correct (clause 7.5.5, Table 15), a new
    /// object therefore never takes the number of another; the
    /// cross-reference sections are not checked against it. `/Size`
    /// stays within [`MAX_SIZE`].
    fn update(&self, changed: &[(u32, String)], added: &[String]) -> Result<Vec<u8>, Unsupported> {
        let mut numbers: Vec<u32> = changed.iter().map(|(number, _)| *number).collect();
        if numbers.iter().any(|number| *number >= self.size) {
            return Err(Unsupported("the object number is not below /Size"));
        }
        numbers.sort_unstable();
        if numbers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Unsupported("the update writes an object twice"));
        }
        let size = u32::try_from(added.len())
            .ok()
            .and_then(|count| self.size.checked_add(count))
            .filter(|size| *size <= MAX_SIZE)
            .ok_or(Unsupported("the update needs more objects than the limit"))?;
        let mut out = self.bytes.to_vec();
        let mut offsets: Vec<(u32, usize)> = Vec::with_capacity(changed.len() + added.len());
        let objects = changed
            .iter()
            .map(|(number, object)| (*number, object))
            .chain((self.size..size).zip(added));
        for (number, object) in objects {
            offsets.push((number, out.len()));
            out.extend_from_slice(format!("{number} 0 obj\n{object}\nendobj\n").as_bytes());
        }
        offsets.sort_unstable();
        let xref = out.len();
        out.extend_from_slice(b"xref\n");
        let mut at = 0;
        while at < offsets.len() {
            let mut end = at + 1;
            while end < offsets.len() && offsets[end].0 == offsets[end - 1].0 + 1 {
                end += 1;
            }
            out.extend_from_slice(format!("{} {}\n", offsets[at].0, end - at).as_bytes());
            for (_, offset) in &offsets[at..end] {
                out.extend_from_slice(format!("{offset:010} 00000 n\r\n").as_bytes());
            }
            at = end;
        }
        let mut trailer = format!("trailer\n<< /Size {size}");
        for (name, value) in &self.entries {
            trailer.push_str(&format!(" /{name} {value}"));
        }
        trailer.push_str(&format!(
            " /Prev {} >>\nstartxref\n{xref}\n%%EOF\n",
            self.startxref
        ));
        out.extend_from_slice(trailer.as_bytes());
        Ok(out)
    }
}

/// `text` with every run of white space (clause 7.2.2, Table 1) written as
/// one space, so that an object that DSS writes again with one entry per
/// line compares equal to the object as [`crate::documents`] writes it.
/// The objects compared hold no literal string with two spaces in a row.
fn collapsed(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut white = false;
    for byte in text.bytes() {
        if is_white(byte) {
            white = true;
        } else {
            if white && !out.is_empty() {
                out.push(' ');
            }
            white = false;
            out.push(char::from(byte));
        }
    }
    out
}

/// Reports whether the most recent copy of the object `number` is
/// `expected`, white space aside.
fn object_is(file: &Pdf<'_>, number: u32, expected: &str) -> Result<bool, Unsupported> {
    Ok(collapsed(file.object_text(number)?) == collapsed(expected))
}

/// Replaces the one occurrence of `from` in `object`, which must not be
/// followed by a digit, with `to`.
fn replace_once(object: &str, from: &str, to: &str) -> Result<String, Unsupported> {
    let mut found = object
        .match_indices(from)
        .filter(|(at, _)| {
            !object
                .as_bytes()
                .get(at + from.len())
                .is_some_and(u8::is_ascii_digit)
        })
        .map(|(at, _)| at);
    let (Some(at), None) = (found.next(), found.next()) else {
        return Err(Unsupported(
            "the object does not hold the entry exactly once",
        ));
    };
    Ok(format!(
        "{}{to}{}",
        &object[..at],
        &object[at + from.len()..]
    ))
}

/// Adds a content stream to the page of a file of the corpus, in an
/// incremental update: the new stream takes the number `/Size` of the last
/// trailer, and the page, object 3, is written again with `/Contents`
/// changed from `5 0 R` to an array of both streams (ISO 32000-1:2008,
/// clause 7.7.3.3).
///
/// # Errors
///
/// Returns [`Unsupported`] when the input is not a PDF of the structure
/// read here, or its page does not have `/Contents 5 0 R` exactly once.
pub fn add_page_content(pdf: &[u8]) -> Result<Vec<u8>, Unsupported> {
    let file = Pdf::parse(pdf)?;
    let added = file.size;
    let page = replace_once(
        file.object_text(3)?,
        "/Contents 5 0 R",
        &format!("/Contents [5 0 R {added} 0 R]"),
    )?;
    file.update(&[(3, page)], &[documents::stream("", ADDED_CONTENT)])
}

/// Empties the overlay of the hide document of [`crate::documents`],
/// object 6, in an incremental update. The page, object 3, must draw it
/// after its content, with `/Contents [5 0 R 6 0 R]`.
///
/// # Errors
///
/// Returns [`Unsupported`] when the input is not a PDF of the structure
/// read here, or its object 6 is not the overlay drawn by the page.
pub fn remove_overlay(pdf: &[u8]) -> Result<Vec<u8>, Unsupported> {
    let file = Pdf::parse(pdf)?;
    if !object_is(&file, 6, &documents::overlay_object())? {
        return Err(Unsupported("object 6 is not the overlay"));
    }
    replace_once(file.object_text(3)?, "/Contents [5 0 R 6 0 R]", "")?;
    file.update(&[(6, documents::stream("", ""))], &[])
}

/// Replaces the value of the text field of the replace document of
/// [`crate::documents`], object 6, with `900 EUR`, and its
/// appearance with a new one that shows it, which takes the number `/Size`
/// of the last trailer, in an incremental update.
///
/// # Errors
///
/// Returns [`Unsupported`] when the input is not a PDF of the structure
/// read here, or its object 6 is not the field as signed, white space
/// aside: DSS writes it again when it adds the signature field.
pub fn replace_field_value(pdf: &[u8]) -> Result<Vec<u8>, Unsupported> {
    let file = Pdf::parse(pdf)?;
    if !object_is(
        &file,
        6,
        &documents::amount_field(documents::AMOUNT_SIGNED, 7),
    )? {
        return Err(Unsupported("object 6 is not the text field as signed"));
    }
    let appearance = file.size;
    file.update(
        &[(6, documents::amount_field(AMOUNT_REPLACED, appearance))],
        &[documents::amount_appearance(AMOUNT_REPLACED)],
    )
}

/// Writes the catalog, object 1, again with `/Pages 6 0 R` instead of
/// `/Pages 2 0 R`, in an incremental update that holds no other object.
/// Object 6 must be the second page tree of the hide-and-replace document
/// of [`crate::documents`].
///
/// # Errors
///
/// Returns [`Unsupported`] when the input is not a PDF of the structure
/// read here, its object 6 is not that page tree, or its catalog does not
/// have `/Pages 2 0 R` exactly once.
pub fn switch_page_tree(pdf: &[u8]) -> Result<Vec<u8>, Unsupported> {
    let file = Pdf::parse(pdf)?;
    if !object_is(&file, 6, documents::HIDDEN_PAGES)? {
        return Err(Unsupported("object 6 is not the second page tree"));
    }
    let catalog = replace_once(file.object_text(1)?, "/Pages 2 0 R", "/Pages 6 0 R")?;
    file.update(&[(1, catalog)], &[])
}

/// Moves the second range of the `ByteRange` of the only signature of a
/// file to a copy of its bytes appended to the file.
///
/// The file must be a PDF of at most [`MAX_PDF_LEN`] bytes with the
/// cross-reference tables that the other mutations read, and hold `/ByteRange [` once, followed by four non-negative integers `0 a b c` separated by
/// single spaces, `]`, and white space up to the next entry, as DSS writes
/// it with space to spare. The ranges must not overlap, the second must end
/// the file, the bytes between them must be a hexadecimal string, the
/// `Contents` of the signature, and the `ByteRange` must lie in the second
/// range. The output is the file with the value `[0 a L c]`, where `L` is
/// the length of the file, written over the old one and padded with spaces,
/// followed by the bytes from `b` to the end of the file.
///
/// # Errors
///
/// Returns [`Unsupported`] when the input is not of that form.
pub fn wrap_byte_range(pdf: &[u8]) -> Result<Vec<u8>, Unsupported> {
    Pdf::parse(pdf)?;
    let key = b"/ByteRange [";
    let mut found = pdf
        .windows(key.len())
        .enumerate()
        .filter(|(_, w)| *w == key)
        .map(|(at, _)| at + key.len() - 1);
    let (Some(open), None) = (found.next(), found.next()) else {
        return Err(Unsupported(
            "the file does not hold /ByteRange exactly once",
        ));
    };
    let malformed = Unsupported("the ByteRange is not of four integers 0 a b c with spaces");
    let close = pdf[open..]
        .iter()
        .take(48)
        .position(|&b| b == b']')
        .ok_or(malformed)?
        + open;
    let values = std::str::from_utf8(&pdf[open + 1..close]).map_err(|_| malformed)?;
    let values: Vec<usize> = values
        .split(' ')
        .map(integer)
        .collect::<Result<_, _>>()
        .map_err(|_| malformed)?;
    let [0, a, b, c] = values[..] else {
        return Err(malformed);
    };
    let length = pdf.len();
    if a >= b || b.checked_add(c) != Some(length) || open < b {
        return Err(Unsupported(
            "the ranges of the ByteRange do not end the file around the signature dictionary",
        ));
    }
    if pdf.get(a) != Some(&b'<') || pdf.get(b - 1) != Some(&b'>') {
        return Err(Unsupported(
            "the bytes between the ranges are not a hexadecimal string",
        ));
    }
    // The value and the spaces after it, up to the next entry or the end of
    // the dictionary, which DSS leaves to write the final value.
    let end = close
        + 1
        + pdf[close + 1..]
            .iter()
            .take_while(|&&byte| byte == b' ')
            .count();
    let value = format!("[0 {a} {length} {c}]");
    let space = end - open;
    if value.len() > space {
        return Err(Unsupported(
            "the new ByteRange does not fit in the space of the old one",
        ));
    }
    let mut out = Vec::with_capacity(length + c);
    out.extend_from_slice(&pdf[..open]);
    out.extend_from_slice(value.as_bytes());
    out.resize(end, b' ');
    out.extend_from_slice(&pdf[end..]);
    out.extend_from_slice(&pdf[b..]);
    Ok(out)
}

#[cfg(test)]
mod tests;
