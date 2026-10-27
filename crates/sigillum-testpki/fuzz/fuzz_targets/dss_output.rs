//! Fuzz target for the readers of the output of `tools/dss-oracle` in
//! `sigillum-testpki verify --dss`: the version line of `--version`, and
//! the `summary.json` of a validation, read for each mode at the
//! validation time and DSS version of the corpus.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sigillum_testpki::dss::{Mode, parse_version, read_summary};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_version(text);
    for mode in [Mode::Certificate, Mode::Timestamp, Mode::Document] {
        let _ = read_summary(text, mode, "2030-01-15T10:00:00Z", "6.5.1");
    }
});
