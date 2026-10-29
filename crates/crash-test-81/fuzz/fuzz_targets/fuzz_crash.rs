//! Temporary target that fails while fuzzing, after building a corpus.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.len() >= 3 && data[0] == b'c' && data[1] == b'r' {
        assert!(data[2] != b'a', "crash while fuzzing");
    }
});
