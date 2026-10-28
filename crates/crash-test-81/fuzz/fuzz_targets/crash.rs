//! Temporary target that panics on an input starting with "crash".
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    assert!(!data.starts_with(b"crash"), "crash input");
});
