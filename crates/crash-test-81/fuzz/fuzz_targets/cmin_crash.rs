//! Temporary target that fails only while its corpus is minimised.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.first() == Some(&b'c') {
        assert!(std::env::var_os("CRASH_DURING_CMIN").is_none(), "crash during cmin");
    }
});
