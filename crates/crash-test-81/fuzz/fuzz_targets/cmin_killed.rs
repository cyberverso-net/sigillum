//! Temporary target whose process is killed, with no report, while its
//! corpus is minimised.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if data.first() == Some(&b'c') && std::env::var_os("CRASH_DURING_CMIN").is_some() {
        let _ = std::process::Command::new("kill")
            .args(["-9", &std::process::id().to_string()])
            .status();
    }
});
