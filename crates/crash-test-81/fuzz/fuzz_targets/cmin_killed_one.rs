//! Temporary target whose process is killed, with no report, while its
//! corpus, trimmed to one input, is minimised.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if std::env::var_os("CRASH_DURING_CMIN").is_some() {
        let _ = std::process::Command::new("kill")
            .args(["-9", &std::process::id().to_string()])
            .status();
    }
    if data.len() > 2 && data[0] == b'o' && data[1] == b'n' {
        std::hint::black_box(data[2]);
    }
});
