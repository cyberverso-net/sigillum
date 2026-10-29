//! Temporary target with a corpus of about one input, whose process is
//! killed, with no report, while the corpus is minimised.
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    if std::env::var_os("CRASH_DURING_CMIN").is_some() {
        let _ = std::process::Command::new("kill")
            .args(["-9", &std::process::id().to_string()])
            .status();
    }
    std::hint::black_box(data.is_empty());
});
