#![no_main]

//! Fuzz the fully-qualified DNS name trimmer. The result must be a prefix of
//! the input with only `.` characters removed from the end — never interior
//! dots, never other characters — and trimming must be idempotent.

use libfuzzer_sys::fuzz_target;
use mdns_sd_discovery::fuzzing::trim_dot;

fuzz_target!(|name: &str| {
    let trimmed = trim_dot(name);
    assert!(!trimmed.ends_with('.'));
    assert!(name.starts_with(&trimmed));
    assert!(name[trimmed.len()..].bytes().all(|b| b == b'.'));
    assert_eq!(trim_dot(&trimmed), trimmed);
});
