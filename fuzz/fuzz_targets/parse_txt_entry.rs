#![no_main]

//! Fuzz the `key[=value]` TXT entry splitter against a straight-line spec of
//! [RFC 6763 §6.4](https://datatracker.ietf.org/doc/html/rfc6763#section-6.4):
//! the first `=` separates key from value, the value keeps its raw bytes
//! untouched, and an entry without `=` is key-only (`None`, never an empty
//! value) — so binary values and `=` characters inside a value can never be
//! reshaped or misattributed to the key.

use libfuzzer_sys::fuzz_target;
use mdns_sd_discovery::fuzzing::parse_txt_entry;

fuzz_target!(|data: &[u8]| {
    let record = parse_txt_entry(data);
    match data.iter().position(|&b| b == b'=') {
        Some(pos) => {
            assert_eq!(record.key, String::from_utf8_lossy(&data[..pos]));
            assert_eq!(record.value.as_deref(), Some(&data[pos + 1..]));
        }
        None => {
            assert_eq!(record.key, String::from_utf8_lossy(data));
            assert_eq!(record.value, None);
        }
    }
});
