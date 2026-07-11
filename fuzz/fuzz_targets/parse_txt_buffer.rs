#![no_main]

//! Feed arbitrary bytes to the packed TXT buffer parser. The length prefixes
//! come straight off the wire, so beyond not panicking (the out-of-bounds
//! class of bugs), the output must respect the framing limits: every record
//! consumes at least its prefix byte plus one payload byte, and no value can
//! exceed what a single 255-byte entry can carry.

use libfuzzer_sys::fuzz_target;
use mdns_sd_discovery::fuzzing::parse_txt_buffer;

fuzz_target!(|data: &[u8]| {
    let records = parse_txt_buffer(data);

    // Each record came from a non-empty entry: 1 prefix byte + >=1 payload.
    assert!(records.len() <= data.len() / 2);

    for record in &records {
        if let Some(value) = &record.value {
            // 255-byte entry minus the `=` leaves at most 254 value bytes.
            assert!(value.len() <= 254);
        }
    }
});
