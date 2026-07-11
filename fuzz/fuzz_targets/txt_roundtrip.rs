#![no_main]

//! Round-trip the packed TXT wire format: encode arbitrary entries as the
//! length-prefixed buffer a DNS-SD responder would send, decode it back, and
//! require exactly the non-empty entries, in order, each agreeing with the
//! single-entry parser. This is the property that guards against framing bugs
//! — an off-by-one in the length handling would surface as an entry leaking
//! bytes into its neighbour.

use libfuzzer_sys::fuzz_target;
use mdns_sd_discovery::fuzzing::{parse_txt_buffer, parse_txt_entry};

fuzz_target!(|entries: Vec<Vec<u8>>| {
    let mut buf = Vec::new();
    let mut expected = Vec::new();
    for entry in &entries {
        let entry = &entry[..entry.len().min(255)];
        buf.push(entry.len() as u8);
        buf.extend_from_slice(entry);
        // The parser skips empty entries (a lone zero length prefix).
        if !entry.is_empty() {
            expected.push(parse_txt_entry(entry));
        }
    }
    assert_eq!(parse_txt_buffer(&buf), expected);
});
