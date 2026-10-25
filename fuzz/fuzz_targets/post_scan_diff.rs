#![no_main]
//! The §4.2 byte-stream scanner must be chunk-invariant: feeding a body whole or
//! split at any points yields the SAME high-water counts. That invariance is
//! what stops a client from desyncing the scanner (switching a limit off) by
//! choosing chunk boundaries — the 1.2.1 bug class. The target also proves the
//! scanner never panics and stays bounded on arbitrary input. (A true
//! differential against PHP's own rfc1867 parse needs PHP and runs in the lab.)
use howdah_core::multipart::MultipartState;
use libfuzzer_sys::fuzz_target;

// Input layout: [boundary_len_byte][boundary...][split_seed][body...]
fuzz_target!(|data: &[u8]| {
    let Some((&bl, rest)) = data.split_first() else { return };
    let bl = (bl as usize % 12) + 1;
    if rest.len() < bl + 1 {
        return;
    }
    let (boundary, rest) = rest.split_at(bl);
    let (&seed, body) = rest.split_first().unwrap();

    // Whole, in one feed.
    let mut whole = MultipartState::new(boundary);
    let whole_ok = whole.feed(body).is_ok();

    // Split at body-derived pseudo-random points.
    let mut split = MultipartState::new(boundary);
    let mut pos = 0usize;
    let mut k = seed as usize;
    let mut split_ok = true;
    while pos < body.len() {
        k = (k.wrapping_mul(31).wrapping_add(body[pos] as usize)) % 97 + 1;
        let end = (pos + k).min(body.len());
        if split.feed(&body[pos..end]).is_err() {
            split_ok = false;
            break;
        }
        pos = end;
    }

    // When both parse the whole body without error, every counter the limits
    // read must be identical regardless of how the body was chunked.
    if whole_ok && split_ok {
        assert_eq!(whole.parts(), split.parts(), "parts");
        assert_eq!(whole.files(), split.files(), "files");
        assert_eq!(whole.max_headers_in_any_part(), split.max_headers_in_any_part(), "max_headers");
        assert_eq!(whole.max_header_bytes_seen(), split.max_header_bytes_seen(), "max_header_bytes");
        assert_eq!(whole.total_nonfile_bytes(), split.total_nonfile_bytes(), "nonfile_bytes");
        assert_eq!(whole.total_fed_bytes(), split.total_fed_bytes(), "total_fed");
    }
});
