#![no_main]
use howdah_core::multipart::MultipartState;
use libfuzzer_sys::fuzz_target;

// Input layout: [boundary_len_byte][boundary...][split_seed][body...]
// The body is fed split at pseudo-random points; must never panic.
fuzz_target!(|data: &[u8]| {
    let Some((&bl, rest)) = data.split_first() else { return };
    let bl = (bl as usize % 12) + 1;
    if rest.len() < bl + 1 {
        return;
    }
    let (boundary, rest) = rest.split_at(bl);
    let (&seed, body) = rest.split_first().unwrap();
    let mut s = MultipartState::new(boundary);
    let mut pos = 0usize;
    let mut k = seed as usize;
    while pos < body.len() {
        // Derive a chunk size from the body bytes themselves.
        k = (k.wrapping_mul(31).wrapping_add(body[pos] as usize)) % 97 + 1;
        let end = (pos + k).min(body.len());
        if s.feed(&body[pos..end]).is_err() {
            return;
        }
        pos = end;
    }
    let _ = s.finish();
});
