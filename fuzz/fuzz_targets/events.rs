#![no_main]
//! Fuzz the interface production actually uses: the PHP glue reports parsed
//! events (`howdah_part`, `howdah_part_data`) over the C ABI; it never feeds
//! request bytes. The invariant under test is the one the PHP2Shell defence
//! rests on: once more file parts (or parts) have been reported than the
//! limit allows, the action is Block for that part and stays Block, whatever
//! data lengths or stray raw bytes were interleaved. Must never panic.
use howdah_core::ffi::{
    howdah_feed, howdah_free, howdah_init, howdah_part, howdah_part_data, howdah_request_begin,
    howdah_request_end, HOWDAH_BLOCK, HOWDAH_PART_FIELD, HOWDAH_PART_FILE,
};
use libfuzzer_sys::fuzz_target;
use std::ffi::c_char;

const MAX_FILES: u64 = 5;
const MAX_PARTS: u64 = 50;
const CFG: &str = "mode = \"detect\"\n[limits]\nmax_files = 5\nmax_parts = 50\n";

// Input layout: a stream of ops. op byte % 4:
//   0: field part, name_len = next byte
//   1: file part, name_len = next byte, filename_len = next byte
//   2: part data, len = next two bytes (little-endian)
//   3: raw bytes fed to howdah_feed (len = next byte, then that many bytes)
fuzz_target!(|data: &[u8]| {
    unsafe {
        let ctx = howdah_init(CFG.as_ptr() as *const c_char, CFG.len());
        howdah_request_begin(ctx, std::ptr::null(), 0, std::ptr::null());
        let (mut parts, mut files) = (0u64, 0u64);
        let over = |parts: u64, files: u64| parts > MAX_PARTS || files > MAX_FILES;
        let mut i = 0;
        while i < data.len() {
            let op = data[i] % 4;
            i += 1;
            let action = match op {
                0 => {
                    let n = *data.get(i).unwrap_or(&1) as usize;
                    i += 1;
                    parts += 1;
                    howdah_part(ctx, HOWDAH_PART_FIELD, n, 0)
                }
                1 => {
                    let n = *data.get(i).unwrap_or(&1) as usize;
                    let f = *data.get(i + 1).unwrap_or(&1) as usize;
                    i += 2;
                    parts += 1;
                    files += 1;
                    howdah_part(ctx, HOWDAH_PART_FILE, n, f)
                }
                2 => {
                    let len = u16::from_le_bytes([
                        *data.get(i).unwrap_or(&0),
                        *data.get(i + 1).unwrap_or(&0),
                    ]) as usize;
                    i += 2;
                    howdah_part_data(ctx, len)
                }
                _ => {
                    let n = *data.get(i).unwrap_or(&0) as usize;
                    let start = (i + 1).min(data.len());
                    let end = (start + n).min(data.len());
                    let chunk = &data[start..end];
                    i = end.max(i + 1);
                    howdah_feed(ctx, chunk.as_ptr() as *const c_char, chunk.len())
                }
            };
            if over(parts, files) {
                assert_eq!(action, HOWDAH_BLOCK, "parts={parts} files={files} op={op}");
            }
        }
        let end = howdah_request_end(ctx);
        if over(parts, files) {
            assert_eq!(end, HOWDAH_BLOCK);
        }
        howdah_free(ctx);
    }
});
