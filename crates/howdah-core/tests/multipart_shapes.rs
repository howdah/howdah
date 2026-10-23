use howdah_core::multipart::{Event, MalformedBody, MultipartState};

const B: &[u8] = b"XyZ123";

fn three_part_body() -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"preamble ignored\r\n");
    v.extend_from_slice(b"--XyZ123\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nhello\r\n");
    v.extend_from_slice(b"--XyZ123\r\nContent-Disposition: form-data; name=\"up\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\nfile\r\n--XyZ12 not-a-delim\r\n\r\n");
    v.extend_from_slice(b"\r\n--XyZ123\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\n\r\n--XyZ123--\r\nepilogue");
    v
}

/// Run whole-body, returning (events, parts, files).
fn run(chunks: &[&[u8]]) -> Result<(Vec<Event>, u64, u64), MalformedBody> {
    let mut s = MultipartState::new(B);
    let mut ev = Vec::new();
    for c in chunks {
        ev.extend(s.feed(c)?);
    }
    ev.extend(s.finish()?);
    Ok((ev, s.parts(), s.files()))
}

#[test]
fn well_formed_three_parts() {
    let body = three_part_body();
    let (ev, parts, files) = run(&[&body]).unwrap();
    assert_eq!(parts, 3);
    assert_eq!(files, 1);
    assert_eq!(ev.iter().filter(|e| **e == Event::PartStart).count(), 3);
    assert_eq!(ev.iter().filter(|e| **e == Event::PartEnd).count(), 3);
    assert_eq!(ev.last(), Some(&Event::BodyEnd));
    assert!(ev.contains(&Event::FileStart { filename_len: 5 }));
    assert!(ev.contains(&Event::FieldStart { name_len: 1 }));
    // per-part header counts: part 2 has two headers
    let hdrs: Vec<usize> = ev
        .split(|e| *e == Event::PartStart)
        .skip(1)
        .map(|p| p.iter().filter(|e| matches!(e, Event::PartHeader { .. })).count())
        .collect();
    assert_eq!(hdrs, vec![1, 2, 1]);
    assert!(ev.contains(&Event::PartData { len: 5 }));
    assert!(ev.contains(&Event::PartData { len: 29 }));
    assert!(ev.contains(&Event::PartData { len: 0 }));
}

#[test]
fn headers_counter_tracks_current_part() {
    let mut s = MultipartState::new(B);
    s.feed(b"--XyZ123\r\nContent-Disposition: form-data; name=\"a\"\r\nX-A: 1\r\n").unwrap();
    assert_eq!(s.headers_in_current_part(), 2);
    assert_eq!(s.parts(), 1);
}

#[test]
fn one_byte_chunks_equal_whole() {
    let body = three_part_body();
    let whole = run(&[&body]).unwrap();
    let singles: Vec<&[u8]> = body.chunks(1).collect();
    assert_eq!(run(&singles).unwrap(), whole);
    for n in 2..40 {
        let cs: Vec<&[u8]> = body.chunks(n).collect();
        assert_eq!(run(&cs).unwrap(), whole, "chunk size {n}");
    }
}

#[test]
fn truncated_is_malformed() {
    let body = three_part_body();
    let cut = &body[..body.len() - 30];
    assert!(run(&[cut]).is_err());
    assert!(run(&[b"--XyZ123\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nabc"]).is_err());
    assert!(run(&[b""]).is_err());
}

#[test]
fn bad_boundary_is_malformed() {
    // delimiter line followed by garbage
    assert!(run(&[b"--XyZ123garbage\r\n"]).is_err());
    // empty boundary
    let mut s = MultipartState::new(b"");
    assert!(s.feed(b"--\r\n").is_err());
}

#[test]
fn duplicate_boundary_is_malformed() {
    let mut b = three_part_body();
    b.extend_from_slice(b"\r\n--XyZ123\r\nContent-Disposition: form-data; name=\"z\"\r\n\r\nq\r\n--XyZ123--\r\n");
    assert!(run(&[&b]).is_err());
}

#[test]
fn conflicting_content_disposition_is_malformed() {
    let two = b"--XyZ123\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nx\r\n--XyZ123--";
    assert!(run(&[two]).is_err());
    let dup = b"--XyZ123\r\nContent-Disposition: form-data; name=\"a\"; name=\"b\"\r\n\r\nx\r\n--XyZ123--";
    assert!(run(&[dup]).is_err());
    let missing = b"--XyZ123\r\nX-A: b\r\n\r\nx\r\n--XyZ123--";
    assert!(run(&[missing]).is_err());
}

#[test]
fn self_overlapping_boundary_is_chunk_independent() {
    let body: &[u8] = b"--aa\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n\r\n--a\r\n--\r\n-\r\n--aXaa\r\n--a\r\n--aa--";
    let go = |cs: &[&[u8]]| {
        let mut s = MultipartState::new(b"aa");
        let mut ev = Vec::new();
        for c in cs {
            ev.extend(s.feed(c).unwrap());
        }
        ev.extend(s.finish().unwrap());
        ev
    };
    let whole = go(&[body]);
    assert!(whole.iter().any(|e| matches!(e, Event::PartData { len } if *len > 10)));
    let singles: Vec<&[u8]> = body.chunks(1).collect();
    assert_eq!(go(&singles), whole);
}

#[test]
fn errors_are_sticky_and_never_panic() {
    let mut s = MultipartState::new(B);
    assert!(s.feed(b"--XyZ123 x\r\n").is_err());
    assert!(s.feed(b"anything").is_err());
}
