//! Extract the multipart boundary from a `Content-Type` header the way PHP's
//! `main/rfc1867.c` does, byte for byte — so the scanner frames parts on exactly
//! the delimiter PHP will use. A clean RFC parser is wrong here: any divergence
//! is attacker-selectable (via the request's own Content-Type) and silently
//! disarms or mis-frames the scanner, taking gaps A and B with it.
//!
//! PHP's algorithm: find the SUBSTRING `boundary` (case-insensitive — it does a
//! case-sensitive `strstr` then a lowercased retry), the first `=` after it,
//! then a quoted value running to the next `"` (NO backslash handling) or an
//! unquoted value running to the next `,` or `;` (else to the end). It does NOT
//! check the media type here — PHP only calls this for a body it already
//! resolved as `multipart/form-data` (its `post_entry`), which is exactly the
//! condition the glue arms on (`howdah_is_multipart_post`), so this function is
//! only ever called for a real multipart body.

/// The boundary bytes PHP would use, or `None` when there is no `boundary=` with
/// a non-empty value. Mirrors `rfc1867.c`, quirks included (a substring match,
/// so `myboundary=X` yields `X`; the first `boundary` wins; no escape handling).
pub fn extract(content_type: &[u8]) -> Option<Vec<u8>> {
    const KEY: &[u8] = b"boundary";
    let pos = find_ci(content_type, KEY)?;
    let after = &content_type[pos + KEY.len()..];
    let eq = after.iter().position(|&b| b == b'=')?;
    let v = &after[eq + 1..];
    let bound: &[u8] = if v.first() == Some(&b'"') {
        let inner = &v[1..];
        let end = inner.iter().position(|&b| b == b'"')?; // run to the next quote
        &inner[..end]
    } else {
        let end = v.iter().position(|&b| b == b',' || b == b';').unwrap_or(v.len());
        &v[..end]
    };
    (!bound.is_empty()).then(|| bound.to_vec())
}

/// First case-insensitive occurrence of `needle` in `hay`.
fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(ct: &[u8]) -> Option<Vec<u8>> {
        extract(ct)
    }

    #[test]
    fn plain_and_quoted() {
        assert_eq!(ext(b"multipart/form-data; boundary=abc").as_deref(), Some(b"abc".as_slice()));
        // Quoted runs to the next quote; inner ';' and spaces are kept.
        assert_eq!(ext(b"multipart/form-data; boundary=\"a b;c\"").as_deref(), Some(b"a b;c".as_slice()));
        assert_eq!(ext(b"Multipart/Form-Data; BOUNDARY=XYZ").as_deref(), Some(b"XYZ".as_slice()));
    }

    // Each case is what PHP's rfc1867.c actually extracts (reviewed against the
    // 5.6/7.4/8.3 sources). A clean parser would differ and disarm the scanner.
    #[test]
    fn matches_php_quirks() {
        // No ';' separator: PHP still finds boundary=X.
        assert_eq!(ext(b"multipart/form-data boundary=X").as_deref(), Some(b"X".as_slice()));
        // strstr is a SUBSTRING match: myboundary matches "boundary".
        assert_eq!(ext(b"multipart/form-data; myboundary=X").as_deref(), Some(b"X".as_slice()));
        // The FIRST "boundary" wins (xboundary=A before boundary=B).
        assert_eq!(ext(b"multipart/form-data; xboundary=A; boundary=B").as_deref(), Some(b"A".as_slice()));
        // "boundary" inside a quoted earlier param still wins, and the unquoted
        // value runs to ';' including a stray quote.
        assert_eq!(ext(b"multipart/form-data; foo=\"boundary=A\"; boundary=B").as_deref(), Some(b"A\"".as_slice()));
        // No backslash handling: quoted value stops at the first '"'.
        assert_eq!(ext(b"boundary=\"a\\\"b\"").as_deref(), Some(b"a\\".as_slice()));
        // Unquoted stops at ',' too.
        assert_eq!(ext(b"multipart/form-data; boundary=X, charset=utf-8").as_deref(), Some(b"X".as_slice()));
    }

    #[test]
    fn seventy_char_boundary() {
        let b = vec![b'x'; 70];
        let mut ct = b"multipart/form-data; boundary=".to_vec();
        ct.extend_from_slice(&b);
        assert_eq!(ext(&ct).as_deref(), Some(b.as_slice()));
    }

    #[test]
    fn no_boundary_or_empty_is_none() {
        assert_eq!(ext(b"multipart/form-data"), None); // no "boundary" substring
        assert_eq!(ext(b"multipart/form-data; charset=utf-8"), None);
        assert_eq!(ext(b"multipart/form-data; boundary="), None); // empty
        assert_eq!(ext(b"multipart/form-data; boundary=\"\""), None); // empty quoted
    }
}
