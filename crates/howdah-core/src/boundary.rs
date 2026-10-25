//! Extract the multipart boundary from a `Content-Type` header, the way PHP's
//! `main/rfc1867.c` does, so the byte scanner frames parts on the request's REAL
//! boundary.
//!
//! PHP only runs its rfc1867 parser for `multipart/form-data`, and it takes the
//! first `boundary` parameter: a quoted value runs to the closing quote, an
//! unquoted value to the next `;` or the end. A missing or empty boundary means
//! no multipart parse (the scanner stays off; the parsed-event counter still
//! enforces the structural limits — fail closed, per design §4.2).

/// The boundary bytes, or `None` when the type is not `multipart/form-data` or
/// carries no usable `boundary`. Matching PHP: the media type (before the first
/// `;`, trimmed) must be `multipart/form-data` case-insensitively.
pub fn extract(content_type: &[u8]) -> Option<Vec<u8>> {
    let semi = content_type.iter().position(|&b| b == b';')?;
    let media = trim(&content_type[..semi]);
    if !media.eq_ignore_ascii_case(b"multipart/form-data") {
        return None;
    }
    // Walk the `; key=value` parameters; take the first `boundary`.
    let mut rest = &content_type[semi + 1..];
    loop {
        // One parameter: up to the next top-level `;` (quotes may contain `;`).
        let (param, tail) = split_param(rest);
        let param = trim(param);
        if let Some(eq) = param.iter().position(|&b| b == b'=') {
            let key = trim(&param[..eq]);
            if key.eq_ignore_ascii_case(b"boundary") {
                let val = parse_value(trim(&param[eq + 1..]));
                return (!val.is_empty()).then_some(val);
            }
        }
        match tail {
            Some(t) => rest = t,
            None => return None,
        }
    }
}

/// Split off one parameter at the next `;` that is not inside a quoted string.
fn split_param(s: &[u8]) -> (&[u8], Option<&[u8]>) {
    let mut in_quote = false;
    let mut i = 0;
    while i < s.len() {
        match s[i] {
            b'"' => in_quote = !in_quote,
            b';' if !in_quote => return (&s[..i], Some(&s[i + 1..])),
            _ => {}
        }
        i += 1;
    }
    (s, None)
}

/// A parameter value: quoted (bytes between the quotes, backslash-escapes kept as
/// their escaped byte) or bare (as-is, already trimmed by the caller).
fn parse_value(v: &[u8]) -> Vec<u8> {
    if v.first() != Some(&b'"') {
        return v.to_vec();
    }
    let mut out = Vec::new();
    let mut i = 1;
    while i < v.len() {
        match v[i] {
            b'"' => break,
            b'\\' if i + 1 < v.len() => {
                out.push(v[i + 1]);
                i += 2;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_boundary() {
        assert_eq!(extract(b"multipart/form-data; boundary=abc").as_deref(), Some(b"abc".as_slice()));
    }
    #[test]
    fn quoted_boundary_keeps_inner_spaces_and_semicolons() {
        assert_eq!(extract(b"multipart/form-data; boundary=\"a b;c\"").as_deref(), Some(b"a b;c".as_slice()));
    }
    #[test]
    fn case_insensitive_type_and_key() {
        assert_eq!(extract(b"Multipart/Form-Data; BOUNDARY=XYZ").as_deref(), Some(b"XYZ".as_slice()));
    }
    #[test]
    fn boundary_then_other_params() {
        assert_eq!(extract(b"multipart/form-data; boundary=abc; charset=utf-8").as_deref(), Some(b"abc".as_slice()));
        assert_eq!(extract(b"multipart/form-data; charset=utf-8; boundary=abc").as_deref(), Some(b"abc".as_slice()));
    }
    #[test]
    fn seventy_char_boundary() {
        let b = vec![b'x'; 70];
        let mut ct = b"multipart/form-data; boundary=".to_vec();
        ct.extend_from_slice(&b);
        assert_eq!(extract(&ct).as_deref(), Some(b.as_slice()));
    }
    #[test]
    fn not_multipart_or_missing_is_none() {
        assert_eq!(extract(b"application/x-www-form-urlencoded"), None);
        assert_eq!(extract(b"text/plain; charset=utf-8"), None);
        assert_eq!(extract(b"multipart/form-data"), None); // no params at all
        assert_eq!(extract(b"multipart/form-data; charset=utf-8"), None); // no boundary
        assert_eq!(extract(b"multipart/form-data; boundary="), None); // empty
        assert_eq!(extract(b"multipart/form-data; boundary=\"\""), None); // empty quoted
    }
    #[test]
    fn whitespace_around_media_type() {
        assert_eq!(extract(b"  multipart/form-data ; boundary=abc").as_deref(), Some(b"abc".as_slice()));
    }
}
