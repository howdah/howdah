//! Mixed-case TLS URL scheme detection (CVE-2026-128064).
//!
//! PHP's `http`/`ftp` stream wrappers decide TLS by looking for a LOWERCASE
//! `s` at a fixed offset of the URL scheme, so `HTTPS://` / `FTPS://` is
//! connected in plaintext even though the wrapper lookup is case-insensitive.
//! The fix is to lowercase just the scheme before the wrapper sees it.
//!
//! Pure, linear-time, allocation only in `normalize_scheme`. `http`/`ftp`
//! with odd case are deliberately NOT reported: they are plaintext by intent,
//! so normalizing them changes no security property.

/// Length of the scheme token if `url` starts with a TLS scheme (`https` or
/// `ftps`, ASCII case-insensitive) followed by `://` AND the scheme contains
/// at least one uppercase letter. 0 otherwise (all-lowercase, other schemes,
/// no scheme, too short).
pub fn mixed_case_tls_scheme_len(url: &[u8]) -> usize {
    let n = if url.len() >= 8 && url[..5].eq_ignore_ascii_case(b"https") && &url[5..8] == b"://" {
        5
    } else if url.len() >= 7 && url[..4].eq_ignore_ascii_case(b"ftps") && &url[4..7] == b"://" {
        4
    } else {
        return 0;
    };
    if url[..n].iter().any(u8::is_ascii_uppercase) {
        n
    } else {
        0
    }
}

/// `url` with its scheme lowercased when `mixed_case_tls_scheme_len` is
/// non-zero; `None` when no change is needed. Only the scheme bytes change.
pub fn normalize_scheme(url: &[u8]) -> Option<Vec<u8>> {
    let n = mixed_case_tls_scheme_len(url);
    if n == 0 {
        return None;
    }
    let mut out = url.to_vec();
    out[..n].make_ascii_lowercase();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mixed_case_tls() {
        assert_eq!(mixed_case_tls_scheme_len(b"HTTPS://h/p"), 5);
        assert_eq!(mixed_case_tls_scheme_len(b"hTTps://h"), 5);
        assert_eq!(mixed_case_tls_scheme_len(b"httpS://h"), 5);
        assert_eq!(mixed_case_tls_scheme_len(b"FTPS://u:p@h/"), 4);
        assert_eq!(mixed_case_tls_scheme_len(b"Ftps://h"), 4);
    }

    #[test]
    fn leaves_lowercase_and_others() {
        for u in [
            &b"https://h"[..], b"ftps://h", b"http://h", b"HTTP://h", b"FTP://h",
            b"file:///x", b"PHAR://x", b"", b"HTTPS", b"HTTPS:/h", b"HTTPS//h",
            b"HTTPSX://h", b"/etc/passwd", b"xHTTPS://h", b"ftp://h", b"FTPS:",
        ] {
            assert_eq!(mixed_case_tls_scheme_len(u), 0, "{:?}", String::from_utf8_lossy(u));
            assert!(normalize_scheme(u).is_none());
        }
    }

    #[test]
    fn normalizes_only_the_scheme() {
        assert_eq!(normalize_scheme(b"HTTPS://Host/PATH?Q=A").unwrap(), b"https://Host/PATH?Q=A");
        assert_eq!(normalize_scheme(b"FtpS://U:P@Host/F").unwrap(), b"ftps://U:P@Host/F");
        assert_eq!(normalize_scheme(b"HTTPS://").unwrap(), b"https://");
    }

    #[test]
    fn non_utf8_tail_is_fine() {
        let u = b"HTTPS://h/\xff\xfe";
        assert_eq!(normalize_scheme(u).unwrap(), b"https://h/\xff\xfe");
    }
}
