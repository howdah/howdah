//! SSRF URL/host parsing and IP classification: pure, linear-time, wasm-safe.
//!
//! No `std::net` types, no DNS, no regex. DNS resolution happens in the C glue;
//! this module only parses hosts and classifies raw address bytes.
//!
//! Resolved IPs are authoritative. Literal-IP decoding here mirrors glibc
//! `inet_aton` permissiveness (dword, octal, hex, short forms) so encoded-IP
//! bypasses are not missed, but it is belt-and-braces only: libcurl and musl
//! parse literals differently, so a decode miss must never be relied on.

/// Network schemes whose URLs we inspect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
    Ftp,
    Ftps,
    Tcp,
    Udp,
    Ssl,
    Tls,
    Gopher,
}

/// Whether a scheme is required (URL-only sinks) or a bare `host[:port]` is
/// acceptable (curl-style).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostForm {
    SchemeRequired,
    BareHostOk,
}

/// Parsed host. `name` has userinfo stripped, IPv6 brackets and zone-id
/// removed, trailing dots removed, and is lowercased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub scheme: Option<Scheme>,
    pub name: Vec<u8>,
    pub port: Option<u16>,
    /// The authority contained a NUL byte. No legitimate host does; the two
    /// consumers (PHP's `php_url_parse`, which keeps userinfo, and libc, which
    /// stops at the NUL) can then resolve to different hosts, so the caller must
    /// treat it as suspicious rather than trust a single parse.
    pub suspicious: bool,
}

fn scheme_from(s: &[u8]) -> Option<Scheme> {
    let l = s.to_ascii_lowercase();
    Some(match l.as_slice() {
        b"http" => Scheme::Http,
        b"https" => Scheme::Https,
        b"ftp" => Scheme::Ftp,
        b"ftps" => Scheme::Ftps,
        b"tcp" => Scheme::Tcp,
        b"udp" => Scheme::Udp,
        b"ssl" => Scheme::Ssl,
        b"tls" => Scheme::Tls,
        b"gopher" => Scheme::Gopher,
        _ => return None,
    })
}

fn find_sub(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Parse a URL (`scheme://[user:pw@]host[:port]/...`) or, for
/// `HostForm::BareHostOk`, a bare `host[:port]`.
pub fn parse_host(input: &[u8], form: HostForm) -> Option<Host> {
    let input = input.trim_ascii();
    if input.is_empty()
        || input.starts_with(b"/")
        || input.starts_with(b"./")
        || input.starts_with(b"../")
    {
        return None;
    }
    // Peel leading `scheme://` prefixes. `://` is a delimiter only before any
    // `/`, `?` or `#` (otherwise it is part of a bare host's path/query, e.g.
    // `127.0.0.1/?u=http://x`). A known network scheme fixes the scheme and what
    // follows is the authority. An UNKNOWN scheme is peeled and we retry on the
    // remainder, so a curl scheme (`dict://127.0.0.1`) and a nesting wrapper
    // (`compress.zlib://http://169.254.169.254/`) both classify the inner host
    // instead of slipping past the range check as "not a network target" (F4).
    // Iterative, not recursive: every step drops a `scheme://`, so a crafted
    // `a://a://a://…` cannot overflow the stack.
    let mut rest = input;
    let scheme = loop {
        let delim = find_sub(rest, b"://")
            .filter(|&i| !rest[..i].iter().any(|b| matches!(b, b'/' | b'?' | b'#')));
        match delim {
            Some(i) => {
                let sch = &rest[..i];
                if sch.is_empty()
                    || !sch
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
                {
                    // Not a valid scheme, so this `://` is not a delimiter. A
                    // bare host (curl) takes the authority as the text BEFORE it
                    // (`127.0.0.1:80://x` connects to 127.0.0.1:80); a stream URL
                    // needs a real scheme (F3 re-review).
                    if form == HostForm::SchemeRequired {
                        return None;
                    }
                    rest = &rest[..i];
                    break None;
                }
                match scheme_from(sch) {
                    Some(s) => {
                        rest = &rest[i + 3..];
                        break Some(s);
                    }
                    None => {
                        rest = &rest[i + 3..];
                        continue;
                    }
                }
            }
            None => {
                if form == HostForm::SchemeRequired {
                    return None;
                }
                break None;
            }
        }
    };
    // Authority ends at `/`, `?` or `#` only. A backslash is NOT a terminator:
    // PHP's `php_url_parse` (the http/ftp stream wrappers) and libcurl both keep
    // `\` in the userinfo and take the host after the last `@`, so
    // `http://public.example\@169.254.169.254/` connects to 169.254.169.254 on
    // both (PoC-confirmed, PHP 5.6 and 8.3). Terminating at `\` here would make
    // us read `public.example` and allow the request.
    let end = rest
        .iter()
        .position(|b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(rest.len());
    // A NUL anywhere in the authority (userinfo, host or port) makes the host
    // ambiguous between the URL-parser view (keeps userinfo) and the libc view
    // (stops at the NUL): e.g. `127.0.0.1\0@public` is `public` to one and
    // `127.0.0.1` to the other. No legitimate host has a NUL, so flag the whole
    // request suspicious rather than trust either single view.
    let suspicious = rest[..end].contains(&0);
    let mut auth = &rest[..end];
    if let Some(at) = auth.iter().rposition(|&b| b == b'@') {
        auth = &auth[at + 1..];
    }
    // A NUL terminates the authority for libc / PHP < 7, so classify only the
    // bytes before the first NUL. One cut on the whole authority (after the
    // userinfo strip), BEFORE the split, so garbage AFTER the NUL — a bad port,
    // or a stray `]` — cannot make the parse fail open (libc ignores everything
    // past the NUL): `127.0.0.1\0:99999` -> 127.0.0.1, `127.0.0.1:80\0x` -> :80,
    // `[::1\0]` and `[::1]\0:80` -> ::1 (F3).
    if let Some(z) = auth.iter().position(|&b| b == 0) {
        auth = &auth[..z];
    }
    let (name, port_s): (&[u8], &[u8]) = if auth.first() == Some(&b'[') {
        // Tolerate a missing `]` (a NUL cut may have removed it): take the rest
        // as the address so `[::1\0]` yields `::1` rather than failing open.
        let close = auth.iter().position(|&b| b == b']').unwrap_or(auth.len());
        let after = if close < auth.len() { &auth[close + 1..] } else { &[][..] };
        let port = match after.split_first() {
            None => &[][..],
            Some((b':', p)) => p,
            _ => return None,
        };
        (&auth[1..close], port)
    } else if auth.iter().filter(|&&b| b == b':').count() == 1 {
        let c = auth.iter().position(|&b| b == b':')?;
        (&auth[..c], &auth[c + 1..])
    } else {
        (auth, &[][..])
    };
    // An unparseable or out-of-range port does NOT drop the host: classify it
    // with port None. Otherwise `127.0.0.1:99999` (out of u16 range) or a
    // leading-zero port would fail the whole parse and slip the host past the
    // check (round-5). The port only narrows the match; the host is what must
    // not be lost.
    let port = std::str::from_utf8(port_s).ok().and_then(|s| s.parse::<u16>().ok());
    // Zone-id only exists on IPv6; elsewhere `%` is percent-encoding, so never
    // truncate a non-IPv6 name at it.
    let name = match name.iter().position(|&b| b == b'%') {
        Some(z) if name.contains(&b':') => &name[..z],
        _ => name,
    };
    let mut name = name.to_ascii_lowercase();
    while name.last() == Some(&b'.') {
        name.pop();
    }
    if name.is_empty() {
        return None;
    }
    Some(Host { scheme, name, port, suspicious })
}

/// Where a URL is about to be used, for the egress-scheme policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemeCtx {
    /// A `curl_exec` target (or a redirect hop): anything but `http`/`https`
    /// is refused, because libcurl is purely an egress tool (`file://` reads a
    /// local file, `gopher://` / `dict://` smuggle raw bytes to an internal
    /// service).
    Curl,
    /// A URL handed to `file_get_contents` / `fopen` / `get_headers`: only the
    /// remote (network) wrappers are refused. Local wrappers (`file`, `php`,
    /// `data`, `glob`, `zip`, `compress.*`) are not egress and are left alone;
    /// `phar` is the phar sink's job.
    Stream,
}

/// Schemes libcurl speaks (or that a PHP wrapper extension may add) that are
/// not HTTP(S). The label is what the log carries: a category, never the URL.
const CURL_SCHEMES: &[&str] = &[
    "file", "gopher", "gophers", "dict", "ldap", "ldaps", "tftp", "ftp", "ftps", "sftp", "scp",
    "telnet", "smb", "smbs", "imap", "imaps", "pop3", "pop3s", "smtp", "smtps", "rtsp", "rtmp",
    "rtmps", "mqtt", "ws", "wss",
];

/// libcurl guesses the protocol of a scheme-less URL from the host's first
/// label (`ftp.example.com` is FTP). Those host prefixes and their labels.
const GUESS_PREFIXES: &[(&str, &str)] = &[
    ("ftp.", "guessed-ftp"),
    ("dict.", "guessed-dict"),
    ("ldap.", "guessed-ldap"),
    ("imap.", "guessed-imap"),
    ("smtp.", "guessed-smtp"),
    ("pop3.", "guessed-pop3"),
    ("gopher.", "guessed-gopher"),
];

fn known_label(s: &[u8]) -> &'static str {
    CURL_SCHEMES.iter().copied().find(|k| k.as_bytes() == s).unwrap_or("other")
}

/// Category label of an egress scheme the policy refuses, or `None` when the
/// URL is allowed (HTTP(S), or no scheme where the context does not guess).
///
/// A scheme is the leading `alpha *(alnum / + / - / .)` run followed by `:/`;
/// `host:port` (a colon then a digit) is not a scheme. For [`SchemeCtx::Curl`]
/// a scheme-less URL is judged by libcurl's host-prefix protocol guess. This is
/// a first line only: in `block` mode the C glue also sets `CURLOPT_PROTOCOLS`
/// so libcurl itself refuses anything a parser difference lets through.
pub fn denied_scheme(url: &[u8], ctx: SchemeCtx) -> Option<&'static str> {
    let u = url.trim_ascii_start();
    let n = u
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        .count();
    if n > 0 && u[0].is_ascii_alphabetic() && u.get(n) == Some(&b':') && u.get(n + 1) == Some(&b'/')
    {
        let s = u[..n].to_ascii_lowercase();
        if s == b"http" || s == b"https" {
            return None;
        }
        return match ctx {
            SchemeCtx::Curl => Some(known_label(&s)),
            SchemeCtx::Stream => {
                if s.starts_with(b"ssh2.") {
                    return Some("ssh2");
                }
                // Not egress / not ours: leave local wrappers and phar alone.
                match known_label(&s) {
                    "other" | "file" | "ws" | "wss" => None,
                    k => Some(k),
                }
            }
        };
    }
    if ctx == SchemeCtx::Curl {
        let end = u
            .iter()
            .position(|&b| matches!(b, b'/' | b'?' | b'#' | b':' | b'\\'))
            .unwrap_or(u.len());
        let host = u[..end].to_ascii_lowercase();
        for (p, label) in GUESS_PREFIXES {
            if host.starts_with(p.as_bytes()) {
                return Some(label);
            }
        }
    }
    None
}

/// Default port for the scheme-less / `http` / `https` URLs the resolve pin
/// covers.
fn pin_port(h: &Host) -> Option<u16> {
    match h.scheme {
        None | Some(Scheme::Http) => Some(h.port.unwrap_or(80)),
        Some(Scheme::Https) => Some(h.port.unwrap_or(443)),
        _ => None,
    }
}

/// Build a `CURLOPT_RESOLVE` entry (`host:port:ip[,ip...]`) that pins the URL's
/// hostname to the validated IPv4 addresses in `recs` (17-byte records), so
/// libcurl connects to exactly what was checked instead of re-resolving
/// (DNS rebinding). `multi` allows a comma list (libcurl 7.59+); otherwise only
/// the first address is pinned. `None` when there is nothing safe to pin: a
/// literal-IP host (no DNS to rebind), a non-HTTP(S) URL, an IPv6-only or
/// unresolved host, or a name carrying anything but hostname characters (which
/// libcurl would also spell differently).
pub fn resolve_pin_entry(url: &[u8], recs: &[u8], multi: bool) -> Option<String> {
    let h = parse_host(url, HostForm::BareHostOk)?;
    let port = pin_port(&h)?;
    if decode_literal_ip(&h.name).is_some()
        || h.name.contains(&b':')
        || !h.name.iter().all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    let mut ips: Vec<String> = Vec::new();
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)] // as_chunks needs Rust 1.88+
    for r in recs.chunks_exact(17) {
        if r[0] == 4 && ips.len() < 8 {
            let s = format!("{}.{}.{}.{}", r[1], r[2], r[3], r[4]);
            if !ips.contains(&s) {
                ips.push(s);
            }
        }
    }
    if ips.is_empty() {
        return None;
    }
    if !multi {
        ips.truncate(1);
    }
    Some(format!("{}:{}:{}", String::from_utf8_lossy(&h.name), port, ips.join(",")))
}

/// Raw IP address bytes (no `std::net`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRepr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// One `inet_aton` component: `0x` hex, leading-`0` octal, else decimal.
fn aton_part(p: &[u8]) -> Option<u64> {
    let (digits, radix) = match p {
        [b'0', b'x' | b'X', rest @ ..] => (rest, 16),
        [b'0', rest @ ..] if !rest.is_empty() => (rest, 8),
        _ => (p, 10),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for &b in digits {
        let d = (b as char).to_digit(radix)? as u64;
        v = v * radix as u64 + d;
        if v > u32::MAX as u64 {
            return None;
        }
    }
    Some(v)
}

fn decode_v4(host: &[u8]) -> Option<[u8; 4]> {
    let parts: Vec<&[u8]> = host.split(|&b| b == b'.').collect();
    if parts.len() > 4 {
        return None;
    }
    let n = parts.len();
    let mut val: u64 = 0;
    for (i, p) in parts.iter().enumerate() {
        let v = aton_part(p)?;
        if i + 1 < n {
            if v > 255 {
                return None;
            }
            val |= v << (8 * (3 - i));
        } else {
            if v >= 1u64 << (8 * (5 - n)) {
                return None;
            }
            val |= v;
        }
    }
    Some((val as u32).to_be_bytes())
}

fn v6_groups(s: &[u8], last_may_be_v4: bool, out: &mut Vec<u16>) -> Option<()> {
    if s.is_empty() {
        return Some(());
    }
    let toks: Vec<&[u8]> = s.split(|&b| b == b':').collect();
    for (i, t) in toks.iter().enumerate() {
        if t.contains(&b'.') {
            if !(last_may_be_v4 && i + 1 == toks.len()) {
                return None;
            }
            let v = decode_v4(t)?;
            out.push(u16::from_be_bytes([v[0], v[1]]));
            out.push(u16::from_be_bytes([v[2], v[3]]));
        } else {
            if t.is_empty() || t.len() > 4 {
                return None;
            }
            let mut g = 0u16;
            for &b in t.iter() {
                g = (g << 4) | (b as char).to_digit(16)? as u16;
            }
            out.push(g);
        }
    }
    Some(())
}

fn decode_v6(host: &[u8]) -> Option<[u8; 16]> {
    let host = match host.iter().position(|&b| b == b'%') {
        Some(z) => &host[..z],
        None => host,
    };
    let (head, tail, compressed) = match find_sub(host, b"::") {
        Some(i) => {
            let t = &host[i + 2..];
            if find_sub(t, b"::").is_some() {
                return None;
            }
            (&host[..i], t, true)
        }
        None => (host, &host[..0], false),
    };
    let (mut h, mut t) = (Vec::new(), Vec::new());
    v6_groups(head, !compressed, &mut h)?;
    v6_groups(tail, true, &mut t)?;
    let total = h.len() + t.len();
    if (compressed && total > 7) || (!compressed && total != 8) {
        return None;
    }
    let mut all = h;
    all.extend(std::iter::repeat_n(0u16, 8 - total));
    all.extend(t);
    let mut out = [0u8; 16];
    for (i, g) in all.iter().enumerate() {
        out[2 * i..2 * i + 2].copy_from_slice(&g.to_be_bytes());
    }
    Some(out)
}

/// Decode a literal IP host: glibc `inet_aton` forms (dotted, decimal dword,
/// octal, hex, short `a.b` / `a.b.c`) or plain/bracketed IPv6.
pub fn decode_literal_ip(host: &[u8]) -> Option<IpRepr> {
    let host = match host {
        [b'[', inner @ .., b']'] => inner,
        _ => host,
    };
    if host.is_empty() {
        return None;
    }
    if host.contains(&b':') {
        decode_v6(host).map(IpRepr::V6)
    } else {
        decode_v4(host).map(IpRepr::V4)
    }
}

/// Reserved / internal address classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservedClass {
    Loopback,
    Unspecified,
    Rfc1918,
    Cgnat,
    LinkLocal,
    Metadata,
    UniqueLocal,
    Benchmarking,
}

impl ReservedClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            ReservedClass::Loopback => "loopback",
            ReservedClass::Unspecified => "unspecified",
            ReservedClass::Rfc1918 => "rfc1918",
            ReservedClass::Cgnat => "cgnat",
            ReservedClass::LinkLocal => "link_local",
            ReservedClass::Metadata => "metadata",
            ReservedClass::UniqueLocal => "unique_local",
            ReservedClass::Benchmarking => "benchmarking",
        }
    }
}

fn classify_v4(a: [u8; 4]) -> Option<ReservedClass> {
    use ReservedClass::*;
    match a {
        [127, ..] => Some(Loopback),
        [0, ..] => Some(Unspecified),
        [10, ..] => Some(Rfc1918),
        [172, b, ..] if (16..=31).contains(&b) => Some(Rfc1918),
        [192, 168, ..] => Some(Rfc1918),
        [100, b, ..] if (64..=127).contains(&b) => Some(Cgnat),
        [169, 254, 169, 254] => Some(Metadata),
        [169, 254, ..] => Some(LinkLocal),
        [198, 18 | 19, ..] => Some(Benchmarking),
        _ => None,
    }
}

fn is_v4_mapped(a: &[u8; 16]) -> bool {
    a[..10].iter().all(|&b| b == 0) && a[10] == 0xff && a[11] == 0xff
}

/// Classify an address; `None` means not reserved. IPv4-mapped
/// (`::ffff:0:0/96`) and NAT64 (`64:ff9b::/96`) unwrap to the embedded v4.
pub fn classify_ip(ip: IpRepr) -> Option<ReservedClass> {
    use ReservedClass::*;
    let a = match ip {
        IpRepr::V4(a) => return classify_v4(a),
        IpRepr::V6(a) => a,
    };
    let v4 = [a[12], a[13], a[14], a[15]];
    if is_v4_mapped(&a) {
        return classify_v4(v4);
    }
    if a[..4] == [0x00, 0x64, 0xff, 0x9b] && a[4..12].iter().all(|&b| b == 0) {
        return classify_v4(v4);
    }
    if a == [0u8; 16] {
        return Some(Unspecified);
    }
    if a[..15].iter().all(|&b| b == 0) && a[15] == 1 {
        return Some(Loopback);
    }
    // AWS IMDSv6: fd00:ec2::254
    if a[..4] == [0xfd, 0x00, 0x0e, 0xc2]
        && a[4..14].iter().all(|&b| b == 0)
        && a[14..] == [0x02, 0x54]
    {
        return Some(Metadata);
    }
    if a[0] & 0xfe == 0xfc {
        return Some(UniqueLocal);
    }
    if a[0] == 0xfe && a[1] & 0xc0 == 0x80 {
        return Some(LinkLocal);
    }
    // 2001:2::/48 benchmarking (RFC 5180)
    if a[..6] == [0x20, 0x01, 0x00, 0x02, 0x00, 0x00] {
        return Some(Benchmarking);
    }
    None
}

/// Strip an IPv4-mapped v6 address down to v4 for comparisons.
fn norm(ip: IpRepr) -> IpRepr {
    match ip {
        IpRepr::V6(a) if is_v4_mapped(&a) => IpRepr::V4([a[12], a[13], a[14], a[15]]),
        other => other,
    }
}

/// Exactly four decimal octets, no leading zeros (which inet_aton reads as octal).
fn strict_dotted_quad(s: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut n = 0;
    for part in s.split(|&b| b == b'.') {
        if n == 4
            || part.is_empty()
            || part.len() > 3
            || (part.len() > 1 && part[0] == b'0')
            || !part.iter().all(u8::is_ascii_digit)
        {
            return None;
        }
        let v: u16 = std::str::from_utf8(part).ok()?.parse().ok()?;
        out[n] = u8::try_from(v).ok()?;
        n += 1;
    }
    (n == 4).then_some(out)
}

/// Parse `ip/prefix` with an in-range prefix length.
pub(crate) fn parse_cidr(entry: &str) -> Option<(IpRepr, u8)> {
    let (ip, pfx) = entry.split_once('/')?;
    if pfx.is_empty() || pfx.len() > 3 || !pfx.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let p: u8 = pfx.parse().ok()?;
    // Strict network address: the permissive inet_aton forms would make
    // `10/8` silently mean 0.0.0.10/8, weakening the operator's intent.
    let ip = if ip.contains(':') {
        decode_literal_ip(ip.as_bytes())?
    } else {
        IpRepr::V4(strict_dotted_quad(ip.as_bytes())?)
    };
    let max = if matches!(ip, IpRepr::V4(_)) { 32 } else { 128 };
    (p <= max).then_some((ip, p))
}

fn bits_match(n: &[u8], i: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    let rem = prefix % 8;
    if n[..full] != i[..full] {
        return false;
    }
    rem == 0 || {
        let mask = 0xffu8 << (8 - rem);
        n[full] & mask == i[full] & mask
    }
}

pub(crate) fn cidr_contains(net: IpRepr, prefix: u8, ip: IpRepr) -> bool {
    // A v4-mapped v6 net with prefix >= 96 is really a v4 net (prefix - 96).
    // Never normalize the net otherwise: the prefix must stay within its width.
    let (net, prefix) = match net {
        IpRepr::V6(a) if prefix >= 96 && is_v4_mapped(&a) => {
            (IpRepr::V4([a[12], a[13], a[14], a[15]]), prefix - 96)
        }
        other => (other, prefix),
    };
    match (net, ip) {
        (IpRepr::V4(n), ip) => match norm(ip) {
            IpRepr::V4(i) => bits_match(&n, &i, prefix),
            IpRepr::V6(_) => false,
        },
        (IpRepr::V6(n), IpRepr::V6(i)) => bits_match(&n, &i, prefix),
        _ => false,
    }
}

/// True iff `host` (hostname: exact, ASCII-case-insensitive, no wildcards),
/// the `literal` IP, or any `resolved` IP matches an allow entry (hostname,
/// literal IP, or CIDR).
pub fn host_allowed(
    host: &[u8],
    resolved: &[IpRepr],
    literal: Option<IpRepr>,
    allow: &[String],
) -> bool {
    // Name-based trust: the operator allowlisted this hostname by name. (The
    // `rebind` knob is the resolve-time defence for a name that answers internal.)
    let name_allowed = allow.iter().any(|e| {
        !e.is_empty()
            && !e.contains('/')
            && decode_literal_ip(e.as_bytes()).is_none()
            && e.as_bytes().eq_ignore_ascii_case(host)
    });
    if name_allowed {
        return true;
    }
    // IP-based: EVERY resolved/literal address must be covered by an IP or CIDR
    // allow entry. Requiring all, not any, stops an attacker-controlled name
    // that resolves to [an allowed address, 169.254.169.254] from passing while
    // PHP connects to the internal one (F6).
    let covers = |ip: IpRepr| {
        allow.iter().any(|e| {
            if e.contains('/') {
                matches!(parse_cidr(e), Some((net, p)) if cidr_contains(net, p, ip))
            } else {
                matches!(decode_literal_ip(e.as_bytes()), Some(x) if norm(x) == norm(ip))
            }
        })
    };
    let mut ips = resolved.iter().copied().chain(literal).peekable();
    ips.peek().is_some() && ips.all(covers)
}

/// True iff `entry` is a well-formed `allow_hosts` entry: a non-empty,
/// whitespace-free hostname, a literal IP, or a CIDR with an in-range prefix.
pub fn valid_allow_entry(entry: &str) -> bool {
    // Wildcards are unsupported; reject rather than let them silently never match.
    if entry.is_empty() || entry.bytes().any(|b| b.is_ascii_whitespace() || b == b'*') {
        return false;
    }
    if entry.contains('/') {
        return parse_cidr(entry).is_some();
    }
    if entry.contains(':') {
        return decode_literal_ip(entry.as_bytes()).is_some();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ReservedClass::*;

    fn cls(h: &str) -> Option<ReservedClass> {
        classify_ip(decode_literal_ip(h.as_bytes()).unwrap())
    }
    fn ph(s: &str, f: HostForm) -> Option<Host> {
        parse_host(s.as_bytes(), f)
    }
    fn al(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn decode_dword() {
        assert_eq!(cls("2130706433"), Some(Loopback));
        assert_eq!(cls("3232235777"), Some(Rfc1918));
    }
    #[test]
    fn decode_octal_hex() {
        assert_eq!(cls("0177.0.0.1"), Some(Loopback));
        assert_eq!(cls("0x7f.0.0.1"), Some(Loopback));
        assert_eq!(cls("0x7f000001"), Some(Loopback));
        assert_eq!(cls("0xA9.0xFE.0xA9.0xFE"), Some(Metadata));
    }
    #[test]
    fn decode_short_form() {
        assert_eq!(cls("127.1"), Some(Loopback));
        assert_eq!(cls("10.1.2"), Some(Rfc1918));
        assert!(decode_literal_ip(b"1.2.3.4.5").is_none());
        assert!(decode_literal_ip(b"256.1.1.1").is_none());
        assert!(decode_literal_ip(b"example.com").is_none());
    }
    #[test]
    fn decode_zero_is_unspecified() {
        assert_eq!(cls("0"), Some(Unspecified));
        assert_eq!(cls("0.0.0.0"), Some(Unspecified));
        assert_eq!(cls("::"), Some(Unspecified));
    }
    #[test]
    fn ipv4_mapped_v6_unwraps() {
        assert_eq!(cls("::ffff:127.0.0.1"), Some(Loopback));
        assert_eq!(cls("[::ffff:7f00:1]"), Some(Loopback));
        assert_eq!(cls("::ffff:8.8.8.8"), None);
        assert_eq!(cls("::1"), Some(Loopback));
    }
    #[test]
    fn nat64_unwraps() {
        assert_eq!(cls("64:ff9b::a9fe:a9fe"), Some(Metadata));
        assert_eq!(cls("64:ff9b::10.0.0.1"), Some(Rfc1918));
        assert_eq!(cls("64:ff9b::8.8.8.8"), None);
    }
    #[test]
    fn metadata_beats_linklocal() {
        assert_eq!(cls("169.254.169.254"), Some(Metadata));
        assert_eq!(cls("169.254.1.1"), Some(LinkLocal));
        assert_eq!(cls("fd00:ec2::254"), Some(Metadata));
        assert_eq!(cls("fe80::1"), Some(LinkLocal));
        assert_eq!(cls("fd12::1"), Some(UniqueLocal));
        assert_eq!(cls("100.64.0.1"), Some(Cgnat));
        assert_eq!(cls("198.18.0.1"), Some(Benchmarking));
        assert_eq!(cls("172.16.0.1"), Some(Rfc1918));
        assert_eq!(cls("172.32.0.1"), None);
    }
    #[test]
    fn classify_public_is_none() {
        assert_eq!(cls("8.8.8.8"), None);
        assert_eq!(cls("2606:4700::1111"), None);
    }
    #[test]
    fn parse_strips_userinfo() {
        let h = ph(
            "http://user:pw@Example.com:8080/x?y",
            HostForm::SchemeRequired,
        )
        .unwrap();
        assert_eq!(h.name, b"example.com");
        assert_eq!(h.port, Some(8080));
        assert_eq!(h.scheme, Some(Scheme::Http));
        let h = ph("http://good.com@127.0.0.1/", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"127.0.0.1");
    }
    #[test]
    fn parse_host_after_backslash_userinfo() {
        // F2: PHP/curl keep `\` in the userinfo and take the host after the last
        // `@`, so the authority must not terminate at `\`.
        let h = ph("http://public.example\\@127.0.0.1/x", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"127.0.0.1");
        let h = ph("http://public.example\\@169.254.169.254/latest", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"169.254.169.254");
    }
    #[test]
    fn parse_flags_nul_in_authority_suspicious() {
        // A NUL anywhere in the authority is suspicious: libc stops at it while
        // PHP's URL parser keeps the userinfo, so the two can resolve to
        // different hosts. Both `public\0@127.0.0.1` (URL-view internal) and its
        // mirror `127.0.0.1\0@public` (libc-view internal) are caught, along
        // with host-, port- and bracket-embedded NULs.
        for s in [
            "http://127.0.0.1\0.example.com/",
            "127.0.0.1\0.evil.com",
            "http://127.0.0.1:80\0x/",
            "http://public\0@127.0.0.1/",
            "http://127.0.0.1\0@public/",
            "http://[::1\0]/",
            "http://127.0.0.1\0:99999/",
            "http://[::1]\0:80/",
        ] {
            let form = if s.starts_with("http") { HostForm::SchemeRequired } else { HostForm::BareHostOk };
            assert!(ph(s, form).is_some_and(|h| h.suspicious), "not suspicious: {s:?}");
        }
        // The host is still cut for non-range consumers (scheme/guess-prefix).
        assert_eq!(ph("127.0.0.1\0.evil.com", HostForm::BareHostOk).unwrap().name, b"127.0.0.1");
        // A NUL-free authority is NOT suspicious.
        assert!(!ph("http://127.0.0.1/", HostForm::SchemeRequired).unwrap().suspicious);
        assert!(!ph("http://example.com:8080/", HostForm::SchemeRequired).unwrap().suspicious);
    }
    #[test]
    fn parse_bare_host_with_invalid_scheme() {
        // Re-review (2b): `host:port://path` is not a scheme (`:` is not a
        // scheme char), and curl connects to the host:port, so a bare host
        // classifies it rather than returning None (fail-open).
        let h = ph("127.0.0.1:80://x", HostForm::BareHostOk).unwrap();
        assert_eq!(h.name, b"127.0.0.1");
        assert_eq!(h.port, Some(80));
        // A stream URL with an invalid scheme is still rejected.
        assert!(ph("127.0.0.1:80://x", HostForm::SchemeRequired).is_none());
    }
    #[test]
    fn parse_bad_port_still_classifies_host() {
        // Round-5: an out-of-range or garbage port must not drop the host (that
        // would fail open on the range check); classify it with port None.
        let h = ph("http://127.0.0.1:99999/", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"127.0.0.1");
        assert_eq!(h.port, None);
        let h = ph("127.0.0.1:8080abc", HostForm::BareHostOk).unwrap();
        assert_eq!(h.name, b"127.0.0.1");
        assert_eq!(h.port, None);
        // A leading-zero port (libcurl accepts it) still parses.
        assert_eq!(ph("http://127.0.0.1:000080/", HostForm::SchemeRequired).unwrap().port, Some(80));
        // A valid port still parses.
        assert_eq!(ph("http://127.0.0.1:8080/", HostForm::SchemeRequired).unwrap().port, Some(8080));
    }
    #[test]
    fn parse_strips_zone_and_trailing_dot() {
        let h = ph("http://[fe80::1%eth0]:80/", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"fe80::1");
        assert_eq!(h.port, Some(80));
        let h = ph("https://Example.COM./", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"example.com");
    }
    #[test]
    fn parse_rejects_relative_filename_when_scheme_required() {
        assert!(ph("/etc/passwd", HostForm::SchemeRequired).is_none());
        assert!(ph("./a.txt", HostForm::BareHostOk).is_none());
        assert!(ph("../a", HostForm::BareHostOk).is_none());
        assert!(ph("file.txt", HostForm::SchemeRequired).is_none());
    }
    #[test]
    fn parse_accepts_schemeless_curl_host() {
        let h = ph("localhost:8080/admin", HostForm::BareHostOk).unwrap();
        assert_eq!(h.name, b"localhost");
        assert_eq!(h.port, Some(8080));
        assert_eq!(h.scheme, None);
        assert_eq!(ph("127.1", HostForm::BareHostOk).unwrap().name, b"127.1");
    }
    #[test]
    fn parse_skips_unix_scheme() {
        assert!(ph("unix:///var/run/x.sock", HostForm::BareHostOk).is_none());
        assert!(ph("file:///etc/passwd", HostForm::SchemeRequired).is_none());
    }
    #[test]
    fn parse_peels_unknown_and_nesting_schemes() {
        // F4: a curl scheme classifies the bare host after it.
        let h = ph("dict://127.0.0.1:6379/x", HostForm::BareHostOk).unwrap();
        assert_eq!(h.name, b"127.0.0.1");
        assert_eq!(h.port, Some(6379));
        // A nesting wrapper classifies the inner URL's host.
        let h = ph("compress.zlib://http://169.254.169.254/latest", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"169.254.169.254");
        assert_eq!(h.scheme, Some(Scheme::Http));
        // A non-network wrapper still yields no host.
        assert!(ph("file:///etc/passwd", HostForm::SchemeRequired).is_none());
    }
    #[test]
    fn cidr_allow_matches() {
        let a = al(&["10.0.0.0/8", "fd00::/8"]);
        let v4 = IpRepr::V4([10, 1, 2, 3]);
        assert!(host_allowed(b"x", &[v4], None, &a));
        assert!(host_allowed(b"x", &[], Some(v4), &a));
        assert!(!host_allowed(b"x", &[IpRepr::V4([11, 0, 0, 1])], None, &a));
        assert!(host_allowed(
            b"x",
            &[decode_literal_ip(b"fd12::1").unwrap()],
            None,
            &a
        ));
        assert!(host_allowed(
            b"x",
            &[IpRepr::V4([9, 9, 9, 9])],
            None,
            &al(&["0.0.0.0/0"])
        ));
        assert!(host_allowed(
            b"x",
            &[IpRepr::V4([1, 2, 3, 4])],
            None,
            &al(&["1.2.3.4"])
        ));
        assert!(host_allowed(
            b"x",
            &[IpRepr::V4([1, 2, 3, 5])],
            None,
            &al(&["1.2.3.4/30"])
        ));
        assert!(!host_allowed(
            b"x",
            &[IpRepr::V4([1, 2, 3, 8])],
            None,
            &al(&["1.2.3.4/30"])
        ));
    }
    #[test]
    fn allow_requires_every_resolved_ip() {
        // F6: a name resolving to [allowed, internal] is NOT allowed by an
        // IP/CIDR allowlist (PHP could connect to the internal address).
        let good = IpRepr::V4([8, 8, 8, 8]);
        let meta = IpRepr::V4([169, 254, 169, 254]);
        assert!(host_allowed(b"x", &[good], None, &al(&["8.8.8.8"])));
        assert!(!host_allowed(b"x", &[good, meta], None, &al(&["8.8.8.8"])));
        assert!(!host_allowed(b"x", &[good, meta], None, &al(&["0.0.0.0/1"])));
        // A hostname allow entry still trusts the name regardless of its IPs.
        assert!(host_allowed(b"trusted.example", &[good, meta], None, &al(&["trusted.example"])));
    }
    #[test]
    fn cidr_rejects_bad_prefixlen() {
        assert!(valid_allow_entry("10.0.0.0/8"));
        assert!(valid_allow_entry("::/0"));
        assert!(valid_allow_entry("fd00::/128"));
        assert!(!valid_allow_entry("10.0.0.0/33"));
        assert!(!valid_allow_entry("fd00::/129"));
        assert!(!valid_allow_entry("10.0.0.0/"));
        assert!(!valid_allow_entry("10.0.0.0/-1"));
        assert!(!valid_allow_entry("nonsense/8"));
        assert!(!valid_allow_entry(""));
        assert!(!valid_allow_entry("a b"));
        assert!(valid_allow_entry("api.example.com"));
        let bad = al(&["10.0.0.0/33"]);
        assert!(!host_allowed(
            b"x",
            &[IpRepr::V4([10, 0, 0, 1])],
            None,
            &bad
        ));
    }
    #[test]
    fn hostname_allow_ci_no_wildcard() {
        let a = al(&["API.example.com", "*.corp.com"]);
        assert!(host_allowed(b"api.example.com", &[], None, &a));
        assert!(!host_allowed(b"x.corp.com", &[], None, &a));
        assert!(!host_allowed(b"evil.api.example.com", &[], None, &a));
    }
    #[test]
    fn cidr_mapped_v6_net_no_panic() {
        let v4 = IpRepr::V4([10, 1, 2, 3]);
        let a = al(&["::ffff:10.0.0.0/104"]);
        assert!(valid_allow_entry("::ffff:10.0.0.0/104"));
        assert!(host_allowed(b"x", &[v4], None, &a));
        assert!(!host_allowed(b"x", &[IpRepr::V4([11, 0, 0, 1])], None, &a));
        let a = al(&["::ffff:0:0/96"]);
        assert!(host_allowed(b"x", &[v4], None, &a));
        let a = al(&["::ffff:0:0/80"]);
        assert!(host_allowed(
            b"x",
            &[decode_literal_ip(b"::1").unwrap()],
            None,
            &a
        ));
        let a = al(&["::ffff:0:0/128"]);
        assert!(!host_allowed(b"x", &[IpRepr::V4([1, 1, 1, 1])], None, &a));
    }
    #[test]
    fn parse_barehost_with_url_in_query() {
        let h = ph("127.0.0.1/?u=http://x", HostForm::BareHostOk).unwrap();
        assert_eq!(h.name, b"127.0.0.1");
        assert_eq!(h.scheme, None);
        assert!(ph("127.0.0.1/?u=http://x", HostForm::SchemeRequired).is_none());
    }
    #[test]
    fn parse_percent_encoded_host_not_dropped() {
        assert!(ph("http://%31%32%37.0.0.1/", HostForm::SchemeRequired).is_some());
        let h = ph("http://[fe80::1%25eth0]/", HostForm::SchemeRequired).unwrap();
        assert_eq!(h.name, b"fe80::1");
    }
    #[test]
    fn reserved_extras() {
        assert_eq!(cls("0.1.2.3"), Some(Unspecified));
        assert_eq!(cls("2001:2::1"), Some(Benchmarking));
    }
    #[test]
    fn valid_allow_entry_rejects_wildcard() {
        assert!(!valid_allow_entry("*.corp.com"));
        assert!(!valid_allow_entry("*"));
    }
    #[test]
    fn cidr_requires_strict_address() {
        assert!(!valid_allow_entry("10/8"));
        assert!(!valid_allow_entry("0x0a.0.0.0/8"));
        assert!(!valid_allow_entry("167772160/8"));
        assert!(!valid_allow_entry("010.0.0.0/8"));
        assert!(!valid_allow_entry("10.0.0/8"));
        assert!(valid_allow_entry("10.0.0.0/8"));
        assert!(!host_allowed(
            b"x",
            &[IpRepr::V4([10, 0, 0, 1])],
            None,
            &al(&["10/8"])
        ));
    }
    fn ds(u: &str, c: SchemeCtx) -> Option<&'static str> {
        denied_scheme(u.as_bytes(), c)
    }

    #[test]
    fn curl_scheme_allows_only_http_https() {
        use SchemeCtx::Curl;
        for ok in [
            "http://example.com/",
            "HTTPS://example.com/x?y=gopher://z",
            "  https://example.com",
            "example.com/path",
            "example.com:8080/path",
            "localhost:8080",
            "127.0.0.1:80",
            "//cdn.example.com/x",
            "/relative/path",
            "ftpserver.example.com", // no dot after ftp: not the ftp. guess
        ] {
            assert_eq!(ds(ok, Curl), None, "{ok}");
        }
        for (bad, label) in [
            ("gopher://127.0.0.1:70/_x", "gopher"),
            ("GOPHER://127.0.0.1/", "gopher"),
            ("dict://127.0.0.1:11211/info", "dict"),
            ("file:///etc/passwd", "file"),
            ("file:/etc/passwd", "file"),
            ("ldap://127.0.0.1/", "ldap"),
            ("tftp://127.0.0.1/x", "tftp"),
            ("ftp://127.0.0.1/", "ftp"),
            ("  sftp://h/x", "sftp"),
            ("smtp://127.0.0.1:25/", "smtp"),
            ("weird+scheme://h/", "other"),
            ("ftp.example.com/x", "guessed-ftp"),
            ("DICT.example.com", "guessed-dict"),
            ("ldap.example.com:389", "guessed-ldap"),
        ] {
            assert_eq!(ds(bad, Curl), Some(label), "{bad}");
        }
    }

    #[test]
    fn stream_scheme_denies_only_remote_wrappers() {
        use SchemeCtx::Stream;
        for ok in [
            "http://example.com/",
            "https://example.com/",
            "file:///etc/hostname",
            "php://temp",
            "php://input",
            "data:text/plain,hi",
            "data://text/plain;base64,aGk=",
            "glob:///tmp/*",
            "zip:///tmp/a.zip#b",
            "compress.zlib:///tmp/a.gz",
            "phar:///tmp/a.phar/x", // the phar sink's job
            "expect://id",          // the include/open firewall's job
            "/tmp/plain.txt",
            "plain.txt",
            "ws://host/",
        ] {
            assert_eq!(ds(ok, Stream), None, "{ok}");
        }
        for (bad, label) in [
            ("ftp://127.0.0.1/x", "ftp"),
            ("FTPS://h/x", "ftps"),
            ("gopher://h/", "gopher"),
            ("dict://h/", "dict"),
            ("ldap://h/", "ldap"),
            ("tftp://h/", "tftp"),
            ("sftp://h/", "sftp"),
            ("ssh2.sftp://u:p@h/x", "ssh2"),
            ("ssh2.tunnel://h:22", "ssh2"),
        ] {
            assert_eq!(ds(bad, Stream), Some(label), "{bad}");
        }
        // Stream context never guesses a protocol from a scheme-less host.
        assert_eq!(ds("ftp.example.com/x", Stream), None);
    }

    fn rec4(a: [u8; 4]) -> [u8; 17] {
        let mut r = [0u8; 17];
        r[0] = 4;
        r[1..5].copy_from_slice(&a);
        r
    }
    fn rec6(a: [u8; 16]) -> [u8; 17] {
        let mut r = [0u8; 17];
        r[0] = 6;
        r[1..].copy_from_slice(&a);
        r
    }

    #[test]
    fn pin_entry_builds_host_port_ip() {
        let mut recs = Vec::new();
        recs.extend_from_slice(&rec4([93, 184, 216, 34]));
        assert_eq!(
            resolve_pin_entry(b"http://Example.COM/x?y", &recs, false).as_deref(),
            Some("example.com:80:93.184.216.34")
        );
        assert_eq!(
            resolve_pin_entry(b"https://example.com/", &recs, false).as_deref(),
            Some("example.com:443:93.184.216.34")
        );
        assert_eq!(
            resolve_pin_entry(b"example.com:8080/p", &recs, false).as_deref(),
            Some("example.com:8080:93.184.216.34")
        );
        assert_eq!(
            resolve_pin_entry(b"http://user:pw@example.com:81/", &recs, false).as_deref(),
            Some("example.com:81:93.184.216.34")
        );
    }

    #[test]
    fn pin_entry_multi_and_v6_filtering() {
        let mut recs = Vec::new();
        recs.extend_from_slice(&rec6([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]));
        recs.extend_from_slice(&rec4([1, 2, 3, 4]));
        recs.extend_from_slice(&rec4([5, 6, 7, 8]));
        recs.extend_from_slice(&rec4([1, 2, 3, 4])); // duplicate dropped
        let single = resolve_pin_entry(b"http://h.example/", &recs, false).unwrap();
        assert_eq!(single, "h.example:80:1.2.3.4");
        let multi = resolve_pin_entry(b"http://h.example/", &recs, true).unwrap();
        assert_eq!(multi, "h.example:80:1.2.3.4,5.6.7.8");
        // IPv6-only: nothing safe to pin.
        let v6only = rec6([0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(resolve_pin_entry(b"http://h.example/", &v6only, true), None);
    }

    #[test]
    fn pin_entry_refuses_unpinnable_targets() {
        let recs = rec4([1, 2, 3, 4]);
        // Literal IPs resolve nothing, so there is nothing to rebind or pin.
        for lit in ["http://127.0.0.1/", "http://2130706433/", "http://[::1]/", "10.0.0.1:80"] {
            assert_eq!(resolve_pin_entry(lit.as_bytes(), &recs, true), None, "{lit}");
        }
        // Non-HTTP(S) schemes and odd host spellings are never pinned.
        assert_eq!(resolve_pin_entry(b"ftp://h.example/", &recs, true), None);
        assert_eq!(resolve_pin_entry(b"gopher://h.example/", &recs, true), None);
        assert_eq!(resolve_pin_entry(b"http://h%2eexample/", &recs, true), None);
        // No usable address: no pin.
        assert_eq!(resolve_pin_entry(b"http://h.example/", &[], true), None);
    }

    #[test]
    fn reservedclass_as_str_pinned() {
        let all = [
            (Loopback, "loopback"),
            (Unspecified, "unspecified"),
            (Rfc1918, "rfc1918"),
            (Cgnat, "cgnat"),
            (LinkLocal, "link_local"),
            (Metadata, "metadata"),
            (UniqueLocal, "unique_local"),
            (Benchmarking, "benchmarking"),
        ];
        for (c, s) in all {
            assert_eq!(c.as_str(), s);
        }
    }
}
