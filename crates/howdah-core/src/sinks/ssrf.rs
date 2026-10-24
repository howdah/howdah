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
    // `://` is a scheme delimiter only before any `/`, `?` or `#`; otherwise it
    // is part of a path/query (e.g. `127.0.0.1/?u=http://x`) of a bare host.
    let delim = find_sub(input, b"://")
        .filter(|&i| !input[..i].iter().any(|b| matches!(b, b'/' | b'?' | b'#')));
    let (scheme, rest) = match delim {
        Some(i) => {
            let sch = &input[..i];
            if sch.is_empty()
                || !sch
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
            {
                return None;
            }
            (Some(scheme_from(sch)?), &input[i + 3..])
        }
        None => {
            if form == HostForm::SchemeRequired {
                return None;
            }
            (None, input)
        }
    };
    let end = rest
        .iter()
        .position(|b| matches!(b, b'/' | b'?' | b'#' | b'\\'))
        .unwrap_or(rest.len());
    let mut auth = &rest[..end];
    if let Some(at) = auth.iter().rposition(|&b| b == b'@') {
        auth = &auth[at + 1..];
    }
    let (name, port_s): (&[u8], &[u8]) = if auth.first() == Some(&b'[') {
        let close = auth.iter().position(|&b| b == b']')?;
        let after = &auth[close + 1..];
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
    let port = if port_s.is_empty() {
        None
    } else {
        if port_s.len() > 5 || !port_s.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(std::str::from_utf8(port_s).ok()?.parse::<u16>().ok()?)
    };
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
    Some(Host { scheme, name, port })
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
    allow.iter().any(|entry| {
        if entry.is_empty() {
            return false;
        }
        let mut ips = resolved.iter().copied().chain(literal);
        if entry.contains('/') {
            return match parse_cidr(entry) {
                Some((net, p)) => ips.any(|ip| cidr_contains(net, p, ip)),
                None => false,
            };
        }
        if let Some(ip) = decode_literal_ip(entry.as_bytes()) {
            return ips.any(|x| norm(x) == norm(ip));
        }
        entry.as_bytes().eq_ignore_ascii_case(host)
    })
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
