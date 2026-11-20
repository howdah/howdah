//! Phar signature-TYPE classifier (CVE-2026-128090, GHSA-68fq-fh7h-f8gr).
//!
//! PHP's phar verifier takes the signature type from the archive itself. When
//! the owner pinned an OpenSSL public key (a sibling `<archive>.pubkey`), an
//! archive that declares a keyless digest (MD5 / SHA1 / SHA256 / SHA512) skips
//! the key check, so whoever can modify the archive (but not the `.pubkey`) can
//! replace its contents and re-sign with a plain digest. The guard refuses an
//! archive whose declared type is not one of the three OpenSSL types while a
//! `.pubkey` exists.
//!
//! This module only READS the declared 4-byte little-endian flag word; it never
//! verifies a signature and never executes or unpacks anything. It is pure: the
//! caller supplies a bounded random-access reader, so the I/O (plain `pread` in
//! the C glue, no `php_stream` internals) stays out of the core.
//!
//! Where the flag word lives:
//!  * native phar: `<sig bytes><flags u32 LE><"GBMB">` at EOF, so flags are at
//!    `size-8`.
//!  * zip phar: the first 4 bytes of the stored `.phar/signature.bin` entry,
//!    found through the End-Of-Central-Directory record + central directory.
//!  * tar phar: the first 4 bytes of the `.phar/signature.bin` entry, found by
//!    walking the 512-byte tar headers.
//!
//! Ambiguity resolves toward REFUSING: if an archive has several readable
//! interpretations or several signature entries, any keyless one wins. Anything
//! unreadable (whole-archive gzip/bzip2, zip64, deflated signature entry,
//! malformed) is `Indeterminate`, which the caller reports but does not block.

/// `PHAR_SIG_OPENSSL`, `_SHA256`, `_SHA512` (php-src ext/phar, util.c).
const SIG_OPENSSL: u32 = 0x0010;
const SIG_OPENSSL_SHA256: u32 = 0x0011;
const SIG_OPENSSL_SHA512: u32 = 0x0012;

const SIG_ENTRY: &[u8] = b".phar/signature.bin";
const MAX_CD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TAR_ENTRIES: u32 = 50_000;

/// What the archive declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PharSig {
    /// One of the OpenSSL types (flag word attached).
    OpenSsl(u32),
    /// Any other declared type (MD5=1, SHA1=2, SHA256=4, SHA512=8, or garbage).
    Keyless(u32),
    /// Could not be determined: do not guess.
    Indeterminate,
}

pub fn from_flags(flags: u32) -> PharSig {
    match flags {
        SIG_OPENSSL | SIG_OPENSSL_SHA256 | SIG_OPENSSL_SHA512 => PharSig::OpenSsl(flags),
        _ => PharSig::Keyless(flags),
    }
}

/// Reason string when a pinned `.pubkey` meets this signature, or `None` when
/// the archive is fine. `Keyless` with a pubkey is the downgrade
/// (`"signature-downgrade"`, blockable); `Indeterminate` with a pubkey is
/// `"signature-indeterminate"` (the caller logs, never blocks). No pubkey is
/// never a finding: the owner did not ask for key verification.
pub fn verdict(sig: PharSig, pubkey_present: bool) -> Option<&'static str> {
    if !pubkey_present {
        return None;
    }
    match sig {
        PharSig::OpenSsl(_) => None,
        PharSig::Keyless(_) => Some("signature-downgrade"),
        PharSig::Indeterminate => Some("signature-indeterminate"),
    }
}

/// Random-access reader: fill `buf` from absolute offset, true only if every
/// byte was read.
pub type ReadAt<'a> = &'a mut dyn FnMut(u64, &mut [u8]) -> bool;

fn u16le(b: &[u8], o: usize) -> u64 {
    u16::from_le_bytes([b[o], b[o + 1]]) as u64
}
fn u32le(b: &[u8], o: usize) -> u64 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]) as u64
}

fn read_flags(rd: ReadAt, off: u64) -> Option<u32> {
    let mut f = [0u8; 4];
    rd(off, &mut f).then(|| u32::from_le_bytes(f))
}

/// Native: flags are the 4 bytes before the trailing `GBMB`. `None` = not native.
fn native(size: u64, rd: ReadAt) -> Option<u32> {
    if size < 8 {
        return None;
    }
    let mut t = [0u8; 8];
    if !rd(size - 8, &mut t) || &t[4..] != b"GBMB" {
        return None;
    }
    Some(u32::from_le_bytes([t[0], t[1], t[2], t[3]]))
}

/// Zip: all `.phar/signature.bin` flag words found (`Err(())` = zip-looking
/// but unreadable, `Ok(empty)` = not a zip at all).
fn zip(size: u64, rd: ReadAt) -> Result<Vec<u32>, ()> {
    if size < 22 {
        return Ok(Vec::new());
    }
    let tail_len = size.min(22 + 65_535) as usize;
    let tail_off = size - tail_len as u64;
    let mut tail = vec![0u8; tail_len];
    if !rd(tail_off, &mut tail) {
        return Err(());
    }
    // Last EOCD whose comment length reaches exactly EOF.
    let mut eocd = None;
    let mut i = tail_len - 22;
    loop {
        if &tail[i..i + 4] == b"PK\x05\x06" && i + 22 + u16le(&tail, i + 20) as usize == tail_len {
            eocd = Some(i);
            break;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    let Some(e) = eocd else { return Ok(Vec::new()) };
    let eocd_abs = tail_off + e as u64;
    let cd_size = u32le(&tail, e + 12);
    let cd_off = u32le(&tail, e + 16);
    if cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF || u16le(&tail, e + 10) == 0xFFFF {
        return Err(()); // zip64
    }
    if cd_size > MAX_CD_BYTES || cd_size == 0 {
        return Err(());
    }
    // A stub-prefixed zip may carry offsets relative to the zip start.
    let adj = eocd_abs.checked_sub(cd_size).and_then(|x| x.checked_sub(cd_off)).ok_or(())?;
    let mut cd = vec![0u8; cd_size as usize];
    if !rd(cd_off + adj, &mut cd) {
        return Err(());
    }
    let mut out = Vec::new();
    let mut p = 0usize;
    while p + 46 <= cd.len() {
        if &cd[p..p + 4] != b"PK\x01\x02" {
            return Err(());
        }
        let nlen = u16le(&cd, p + 28) as usize;
        let elen = u16le(&cd, p + 30) as usize;
        let clen = u16le(&cd, p + 32) as usize;
        let end = p + 46 + nlen + elen + clen;
        if end > cd.len() {
            return Err(());
        }
        if &cd[p + 46..p + 46 + nlen] == SIG_ENTRY {
            if u16le(&cd, p + 10) != 0 || u32le(&cd, p + 24) < 4 {
                return Err(()); // compressed or too short: not readable
            }
            let lh = u32le(&cd, p + 42) + adj;
            let mut h = [0u8; 30];
            if !rd(lh, &mut h) || &h[..4] != b"PK\x03\x04" {
                return Err(());
            }
            let data = lh + 30 + u16le(&h, 26) + u16le(&h, 28);
            out.push(read_flags(rd, data).ok_or(())?);
        }
        p = end;
    }
    Ok(out)
}

fn tar_octal(f: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    let mut seen = false;
    for &c in f {
        match c {
            b'0'..=b'7' => {
                v = v.checked_mul(8)?.checked_add((c - b'0') as u64)?;
                seen = true;
            }
            b' ' | 0 if !seen => {}
            b' ' | 0 => break,
            _ => return None,
        }
    }
    seen.then_some(v)
}

fn tar_header_ok(h: &[u8; 512]) -> bool {
    let Some(want) = tar_octal(&h[148..156]) else { return false };
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| if (148..156).contains(&i) { 32 } else { b as u64 })
        .sum();
    sum == want
}

/// Tar: all `.phar/signature.bin` flag words (`Ok(empty)` = not a tar).
fn tar(size: u64, rd: ReadAt) -> Result<Vec<u32>, ()> {
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut n = 0u32;
    while off + 512 <= size {
        let mut h = [0u8; 512];
        if !rd(off, &mut h) {
            return Err(());
        }
        if h.iter().all(|&b| b == 0) {
            break;
        }
        if !tar_header_ok(&h) {
            // Not a tar at all (first block) vs corrupt mid-walk.
            return if n == 0 { Ok(Vec::new()) } else { Err(()) };
        }
        n += 1;
        if n > MAX_TAR_ENTRIES {
            return Err(());
        }
        let nlen = h[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let Some(esz) = tar_octal(&h[124..136]) else { return Err(()) };
        if &h[..nlen] == SIG_ENTRY {
            if esz < 4 {
                return Err(());
            }
            out.push(read_flags(rd, off + 512).ok_or(())?);
        }
        off = match off.checked_add(512).and_then(|x| x.checked_add(esz.div_ceil(512).checked_mul(512)?)) {
            Some(x) => x,
            None => return Err(()),
        };
    }
    Ok(out)
}

/// Classify an archive of `size` bytes read through `rd`. See the module docs
/// for the formats and the refuse-on-ambiguity rule.
pub fn classify(size: u64, rd: ReadAt) -> PharSig {
    let mut flags: Vec<u32> = Vec::new();
    let mut unreadable = false;

    let nat = native(size, rd);
    if let Some(f) = nat {
        flags.push(f);
    }
    // Zip: only when it is not already native, or when it also looks zip-headed
    // (a polyglot is judged by every reading).
    let mut head = [0u8; 4];
    let zip_headed = size >= 4 && rd(0, &mut head) && &head == b"PK\x03\x04";
    if nat.is_none() || zip_headed {
        match zip(size, rd) {
            Ok(v) => flags.extend(v),
            Err(()) => unreadable = unreadable || nat.is_none() && zip_headed,
        }
    }
    match tar(size, rd) {
        Ok(v) => flags.extend(v),
        Err(()) => unreadable = true,
    }

    if let Some(&bad) = flags.iter().find(|&&f| matches!(from_flags(f), PharSig::Keyless(_))) {
        return PharSig::Keyless(bad);
    }
    if unreadable && nat.is_none() {
        return PharSig::Indeterminate;
    }
    match flags.first() {
        Some(&f) => from_flags(f),
        None => PharSig::Indeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(bytes: &[u8]) -> PharSig {
        let mut rd = |off: u64, buf: &mut [u8]| {
            let o = off as usize;
            match o.checked_add(buf.len()) {
                Some(e) if e <= bytes.len() => {
                    buf.copy_from_slice(&bytes[o..e]);
                    true
                }
                _ => false,
            }
        };
        classify(bytes.len() as u64, &mut rd)
    }

    fn native_phar(flags: u32) -> Vec<u8> {
        let mut v = b"<?php echo 'ok'; __HALT_COMPILER(); ?>\r\nmanifest-bytes".to_vec();
        v.extend_from_slice(&[0xAB; 32]); // pretend signature
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(b"GBMB");
        v
    }

    fn tar_header(name: &[u8], size: usize) -> [u8; 512] {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[100..107].copy_from_slice(b"0000644");
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h[155] = b' ';
        h
    }

    fn tar_phar(flags: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tar_header(b"index.php", 5));
        let mut blk = b"<?php".to_vec();
        blk.resize(512, 0);
        v.extend_from_slice(&blk);
        let mut sig = flags.to_le_bytes().to_vec();
        sig.extend_from_slice(&[0, 0, 0, 0]);
        sig.extend_from_slice(&[0x5A; 32]);
        v.extend_from_slice(&tar_header(SIG_ENTRY, sig.len()));
        sig.resize(512, 0);
        v.extend_from_slice(&sig);
        v
    }

    fn zip_phar(flags: u32, stub: &[u8], method: u16) -> Vec<u8> {
        let mut v = stub.to_vec();
        let base = v.len() as u32;
        let mut data = flags.to_le_bytes().to_vec();
        data.extend_from_slice(&[0x77; 20]);
        let mut cd = Vec::new();
        for (name, body) in [(&b"index.php"[..], &b"<?php"[..]), (SIG_ENTRY, &data[..])] {
            let lh = v.len() as u32 - base;
            v.extend_from_slice(b"PK\x03\x04");
            v.extend_from_slice(&[20, 0, 0, 0]);
            let m = if name == SIG_ENTRY { method } else { 0 };
            v.extend_from_slice(&m.to_le_bytes());
            v.extend_from_slice(&[0; 8]); // time, date, crc
            v.extend_from_slice(&(body.len() as u32).to_le_bytes());
            v.extend_from_slice(&(body.len() as u32).to_le_bytes());
            v.extend_from_slice(&(name.len() as u16).to_le_bytes());
            v.extend_from_slice(&[0, 0]);
            v.extend_from_slice(name);
            v.extend_from_slice(body);
            cd.extend_from_slice(b"PK\x01\x02");
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&m.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(body.len() as u32).to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&lh.to_le_bytes());
            cd.extend_from_slice(name);
        }
        let cd_off = v.len() as u32 - base;
        v.extend_from_slice(&cd);
        v.extend_from_slice(b"PK\x05\x06\0\0\0\0\x02\0\x02\0");
        v.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        v.extend_from_slice(&cd_off.to_le_bytes());
        v.extend_from_slice(&[0, 0]);
        v
    }

    #[test]
    fn native_each_type() {
        for f in [0x10, 0x11, 0x12] {
            assert_eq!(run(&native_phar(f)), PharSig::OpenSsl(f));
        }
        for f in [1u32, 2, 4, 8, 0x13, 0] {
            assert_eq!(run(&native_phar(f)), PharSig::Keyless(f), "{f}");
        }
    }

    #[test]
    fn tar_signature_entry() {
        assert_eq!(run(&tar_phar(0x11)), PharSig::OpenSsl(0x11));
        assert_eq!(run(&tar_phar(0x04)), PharSig::Keyless(4));
    }

    #[test]
    fn zip_signature_entry() {
        assert_eq!(run(&zip_phar(0x12, b"", 0)), PharSig::OpenSsl(0x12));
        assert_eq!(run(&zip_phar(0x04, b"", 0)), PharSig::Keyless(4));
        // stub-prefixed zip (offsets relative to the zip start)
        assert_eq!(run(&zip_phar(0x02, b"<?php __HALT_COMPILER(); ?>\r\n", 0)), PharSig::Keyless(2));
        // deflated signature entry: unreadable, never guessed
        assert_eq!(run(&zip_phar(0x10, b"", 8)), PharSig::Indeterminate);
    }

    #[test]
    fn garbage_truncated_and_compressed_are_indeterminate() {
        assert_eq!(run(b""), PharSig::Indeterminate);
        assert_eq!(run(b"GBM"), PharSig::Indeterminate);
        assert_eq!(run(b"no magic here at all, just text........"), PharSig::Indeterminate);
        assert_eq!(run(&[0xFF; 2000]), PharSig::Indeterminate);
        let mut gz = vec![0x1f, 0x8b, 8, 0];
        gz.extend_from_slice(&[0x33; 900]);
        assert_eq!(run(&gz), PharSig::Indeterminate);
        let mut t = tar_phar(0x10);
        t.truncate(1200);
        assert_eq!(run(&t), PharSig::Indeterminate);
        let z = zip_phar(0x10, b"", 0);
        assert_eq!(run(&z[..z.len() - 5]), PharSig::Indeterminate);
    }

    #[test]
    fn duplicate_signature_entries_resolve_to_keyless() {
        // OpenSSL entry first, downgraded entry last (and vice versa).
        for (a, b) in [(0x10, 0x04), (0x04, 0x10)] {
            let mut t = tar_phar(a);
            t.extend_from_slice(&tar_phar(b)[512 * 2..]);
            // second copy also carries a signature header+data only
            assert_eq!(run(&t), PharSig::Keyless(0x04), "{a} {b}");
        }
    }

    #[test]
    fn native_tail_wins_over_tar_looking_head_only_when_not_keyless() {
        let mut v = tar_phar(0x04);
        v.extend_from_slice(&0x10u32.to_le_bytes());
        v.extend_from_slice(b"GBMB");
        assert_eq!(run(&v), PharSig::Keyless(4)); // polyglot: weakest reading
    }

    #[test]
    fn verdicts() {
        assert_eq!(verdict(PharSig::Keyless(4), true), Some("signature-downgrade"));
        assert_eq!(verdict(PharSig::OpenSsl(0x10), true), None);
        assert_eq!(verdict(PharSig::Indeterminate, true), Some("signature-indeterminate"));
        for s in [PharSig::Keyless(1), PharSig::OpenSsl(0x11), PharSig::Indeterminate] {
            assert_eq!(verdict(s, false), None);
        }
    }
}
