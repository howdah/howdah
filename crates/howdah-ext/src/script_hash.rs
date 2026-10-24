//! SHA-256 of a script file for the `[[exceptions]]` `script_sha256` facet,
//! with a small per-process cache. Pure Rust and host-testable: the PHP glue
//! (`origin.rs`) owns the process-global instance and decides when to call it
//! (only when the core says a hash facet could apply to the script).
//!
//! Revalidation is by `stat`: a cached digest is reused only while the
//! file's identity and change stamps are all unchanged: device, inode, size,
//! mtime AND ctime. mtime alone is not enough (`cp -p`, `touch -r`, `rsync
//! -t` and `tar` preserve it); ctime cannot be set from userland, and a
//! rename-in replacement changes the inode. The cache holds at most `cap`
//! paths and is emptied when full (a bounded, simple policy; the facet is
//! meant for a handful of pinned scripts, not hundreds).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use howdah_core::exceptions::sha256;

/// Largest file hashed (bytes); anything bigger yields `None` (no match,
/// the rule stays armed). 4 MiB bounds the transient read inside a sink call;
/// a PHP script larger than that cannot use the hash facet.
pub const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// What must be unchanged for a cached digest to be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl Stamp {
    fn of(md: &std::fs::Metadata) -> Stamp {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Stamp {
                dev: md.dev(),
                ino: md.ino(),
                len: md.len(),
                mtime: (md.mtime(), md.mtime_nsec()),
                ctime: (md.ctime(), md.ctime_nsec()),
            }
        }
        #[cfg(not(unix))]
        {
            use std::time::UNIX_EPOCH;
            let m = md.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok());
            Stamp {
                dev: 0,
                ino: 0,
                len: md.len(),
                mtime: m.map_or((0, 0), |d| (d.as_secs() as i64, d.subsec_nanos() as i64)),
                ctime: (0, 0),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    stamp: Stamp,
    sha: [u8; 32],
}

/// The cache. One per process in the glue.
#[derive(Debug, Default)]
pub struct HashCache {
    map: HashMap<PathBuf, Entry>,
    cap: usize,
    /// Files read (not served from cache), for tests and diagnostics.
    pub reads: u64,
}

impl HashCache {
    pub fn new(cap: usize) -> HashCache {
        HashCache { map: HashMap::new(), cap: cap.max(1), reads: 0 }
    }

    /// SHA-256 of the file at `path`, or `None` if it cannot be read (an
    /// unreadable file never matches a hash facet: fail toward protection).
    pub fn sha256_of(&mut self, path: &Path) -> Option<[u8; 32]> {
        let md = std::fs::metadata(path).ok()?;
        if !md.is_file() || md.len() > MAX_FILE_BYTES {
            return None;
        }
        let stamp = Stamp::of(&md);
        if let Some(e) = self.map.get(path) {
            if e.stamp == stamp {
                return Some(e.sha);
            }
        }
        let bytes = std::fs::read(path).ok()?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return None; // grew between stat and read
        }
        self.reads += 1;
        let sha = sha256::digest(&bytes);
        if self.map.len() >= self.cap && !self.map.contains_key(path) {
            self.map.clear();
        }
        self.map.insert(path.to_path_buf(), Entry { stamp, sha });
        Some(sha)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, body: &[u8]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("howdah-script-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::File::create(&p).unwrap().write_all(body).unwrap();
        p
    }

    #[test]
    fn hashes_and_caches_until_the_file_changes() {
        let p = tmp("a.php", b"<?php echo 1;");
        let mut c = HashCache::new(8);
        let h1 = c.sha256_of(&p).unwrap();
        assert_eq!(h1, sha256::digest(b"<?php echo 1;"));
        assert_eq!(c.sha256_of(&p).unwrap(), h1);
        assert_eq!(c.reads, 1, "second call served from cache");
        // Same length, different bytes, forced older-or-newer mtime: re-read.
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&p, b"<?php echo 2;").unwrap();
        let far = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        let _ = std::fs::File::options().write(true).open(&p).and_then(|f| f.set_modified(far));
        let h2 = c.sha256_of(&p).unwrap();
        assert_eq!(h2, sha256::digest(b"<?php echo 2;"));
        assert_ne!(h1, h2);
        assert_eq!(c.reads, 2);
    }

    #[test]
    fn same_size_rewrite_with_restored_mtime_is_re_read() {
        // `cp -p`, `touch -r`, rsync -t and tar keep size and mtime; only the
        // inode's ctime (and sometimes the inode) changes. The cache must not
        // serve the stale digest.
        let p = tmp("c.php", b"<?php echo 1;");
        let mut c = HashCache::new(8);
        let h1 = c.sha256_of(&p).unwrap();
        let mtime = std::fs::metadata(&p).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&p, b"<?php echo 2;").unwrap(); // same length
        std::fs::File::options().write(true).open(&p).unwrap().set_modified(mtime).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().modified().unwrap(), mtime, "mtime restored");
        let h2 = c.sha256_of(&p).unwrap();
        assert_eq!(h2, sha256::digest(b"<?php echo 2;"));
        assert_ne!(h1, h2);
        assert_eq!(c.reads, 2);
        // A replacement via rename (new inode, same size, copied mtime).
        let q = tmp("c.php.tmp", b"<?php echo 3;");
        std::fs::File::options().write(true).open(&q).unwrap().set_modified(mtime).unwrap();
        std::fs::rename(&q, &p).unwrap();
        assert_eq!(c.sha256_of(&p).unwrap(), sha256::digest(b"<?php echo 3;"));
        assert_eq!(c.reads, 3);
    }

    #[test]
    fn files_over_the_cap_are_not_hashed() {
        let p = tmp("big.php", &vec![b'/'; (MAX_FILE_BYTES + 1) as usize]);
        let mut c = HashCache::new(8);
        assert!(c.sha256_of(&p).is_none());
        assert_eq!(MAX_FILE_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn missing_or_directory_is_none() {
        let mut c = HashCache::new(8);
        assert!(c.sha256_of(Path::new("/nonexistent/howdah/x.php")).is_none());
        assert!(c.sha256_of(&std::env::temp_dir()).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn cache_is_bounded() {
        let mut c = HashCache::new(2);
        for i in 0..5 {
            let p = tmp(&format!("b{i}.php"), format!("<?php // {i}").as_bytes());
            assert!(c.sha256_of(&p).is_some());
            assert!(c.len() <= 2);
        }
    }
}
