//! SHA-256 of a script file for the `[[exceptions]]` `script_sha256` facet,
//! with a small per-process cache. Pure Rust and host-testable: the PHP glue
//! (`origin.rs`) owns the process-global instance and decides when to call it
//! (only when the core says a hash facet could apply to the script).
//!
//! Revalidation is by `stat`: a cached digest is reused while the file's size
//! and mtime are unchanged, so an edited file is re-read. The cache holds at
//! most `cap` paths and is emptied when full (a bounded, simple policy; the
//! facet is meant for a handful of pinned scripts, not hundreds).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use howdah_core::exceptions::sha256;

/// Largest file hashed (bytes); anything bigger yields `None` (no match).
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    len: u64,
    mtime: Option<SystemTime>,
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
        let (len, mtime) = (md.len(), md.modified().ok());
        if let Some(e) = self.map.get(path) {
            if e.len == len && e.mtime == mtime {
                return Some(e.sha);
            }
        }
        let bytes = std::fs::read(path).ok()?;
        self.reads += 1;
        let sha = sha256::digest(&bytes);
        if self.map.len() >= self.cap && !self.map.contains_key(path) {
            self.map.clear();
        }
        self.map.insert(path.to_path_buf(), Entry { len, mtime, sha });
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
        let far = SystemTime::now() + std::time::Duration::from_secs(5);
        let _ = std::fs::File::options().write(true).open(&p).and_then(|f| f.set_modified(far));
        let h2 = c.sha256_of(&p).unwrap();
        assert_eq!(h2, sha256::digest(b"<?php echo 2;"));
        assert_ne!(h1, h2);
        assert_eq!(c.reads, 2);
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
