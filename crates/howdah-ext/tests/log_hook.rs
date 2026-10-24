//! `[log] exec`: the hook receives the event line on stdin, with nothing from
//! the request in its argv or environment beyond HOWDAH_RULE/HOWDAH_ACTION,
//! inherits no stray file descriptors, and is rate limited. Exercises the
//! same `logsink` code the extension calls, with a real child process.
//!
//! One test function on purpose: it sets a process environment variable,
//! which must not race with other tests in this binary.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use howdah_ext::logsink::{Fired, Hook};

const LINE: &str = r#"{"action":"block","client_ip":"203.0.113.7","layer":1,"method":"POST","reason":"multipart part count exceeds limit","request_id":"2a1f9c0d3e4b5a69788","rule":"max_parts","schema":2,"ts":"1761318132123","uri":"/upload.php","version":"1.3.0"}"#;

fn scratch() -> PathBuf {
    let d = std::env::temp_dir().join(format!("howdah-hook-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn write_script(dir: &Path, name: &str, body: &str, mode: u32) -> String {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p.to_str().unwrap().to_string()
}

/// Wait until `p` exists with at least one line (the hook runs detached).
fn wait_for(p: &Path) -> String {
    let t = Instant::now();
    loop {
        if let Ok(s) = fs::read_to_string(p) {
            if s.ends_with('\n') {
                return s;
            }
        }
        assert!(t.elapsed() < Duration::from_secs(10), "hook never wrote {}", p.display());
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn hook_contract() {
    let dir = scratch();
    let out = dir.join("out");

    // A secret in the parent environment must not reach the hook.
    std::env::set_var("HOWDAH_TEST_PARENT_SECRET", "SECRETPARENTENV");
    // A descriptor PHP left open without close-on-exec must not reach it.
    let leak = fs::File::create(dir.join("leak")).unwrap();
    let leak_fd = unsafe { libc::dup2(std::os::unix::io::AsRawFd::as_raw_fd(&leak), 211) };
    assert_eq!(leak_fd, 211);
    assert_eq!(unsafe { libc::fcntl(211, libc::F_SETFD, 0) }, 0, "clear CLOEXEC on the stray fd");

    let script = write_script(
        &dir,
        "hook.sh",
        &format!(
            "#!/bin/sh\n\
             d={d}\n\
             echo \"$#\" > \"$d/argc\"\n\
             env > \"$d/env\"\n\
             ls /proc/$$/fd > \"$d/fds\" 2>/dev/null\n\
             cat > \"$d/stdin\"\n\
             cp \"$d/stdin\" \"$d/out.tmp\" && mv \"$d/out.tmp\" \"$d/out\"\n",
            d = dir.display()
        ),
        0o755,
    );

    // 1. The line arrives on stdin, intact, with a trailing newline.
    let mut hook = Hook::new(&script, 10);
    let t = Instant::now();
    assert_eq!(hook.fire(LINE), Fired::Spawned);
    assert!(t.elapsed() < Duration::from_secs(1), "fire() must not wait for the hook");
    assert_eq!(wait_for(&out), format!("{LINE}\n"));

    // 2. No argv beyond argv[0].
    assert_eq!(fs::read_to_string(dir.join("argc")).unwrap().trim(), "0");

    // 3. Environment: HOWDAH_RULE / HOWDAH_ACTION from the line, a fixed PATH,
    //    plus only what /bin/sh itself sets. Nothing from the parent.
    let env = fs::read_to_string(dir.join("env")).unwrap();
    assert!(env.lines().any(|l| l == "HOWDAH_RULE=max_parts"), "{env}");
    assert!(env.lines().any(|l| l == "HOWDAH_ACTION=block"), "{env}");
    assert!(!env.contains("SECRETPARENTENV"), "parent env leaked: {env}");
    for l in env.lines() {
        let k = l.split('=').next().unwrap();
        assert!(
            ["HOWDAH_RULE", "HOWDAH_ACTION", "PATH", "PWD", "OLDPWD", "SHLVL", "_"].contains(&k),
            "unexpected env var {k} in the hook"
        );
    }

    // 4. The stray descriptor was not inherited.
    let fds = fs::read_to_string(dir.join("fds")).unwrap();
    assert!(!fds.lines().any(|l| l.trim() == "211"), "fd 211 leaked into the hook: {fds:?}");
    unsafe { libc::close(211) };

    // 5. Rate limit: at most N spawns in any one second; the rest are skipped.
    let quiet = write_script(&dir, "quiet.sh", "#!/bin/sh\ncat > /dev/null\n", 0o755);
    let mut hook = Hook::new(&quiet, 3);
    let fired: Vec<Fired> = (0..5).map(|_| hook.fire(LINE)).collect();
    assert_eq!(fired.iter().filter(|f| **f == Fired::Spawned).count(), 3, "{fired:?}");
    assert_eq!(fired.iter().filter(|f| **f == Fired::RateLimited).count(), 2, "{fired:?}");
    // The children are reaped, not left as zombies.
    let t = Instant::now();
    while hook.in_flight() > 0 {
        hook.reap();
        assert!(t.elapsed() < Duration::from_secs(10), "children never reaped");
        std::thread::sleep(Duration::from_millis(20));
    }

    // 6. A world-writable hook is refused (and stays refused).
    let ww = write_script(&dir, "ww.sh", "#!/bin/sh\ntouch \"$0.ran\"\n", 0o777);
    let mut hook = Hook::new(&ww, 10);
    assert!(matches!(hook.fire(LINE), Fired::Refused(_)));
    assert!(matches!(hook.fire(LINE), Fired::Refused(_)));
    std::thread::sleep(Duration::from_millis(200));
    assert!(!Path::new(&format!("{ww}.ran")).exists());

    // 7. A missing hook is a failure, not a panic.
    let mut hook = Hook::new("/nonexistent/howdah-hook", 10);
    assert!(matches!(hook.fire(LINE), Fired::Refused(_)));

    drop(leak);
    let _ = fs::remove_dir_all(&dir);
}
