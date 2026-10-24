//! `[log] exec`: the hook receives the event line on stdin, with nothing from
//! the request in its argv or environment beyond HOWDAH_RULE/HOWDAH_ACTION,
//! inherits no stray file descriptors, is not left as a child of the PHP
//! worker, is rate limited, and runs only a program that passes the checks:
//! the very inode that was checked, opened without following a symlink, not
//! group/world-writable and not in a group/world-writable directory.
//! Exercises the same `logsink` code the extension calls, with real processes.
//!
//! One test function on purpose: it sets a process environment variable and
//! calls waitpid(-1), which must not race other tests in this binary.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use howdah_ext::logsink::{open_checked, spawn_checked, Fired, Hook};

const LINE: &str = r#"{"action":"block","client_ip":"203.0.113.7","layer":1,"method":"POST","reason":"multipart part count exceeds limit","request_id":"2a1f9c0d3e4b5a69788","rule":"max_parts","schema":2,"ts":"1761318132123","uri":"/upload.php","version":"1.4.0"}"#;

/// Under the target dir, not /tmp: /tmp may be mounted noexec.
fn scratch() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("howdah-hook-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    // The hook's directory must not be group/world-writable, whatever the umask.
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    d
}

fn write_script(dir: &Path, name: &str, body: &str, mode: u32) -> String {
    let p = dir.join(name);
    fs::write(&p, body).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
    p.to_str().unwrap().to_string()
}

/// Wait until `p` exists with a complete last line (the hook runs detached).
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

fn refused(f: Fired) -> String {
    match f {
        Fired::Refused(why) => why,
        other => panic!("expected Refused, got {other:?}"),
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
             echo \"$PPID\" > \"$d/ppid\"\n\
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
    // 2. Nothing is left for the PHP worker to reap: the hook was double-forked
    //    and the short-lived middle process is already collected.
    let mut status = 0;
    let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    assert_eq!(r, -1, "a child of the worker is left behind");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::ECHILD));
    assert_eq!(wait_for(&out), format!("{LINE}\n"));
    let ppid: u32 = fs::read_to_string(dir.join("ppid")).unwrap().trim().parse().unwrap();
    assert_ne!(ppid, std::process::id(), "the hook is a direct child of the worker");

    // 3. No argv beyond argv[0].
    assert_eq!(fs::read_to_string(dir.join("argc")).unwrap().trim(), "0");

    // 4. Environment: HOWDAH_RULE / HOWDAH_ACTION from the line, a fixed PATH,
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

    // 5. The stray descriptor was not inherited.
    let fds = fs::read_to_string(dir.join("fds")).unwrap();
    assert!(!fds.lines().any(|l| l.trim() == "211"), "fd 211 leaked into the hook: {fds:?}");
    unsafe { libc::close(211) };

    // 6. Rate limit: at most N spawns in any one second; the rest are skipped.
    let quiet = write_script(&dir, "quiet.sh", "#!/bin/sh\ncat > /dev/null\n", 0o755);
    let mut hook = Hook::new(&quiet, 3);
    let fired: Vec<Fired> = (0..5).map(|_| hook.fire(LINE)).collect();
    assert_eq!(fired.iter().filter(|f| **f == Fired::Spawned).count(), 3, "{fired:?}");
    assert_eq!(fired.iter().filter(|f| **f == Fired::RateLimited).count(), 2, "{fired:?}");

    // 7. Program checks, on every fire. Each refused program would leave a
    //    marker next to itself if it ran.
    let marker = |p: &str| PathBuf::from(format!("{p}.ran"));
    let runs = "#!/bin/sh\ntouch \"$(readlink -f \"$0\").ran\" 2>/dev/null; cat >/dev/null\n";
    let ww = write_script(&dir, "ww.sh", runs, 0o777);
    assert!(refused(Hook::new(&ww, 10).fire(LINE)).contains("writable"));
    let gw = write_script(&dir, "gw.sh", runs, 0o775);
    let mut gw_hook = Hook::new(&gw, 10);
    assert!(refused(gw_hook.fire(LINE)).contains("writable"));
    let noexec = write_script(&dir, "noexec.sh", runs, 0o644);
    assert!(refused(Hook::new(&noexec, 10).fire(LINE)).contains("executable"));
    // a program in a world-writable directory
    let open_dir = dir.join("open");
    fs::create_dir(&open_dir).unwrap();
    fs::set_permissions(&open_dir, fs::Permissions::from_mode(0o777)).unwrap();
    let in_open = write_script(&open_dir, "hook.sh", runs, 0o755);
    assert!(refused(Hook::new(&in_open, 10).fire(LINE)).contains("directory"));
    // a symlink is not followed
    let link = dir.join("link.sh");
    std::os::unix::fs::symlink(&quiet, &link).unwrap();
    assert!(refused(Hook::new(link.to_str().unwrap(), 10).fire(LINE)).contains("symlink"));
    // missing: a refusal, not a panic
    assert!(matches!(Hook::new("/nonexistent/howdah-hook", 10).fire(LINE), Fired::Refused(_)));
    std::thread::sleep(Duration::from_millis(300));
    for p in [&ww, &gw, &noexec, &in_open] {
        assert!(!marker(p).exists(), "{p} ran although it was refused");
    }
    // The check runs on every fire: fixing the mode takes effect at once.
    fs::set_permissions(&gw, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(gw_hook.fire(LINE), Fired::Spawned);
    let t = Instant::now();
    while !marker(&gw).exists() {
        assert!(t.elapsed() < Duration::from_secs(10), "fixed hook never ran");
        std::thread::sleep(Duration::from_millis(20));
    }

    // 8. The inode that was checked is the one that runs: replacing the file
    //    between the check and the start does not run the new content.
    let swap = write_script(&dir, "swap.sh", &format!("#!/bin/sh\ncat >/dev/null\necho v1 > {}/swap.out\n", dir.display()), 0o755);
    let checked = open_checked(&swap).expect("v1 passes the checks");
    let v2 = write_script(&dir, "swap.new", &format!("#!/bin/sh\ncat >/dev/null\necho v2 > {}/swap.out\n", dir.display()), 0o755);
    fs::rename(&v2, &swap).unwrap();
    spawn_checked(&swap, checked, LINE).expect("spawn");
    assert_eq!(wait_for(&dir.join("swap.out")), "v1\n");

    drop(leak);
    let _ = fs::remove_dir_all(&dir);
}
