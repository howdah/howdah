//! Where event lines go (`[log] destination`: a file, syslog or stderr) and
//! the optional per-event hook (`[log] exec`). Pure Rust with no PHP types, so
//! it builds and is tested on the host without PHP headers; the glue
//! (`response::write_log_line`) calls [`Settings::emit`] for every event line.
//!
//! Everything here runs inside a PHP worker and must never block a request
//! for long, never panic across the FFI boundary (callers wrap it), and never
//! take PHP down: every failure falls back to stderr with a loud note.

use std::collections::VecDeque;
use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use howdah_core::{LogConfig, LogDestination, SyslogFacility};

/// The local syslog socket (glibc's `_PATH_LOG`).
pub const SYSLOG_SOCKET: &str = "/dev/log";
/// The only PATH a hook sees (fixed, not inherited from PHP).
pub const HOOK_PATH_ENV: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Mode of a log file Howdah creates (the process umask still applies).
pub const LOG_FILE_MODE: u32 = 0o640;

/// A loud, un-panicking note to stderr. Never unwinds.
pub fn loud_error(msg: &str) {
    let _ = io::stderr().write_all(format!("howdah: ERROR: {msg} (continuing to serve)\n").as_bytes());
}

/// The stderr fallback: still one structured line, written in one call.
pub fn stderr_line(line: &str) {
    let _ = io::stderr().write_all(format!("howdah-event {line}\n").as_bytes());
}

/// Append `line` plus a newline in ONE write on an `O_APPEND` descriptor, so
/// lines from concurrent PHP workers never interleave. The file is opened per
/// event (no descriptor is held), so a rotated file is picked up on the next
/// event with no reload. A new file gets mode 0640 minus the umask; an
/// existing file keeps its mode.
pub fn append_line(path: &str, line: &str) -> io::Result<()> {
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    let mut f = OpenOptions::new().create(true).append(true).mode(LOG_FILE_MODE).open(path)?;
    f.write_all(&buf)
}

// ---- syslog -----------------------------------------------------------------

/// Syslog severity for an event line: block = warning (4), log = notice (5),
/// anything else = info (6). Our lines are compact serde_json output, so the
/// key/value pair appears verbatim and cannot occur inside an escaped string.
pub fn severity(line: &str) -> u8 {
    if line.contains("\"action\":\"block\"") {
        4
    } else if line.contains("\"action\":\"log\"") {
        5
    } else {
        6
    }
}

/// RFC 3164 timestamp in local time, the format glibc's syslog() writes
/// (`%h %e %T`, e.g. `Oct  4 09:41:02`).
pub fn stamp(now: SystemTime) -> String {
    const MON: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let secs = now.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) as libc::time_t;
    // SAFETY: localtime_r writes only into `tm`, which outlives the call.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return "Jan  1 00:00:00".to_string();
    }
    format!(
        "{} {:>2} {:02}:{:02}:{:02}",
        MON[(tm.tm_mon.rem_euclid(12)) as usize],
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

/// One syslog message, framed as glibc's syslog() frames it for the local
/// socket: `<PRI>TIMESTAMP IDENT[PID]: MESSAGE`.
pub fn frame(facility: SyslogFacility, sev: u8, stamp: &str, ident: &str, pid: u32, line: &str) -> String {
    let pri = u32::from(facility.code()) * 8 + u32::from(sev);
    format!("<{pri}>{stamp} {ident}[{pid}]: {line}")
}

/// Writes to the local syslog socket directly instead of calling openlog(3)
/// and syslog(3). openlog state is process-wide and PHP owns it: PHP's
/// `error_log = syslog` calls openlog with its own ident, and ext/standard
/// calls closelog() at the end of every request (PHP 8.3
/// `PHP_RSHUTDOWN_FUNCTION(syslog)`), which resets the ident. Sharing it
/// would relabel PHP's messages as `howdah` or ours as `php-fpm`.
///
/// Datagram only. glibc falls back to a stream socket when `/dev/log` is one
/// (some syslog-ng setups), but a stream connect or send can block the
/// request; a non-blocking datagram cannot. Against a stream socket the
/// connect fails at once (EPROTOTYPE) and the line goes to stderr.
pub struct Syslog {
    facility: SyslogFacility,
    ident: String,
    path: PathBuf,
    /// (pid that connected it, socket). FPM workers fork after MINIT, so a
    /// socket is only reused by the process that opened it.
    sock: Option<(u32, UnixDatagram)>,
}

impl Syslog {
    pub fn new(facility: SyslogFacility, ident: &str) -> Syslog {
        Syslog::with_socket(facility, ident, SYSLOG_SOCKET)
    }

    /// Same, at a different socket path (tests).
    pub fn with_socket(facility: SyslogFacility, ident: &str, path: &str) -> Syslog {
        Syslog { facility, ident: ident.to_string(), path: PathBuf::from(path), sock: None }
    }

    pub fn facility(&self) -> SyslogFacility {
        self.facility
    }

    pub fn ident(&self) -> &str {
        &self.ident
    }

    fn connect(&self) -> io::Result<UnixDatagram> {
        let d = UnixDatagram::unbound()?;
        // A full receive queue (a stalled daemon) must not stall PHP: the
        // send fails with EWOULDBLOCK and the line goes to stderr.
        d.set_nonblocking(true)?;
        d.connect(&self.path)?;
        Ok(d)
    }

    fn send_on(d: &UnixDatagram, msg: &[u8]) -> io::Result<()> {
        let n = d.send(msg)?;
        if n == msg.len() {
            Ok(())
        } else {
            Err(io::Error::other("short syslog datagram"))
        }
    }

    /// Send one event line. Reconnects once (the daemon may have restarted).
    pub fn send(&mut self, line: &str) -> io::Result<()> {
        let pid = std::process::id();
        let msg = frame(self.facility, severity(line), &stamp(SystemTime::now()), &self.ident, pid, line);
        let mut last = None;
        for attempt in 0..2 {
            let reuse = attempt == 0 && matches!(&self.sock, Some((p, _)) if *p == pid);
            if !reuse {
                self.sock = None;
                self.sock = Some((pid, self.connect()?));
            }
            let Some((_, s)) = self.sock.as_mut() else { break };
            match Syslog::send_on(s, msg.as_bytes()) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // The daemon is not keeping up; reconnecting will not help.
                    return Err(e);
                }
                Err(e) => last = Some(e),
            }
        }
        self.sock = None;
        Err(last.unwrap_or_else(|| io::Error::other("syslog send failed")))
    }
}

// ---- the per-event hook -----------------------------------------------------

/// What happened to one event's hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fired {
    /// A hook process was started. It runs detached (double-forked, so it is
    /// never a child of the PHP worker) and is not waited for.
    Spawned,
    /// More than `exec_rate_limit` starts in the last second; skipped.
    RateLimited,
    /// The program failed the checks of [`open_checked`]. They run on every
    /// event, so a fix takes effect at the next one.
    Refused(String),
    /// fork/exec failed, or the line did not fit in the pipe buffer.
    Failed(String),
}

/// `[log] exec`: run a program once per event with the JSON line on stdin.
pub struct Hook {
    path: String,
    limit: u32,
    recent: VecDeque<Instant>,
    /// The refusal last reported on stderr; reported again only if it changes.
    refused: Option<String>,
    noted: bool,
}

impl Hook {
    pub fn new(path: &str, limit: u32) -> Hook {
        Hook { path: path.to_string(), limit: limit.max(1), recent: VecDeque::new(), refused: None, noted: false }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Sliding window: true if fewer than `limit` spawns in the last second.
    pub fn allow(&mut self, now: Instant) -> bool {
        while let Some(&t) = self.recent.front() {
            if now.saturating_duration_since(t) >= Duration::from_secs(1) {
                self.recent.pop_front();
            } else {
                break;
            }
        }
        if self.recent.len() < self.limit as usize {
            self.recent.push_back(now);
            true
        } else {
            false
        }
    }

    /// Run the hook for one event line. Never waits for the hook to finish.
    pub fn fire(&mut self, line: &str) -> Fired {
        // The rate limit comes first, so it also bounds the checks below to
        // `limit` per second.
        if !self.allow(Instant::now()) {
            if !self.noted {
                self.noted = true;
                loud_error(&format!(
                    "[log] exec rate limit reached ({} per second); skipping the hook for further events until it clears (the events are still logged)",
                    self.limit
                ));
            }
            return Fired::RateLimited;
        }
        let prog = match open_checked(&self.path) {
            Ok(fd) => {
                self.refused = None;
                fd
            }
            Err(e) => {
                if self.refused.as_deref() != Some(e.as_str()) {
                    loud_error(&format!("[log] exec '{}' will not be run: {e}", self.path));
                    self.refused = Some(e.clone());
                }
                return Fired::Refused(e);
            }
        };
        match spawn_checked(&self.path, prog, line) {
            Ok(()) => {
                self.noted = false;
                Fired::Spawned
            }
            Err(e) => {
                let hint = if e.kind() == io::ErrorKind::NotFound {
                    " (it is started through /proc/self/fd, so /proc must be mounted)"
                } else {
                    ""
                };
                loud_error(&format!("[log] exec '{}' failed: {e}{hint}", self.path));
                Fired::Failed(e.to_string())
            }
        }
    }
}

/// Open the hook program and check it through the descriptor, not the path,
/// so the checks and the exec see the same inode. Refuses:
/// - a symlink as the program path (`O_NOFOLLOW`);
/// - anything but an executable regular file;
/// - a group- or world-writable file, or one owned by anyone but root or the
///   user PHP runs as;
/// - a file in a group- or world-writable directory, where it could be
///   swapped before the next event.
///
/// The descriptor is `O_PATH` and close-on-exec; [`spawn_checked`] runs it.
pub fn open_checked(path: &str) -> Result<OwnedFd, String> {
    let c = CString::new(path).map_err(|_| "the path contains a NUL byte".to_string())?;
    // SAFETY: `c` is a valid NUL-terminated string for the call.
    let raw = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if raw < 0 {
        let e = io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::ELOOP) {
            "it is a symlink; name the real file".to_string()
        } else {
            format!("cannot open it: {e}")
        });
    }
    // SAFETY: `raw` was just opened and is owned by nobody else.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: fstat writes only into `st`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(format!("cannot stat it: {}", io::Error::last_os_error()));
    }
    // With O_PATH, O_NOFOLLOW opens a symlink itself rather than failing.
    if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Err("it is a symlink; name the real file".into());
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("not a regular file".into());
    }
    if st.st_mode & 0o111 == 0 {
        return Err("not executable".into());
    }
    if st.st_mode & 0o022 != 0 {
        return Err("it is group- or world-writable; chmod go-w it (and keep it owned by root)".into());
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if st.st_uid != 0 && st.st_uid != euid {
        return Err(format!("it is owned by uid {}, not by root or the PHP user (uid {euid})", st.st_uid));
    }
    let dir = Path::new(path).parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("/"));
    let dmode = fs::metadata(dir)
        .map_err(|e| format!("cannot stat its directory {}: {e}", dir.display()))?
        .permissions()
        .mode();
    if dmode & 0o022 != 0 {
        return Err(format!(
            "its directory {} is group- or world-writable, so the file could be swapped",
            dir.display()
        ));
    }
    Ok(fd)
}

/// `rule` and `action` from an event line, restricted to `[a-z0-9_]` (they
/// always are); anything else becomes `unknown`.
pub fn rule_action(line: &str) -> (String, String) {
    let v: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
    let clean = |k: &str| -> String {
        match v.get(k).and_then(|x| x.as_str()) {
            Some(s) if !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') => {
                s.to_string()
            }
            _ => "unknown".to_string(),
        }
    };
    (clean("rule"), clean("action"))
}

/// Descriptors to mark close-on-exec in the hook child when `close_range`
/// is not available (Linux before 5.11). Computed in the parent, where
/// allocating is safe.
enum Sweep {
    /// The descriptors listed in `/proc/self/fd`.
    List(Vec<i32>),
    /// No /proc (a chroot): every number from 3 below this bound.
    Upto(i32),
}

fn sweep() -> Sweep {
    if let Ok(rd) = fs::read_dir("/proc/self/fd") {
        return Sweep::List(
            rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse::<i32>().ok()).filter(|&fd| fd > 2).collect(),
        );
    }
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: getrlimit writes only into `rl`.
    let max = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        // RLIM_INFINITY is clamped to the kernel's own ceiling (NR_OPEN).
        rl.rlim_cur.min(1 << 20) as i32
    } else {
        1 << 20
    };
    Sweep::Upto(max)
}

/// A close-on-exec pipe, read end first.
fn pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: pipe2 writes two descriptors into `fds`.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: both descriptors were just created and are owned by nobody else.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Start the program `prog` (from [`open_checked`]) with `line` on stdin, and
/// return once it has been exec'd. It is run through `/proc/self/fd/N`, so
/// the inode that passed the checks is the one that runs, even if `path`
/// is replaced in between. `path` is only its `argv[0]`.
pub fn spawn_checked(path: &str, prog: OwnedFd, line: &str) -> io::Result<()> {
    let (rule, action) = rule_action(line);
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');

    // Fill the pipe BEFORE the child exists, non-blocking: no SIGPIPE is
    // possible (we hold both ends) and a line larger than the pipe buffer
    // (64 KiB by default) fails here instead of blocking the request.
    let (r, w) = pipe()?;
    // SAFETY: fcntl on a descriptor we own.
    unsafe {
        let fl = libc::fcntl(w.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(w.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    // SAFETY: the pointer/length pair is `buf`, live for the call.
    let n = unsafe { libc::write(w.as_raw_fd(), buf.as_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != buf.len() {
        return Err(io::Error::other("event line is larger than the pipe buffer; hook skipped"));
    }
    drop(w); // the hook sees the line, then EOF

    let sweep = sweep();
    let prog_fd = prog.as_raw_fd();
    let mut cmd = Command::new(format!("/proc/self/fd/{prog_fd}"));
    cmd.arg0(path)
        .env_clear()
        .env("PATH", HOOK_PATH_ENV)
        .env("HOWDAH_RULE", rule)
        .env("HOWDAH_ACTION", action)
        .stdin(Stdio::from(r))
        // In CGI mode stdout IS the HTTP response; never let a hook write there.
        .stdout(Stdio::null())
        // stderr is inherited: the web server or FPM error log, for debugging.
        .current_dir("/");
    // SAFETY: runs in the forked child before exec and calls only
    // async-signal-safe functions (syscall, fcntl, fork, _exit, setsid) on
    // data prepared above; nothing allocates.
    unsafe {
        cmd.pre_exec(move || {
            // Whatever PHP left open without close-on-exec (client sockets,
            // database connections, files) must not leak into the hook:
            // close_range in one call (Linux 5.11+), else one fcntl each.
            let all = libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_uint,
                libc::c_uint::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            if all != 0 {
                match &sweep {
                    Sweep::List(fds) => {
                        for &fd in fds {
                            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                        }
                    }
                    Sweep::Upto(max) => {
                        for fd in 3..*max {
                            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
                        }
                    }
                }
            }
            // ...except the checked program: the kernel, and for a script its
            // interpreter, open it through /proc/self/fd.
            libc::fcntl(prog_fd, libc::F_SETFD, 0);
            // Double fork: this middle process exits at once and is reaped
            // below; the hook is re-parented to init (or a subreaper) and is
            // never a child, or a zombie, of the PHP worker.
            match libc::fork() {
                -1 => return Err(io::Error::last_os_error()),
                0 => {}
                _ => libc::_exit(0),
            }
            // Own session: no controlling terminal, not in PHP's process group.
            libc::setsid();
            Ok(())
        });
    }
    let mut middle = cmd.spawn()?;
    drop(prog);
    // The middle process exits right after its fork, so this returns at once.
    // (If PHP ignores SIGCHLD it was already reaped and this is ECHILD.)
    let _ = middle.wait();
    Ok(())
}

// ---- resolved settings ------------------------------------------------------

/// Where a file path came from (shown in `php --ri howdah`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSource {
    /// The `howdah.log` ini directive (wins when both are set).
    Ini,
    /// `[log] path` in the TOML file.
    Toml,
}

pub enum Target {
    File { path: String, source: PathSource },
    Syslog(Syslog),
    /// `explicit`: chosen with `destination = "stderr"` rather than the
    /// fallback for a `file` destination with no path.
    Stderr { explicit: bool },
}

/// The process's log settings, resolved once at module startup.
pub struct Settings {
    pub target: Target,
    pub hook: Option<Hook>,
}

impl Settings {
    /// Precedence: `destination` picks the target. For `file` (the default)
    /// the path is the `howdah.log` ini value if set, else `[log] path`, else
    /// stderr. `syslog` and `stderr` ignore both paths.
    pub fn resolve(ini_log: Option<&str>, cfg: &LogConfig) -> Settings {
        let nonempty = |s: Option<&str>| s.filter(|p| !p.is_empty()).map(str::to_string);
        let target = match cfg.destination() {
            LogDestination::Syslog => Target::Syslog(Syslog::new(cfg.facility(), cfg.ident())),
            LogDestination::Stderr => Target::Stderr { explicit: true },
            LogDestination::File => match (nonempty(ini_log), nonempty(cfg.path.as_deref())) {
                (Some(p), _) => Target::File { path: p, source: PathSource::Ini },
                (None, Some(p)) => Target::File { path: p, source: PathSource::Toml },
                (None, None) => Target::Stderr { explicit: false },
            },
        };
        let hook = cfg.exec.as_deref().map(|p| Hook::new(p, cfg.exec_rate_limit()));
        Settings { target, hook }
    }

    /// The `php --ri howdah` "Log destination" value.
    pub fn describe(&self) -> String {
        match &self.target {
            Target::File { path, source: PathSource::Ini } => path.clone(),
            Target::File { path, source: PathSource::Toml } => format!("{path} (from [log] path)"),
            Target::Syslog(s) => format!(
                "syslog ({SYSLOG_SOCKET}, facility {}, ident {})",
                s.facility().name(),
                s.ident()
            ),
            Target::Stderr { explicit: true } => "(stderr, [log] destination)".to_string(),
            Target::Stderr { explicit: false } => "(stderr)".to_string(),
        }
    }

    /// The `php --ri howdah` "Log hook" value, if a hook is set.
    pub fn describe_hook(&self) -> Option<String> {
        self.hook.as_ref().map(|h| format!("{} (at most {} per second)", h.path(), h.limit()))
    }

    /// Write one event line to the destination (stderr if that fails), then
    /// run the hook, if any.
    pub fn emit(&mut self, line: &str) {
        match &mut self.target {
            Target::File { path, .. } => {
                if let Err(e) = append_line(path, line) {
                    loud_error(&format!("cannot write the event log '{path}': {e}"));
                    stderr_line(line);
                }
            }
            Target::Syslog(s) => {
                if let Err(e) = s.send(line) {
                    loud_error(&format!("cannot send the event to syslog ({SYSLOG_SOCKET}): {e}"));
                    stderr_line(line);
                }
            }
            Target::Stderr { .. } => stderr_line(line),
        }
        if let Some(h) = self.hook.as_mut() {
            let _ = h.fire(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use howdah_core::Config;
    use std::os::unix::net::UnixListener;

    const LINE: &str = r#"{"action":"block","client_ip":"203.0.113.7","layer":1,"method":"POST","reason":"r","request_id":"1a2b","rule":"max_parts","schema":2,"ts":"1761318132123","uri":"/upload.php","version":"1.3.0"}"#;

    fn cfg(toml: &str) -> LogConfig {
        Config::from_toml(toml).expect(toml).log
    }

    fn tmp(name: &str) -> String {
        let d = std::env::temp_dir().join(format!("howdah-logsink-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&d);
        d.to_str().unwrap().to_string()
    }

    #[test]
    fn default_is_the_1x_behaviour() {
        // ini path set: that file.
        let s = Settings::resolve(Some("/var/log/howdah.log"), &cfg(""));
        assert_eq!(s.describe(), "/var/log/howdah.log");
        assert!(s.hook.is_none());
        // nothing set: stderr.
        let s = Settings::resolve(None, &cfg(""));
        assert!(matches!(s.target, Target::Stderr { explicit: false }));
        assert_eq!(s.describe(), "(stderr)");
        assert!(Settings::resolve(Some(""), &cfg("")).describe() == "(stderr)");
    }

    #[test]
    fn toml_path_is_honoured_and_ini_wins() {
        let c = cfg("[log]\npath = \"/srv/howdah/events.log\"");
        let s = Settings::resolve(None, &c);
        assert_eq!(s.describe(), "/srv/howdah/events.log (from [log] path)");
        let s = Settings::resolve(Some("/var/log/howdah.log"), &c);
        assert_eq!(s.describe(), "/var/log/howdah.log");
        assert!(matches!(s.target, Target::File { source: PathSource::Ini, .. }));
    }

    #[test]
    fn destination_overrides_paths() {
        let c = cfg("[log]\npath = \"/x\"\ndestination = \"syslog\"\nsyslog_facility = \"daemon\"\nsyslog_ident = \"shop\"");
        let s = Settings::resolve(Some("/var/log/howdah.log"), &c);
        assert_eq!(s.describe(), "syslog (/dev/log, facility daemon, ident shop)");
        let s = Settings::resolve(Some("/var/log/howdah.log"), &cfg("[log]\ndestination = \"stderr\""));
        assert_eq!(s.describe(), "(stderr, [log] destination)");
        let s = Settings::resolve(None, &cfg("[log]\ndestination = \"syslog\""));
        assert_eq!(s.describe(), "syslog (/dev/log, facility local0, ident howdah)");
    }

    #[test]
    fn hook_is_off_unless_set() {
        assert!(Settings::resolve(None, &cfg("")).describe_hook().is_none());
        let s = Settings::resolve(None, &cfg("[log]\nexec = \"/usr/local/bin/h\""));
        assert_eq!(s.describe_hook().as_deref(), Some("/usr/local/bin/h (at most 10 per second)"));
        let s = Settings::resolve(None, &cfg("[log]\nexec = \"/h\"\nexec_rate_limit = 2"));
        assert_eq!(s.describe_hook().as_deref(), Some("/h (at most 2 per second)"));
    }

    #[test]
    fn severity_follows_action() {
        assert_eq!(severity(LINE), 4);
        assert_eq!(severity(&LINE.replace("\"block\"", "\"log\"")), 5);
        assert_eq!(severity(&LINE.replace("\"block\"", "\"allow\"")), 6);
        // A reason that quotes the text cannot fool it: quotes are escaped.
        let tricky = r#"{"action":"log","reason":"\"action\":\"block\""}"#;
        assert_eq!(severity(tricky), 5);
    }

    #[test]
    fn frame_matches_glibc_layout() {
        let f = frame(SyslogFacility::Local0, 4, "Oct 24 09:41:02", "howdah", 4242, "{}");
        assert_eq!(f, "<132>Oct 24 09:41:02 howdah[4242]: {}");
        let f = frame(SyslogFacility::Daemon, 5, "Oct  4 09:41:02", "x", 1, "{}");
        assert_eq!(f, "<29>Oct  4 09:41:02 x[1]: {}");
    }

    #[test]
    fn stamp_is_rfc3164() {
        let s = stamp(SystemTime::now());
        assert_eq!(s.len(), 15, "{s:?}");
        let b = s.as_bytes();
        assert!(b[0].is_ascii_uppercase() && b[3] == b' ' && b[6] == b' ' && b[9] == b':' && b[12] == b':', "{s:?}");
    }

    #[test]
    fn syslog_datagram_roundtrip() {
        let p = tmp("dgram.sock");
        let rx = UnixDatagram::bind(&p).unwrap();
        let mut s = Syslog::with_socket(SyslogFacility::Local3, "howdah", &p);
        s.send(LINE).unwrap();
        s.send(LINE).unwrap(); // reuses the socket
        let mut buf = vec![0u8; 4096];
        for _ in 0..2 {
            let n = rx.recv(&mut buf).unwrap();
            let msg = std::str::from_utf8(&buf[..n]).unwrap();
            let pri = 19 * 8 + 4;
            assert!(msg.starts_with(&format!("<{pri}>")), "{msg}");
            assert!(msg.ends_with(&format!(" howdah[{}]: {LINE}", std::process::id())), "{msg}");
        }
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn syslog_reconnects_after_daemon_restart() {
        let p = tmp("restart.sock");
        let rx = UnixDatagram::bind(&p).unwrap();
        let mut s = Syslog::with_socket(SyslogFacility::Local0, "howdah", &p);
        s.send(LINE).unwrap();
        drop(rx);
        let _ = fs::remove_file(&p);
        let rx = UnixDatagram::bind(&p).unwrap();
        s.send(LINE).unwrap();
        let mut buf = vec![0u8; 4096];
        let n = rx.recv(&mut buf).unwrap();
        assert!(std::str::from_utf8(&buf[..n]).unwrap().ends_with(LINE));
        let _ = fs::remove_file(&p);
    }

    /// A stream socket at the syslog path (some syslog-ng setups) is not
    /// used: the datagram connect fails at once and nothing waits on a
    /// listener that never accepts.
    #[test]
    fn stream_socket_is_refused_not_waited_on() {
        let p = tmp("stream.sock");
        let _l = UnixListener::bind(&p).unwrap(); // never accepts
        let mut s = Syslog::with_socket(SyslogFacility::Local0, "howdah", &p);
        let t = Instant::now();
        let e = s.send(LINE).unwrap_err();
        assert!(t.elapsed() < Duration::from_millis(500), "send waited {:?}", t.elapsed());
        assert_eq!(e.raw_os_error(), Some(libc::EPROTOTYPE), "{e}");
        let _ = fs::remove_file(&p);
    }

    /// A log file Howdah creates is 0640 at most (the umask can only remove
    /// bits); an existing file keeps its mode.
    #[test]
    fn new_log_file_is_not_world_readable() {
        let p = tmp("mode.log");
        append_line(&p, "{}").unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & !LOG_FILE_MODE, 0, "mode {mode:o} has bits beyond 0640");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        append_line(&p, "{}").unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_file(&p);
    }

    #[test]
    fn syslog_without_a_daemon_is_an_error_not_a_panic() {
        let mut s = Syslog::with_socket(SyslogFacility::Local0, "howdah", &tmp("absent.sock"));
        assert!(s.send(LINE).is_err());
    }

    #[test]
    fn file_lines_are_appended_whole() {
        let p = tmp("events.log");
        append_line(&p, "{\"a\":1}").unwrap();
        append_line(&p, "{\"a\":2}").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
        let _ = fs::remove_file(&p);
        assert!(append_line("/nonexistent-dir/howdah.log", "{}").is_err());
    }

    #[test]
    fn emit_falls_back_without_panicking() {
        let mut s = Settings::resolve(Some("/nonexistent-dir/howdah.log"), &cfg(""));
        s.emit(LINE); // loud note + stderr, no panic
        let mut s = Settings {
            target: Target::Syslog(Syslog::with_socket(SyslogFacility::Local0, "howdah", &tmp("none.sock"))),
            hook: None,
        };
        s.emit(LINE);
    }

    #[test]
    fn rate_window_slides() {
        let mut h = Hook::new("/bin/true", 3);
        let t0 = Instant::now();
        assert!(h.allow(t0));
        assert!(h.allow(t0 + Duration::from_millis(100)));
        assert!(h.allow(t0 + Duration::from_millis(200)));
        assert!(!h.allow(t0 + Duration::from_millis(900)));
        // The first spawn leaves the window one second after it happened.
        assert!(h.allow(t0 + Duration::from_millis(1000)));
        assert!(!h.allow(t0 + Duration::from_millis(1050)));
        assert!(h.allow(t0 + Duration::from_millis(1100)));
    }

    #[test]
    fn rule_action_is_sanitised() {
        assert_eq!(rule_action(LINE), ("max_parts".to_string(), "block".to_string()));
        assert_eq!(rule_action("not json"), ("unknown".to_string(), "unknown".to_string()));
        assert_eq!(
            rule_action(r#"{"rule":"a b;rm -rf /","action":"LOG"}"#),
            ("unknown".to_string(), "unknown".to_string())
        );
    }
}
