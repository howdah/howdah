//! Read-only report of php.ini settings that are known preconditions for
//! exploited CVE classes. Pure Rust and host-testable: the PHP glue supplies
//! the current ini values, the SAPI name and a directory-mode lookup; nothing
//! here reads PHP state or changes any setting.
//!
//! Only flagged settings are returned. Informational items (`allow_url_fopen`,
//! `open_basedir` unset) are deliberately not flagged here; `howdah-check ini`
//! prints them separately. The same table lives in `tools/howdah-check`.

/// One flagged setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub setting: &'static str,
    /// Current value as PHP reports it.
    pub value: String,
    /// One-line reason.
    pub why: &'static str,
    /// What to set instead.
    pub fix: String,
}

impl Finding {
    /// Single-line text for a `phpinfo()` row value.
    pub fn row_value(&self) -> String {
        format!("{} -- {}. Set: {}", self.value, self.why, self.fix)
    }
}

/// The facts the checks need, supplied by the caller.
pub struct Env<'a> {
    /// `sapi_module.name`, e.g. `cli`, `fpm-fcgi`, `apache2handler`, `cgi-fcgi`.
    pub sapi: &'a str,
    /// Current ini value; `None` for unset or empty.
    pub get: &'a dyn Fn(&str) -> Option<String>,
    /// Unix permission bits of a directory, `None` if it cannot be read.
    pub dir_mode: &'a dyn Fn(&str) -> Option<u32>,
}

fn is_on(v: &Option<String>) -> bool {
    match v {
        Some(s) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "on" | "yes" | "true"),
        None => false,
    }
}

fn is_cli(sapi: &str) -> bool {
    matches!(sapi, "cli" | "phpdbg" | "embed")
}

fn is_cgi_family(sapi: &str) -> bool {
    matches!(sapi, "cgi" | "cgi-fcgi" | "fpm-fcgi")
}

/// Directory part of `session.save_path` (drops a leading `N;` / `N;MODE;`).
pub fn session_dir(save_path: &str) -> &str {
    match save_path.rfind(';') {
        Some(i) => &save_path[i + 1..],
        None => save_path,
    }
}

/// True when a path has a component that is a typical web docroot directory
/// name. A heuristic: Howdah does not know the real docroot.
pub fn looks_like_docroot(path: &str) -> bool {
    path.split('/').any(|c| {
        matches!(c, "public_html" | "htdocs" | "httpdocs" | "wwwroot" | "www" | "html" | "public")
    })
}

const EXEC_FUNCS: [&str; 6] = ["exec", "system", "passthru", "shell_exec", "popen", "proc_open"];

/// Run every check; returns only the flagged settings, in a stable order.
pub fn evaluate(env: &Env) -> Vec<Finding> {
    let get = |n: &str| (env.get)(n);
    let mut out = Vec::new();
    let mut push = |setting: &'static str, value: String, why: &'static str, fix: &str| {
        out.push(Finding { setting, value, why, fix: fix.to_string() });
    };

    let v = get("register_argc_argv");
    if is_on(&v) && !is_cli(env.sapi) {
        push(
            "register_argc_argv",
            v.unwrap_or_default(),
            "enabling condition for Craft CMS CVE-2024-56145 and Laravel CVE-2024-52301",
            "register_argc_argv = Off (the CLI SAPI always enables it itself)",
        );
    }
    let v = get("allow_url_include");
    if is_on(&v) {
        push("allow_url_include", v.unwrap_or_default(), "remote file inclusion", "allow_url_include = Off");
    }
    let v = get("session.upload_progress.enabled");
    if is_on(&v) {
        push(
            "session.upload_progress.enabled",
            v.unwrap_or_default(),
            "session-file writes attacker-controlled data; used in LFI-to-RCE chains",
            "session.upload_progress.enabled = Off unless an upload progress bar needs it",
        );
    }
    let handler = get("session.save_handler");
    if handler.as_deref().map(str::trim) == Some("files") {
        let raw = get("session.save_path").unwrap_or_default();
        let dir = session_dir(&raw).trim();
        let (is_default, d) = if dir.is_empty() { (true, "/tmp") } else { (false, dir) };
        let docroot = !is_default && looks_like_docroot(d);
        let world_readable = (env.dir_mode)(d).map(|m| m & 0o004 != 0).unwrap_or(false);
        if docroot || world_readable {
            let why = if docroot {
                "session file poisoning: session files under a web docroot can be served or included"
            } else {
                "session file poisoning: session files are named sess_<id>, so a directory others can list exposes valid session ids"
            };
            push(
                "session.save_path",
                if is_default { "(unset, system temp dir)".to_string() } else { raw.clone() },
                why,
                "session.save_path to a directory outside the docroot that only the PHP user can read (mode 0700)",
            );
        }
    }
    let v = get("display_errors");
    if !is_cli(env.sapi)
        && (is_on(&v) || v.as_deref().map(|s| s.eq_ignore_ascii_case("stdout")).unwrap_or(false))
    {
        push(
            "display_errors",
            v.unwrap_or_default(),
            "information disclosure: errors reveal paths, queries and versions to visitors",
            "display_errors = Off and log_errors = On",
        );
    }
    let v = get("expose_php");
    if is_on(&v) {
        push("expose_php", v.unwrap_or_default(), "version disclosure in the X-Powered-By header", "expose_php = Off");
    }
    let v = get("enable_dl");
    if is_on(&v) && !is_cli(env.sapi) {
        push(
            "enable_dl",
            v.unwrap_or_default(),
            "historic precondition for loading attacker-supplied extensions",
            "enable_dl = Off",
        );
    }
    let v = get("cgi.fix_pathinfo");
    if is_cgi_family(env.sapi) && is_on(&v) {
        push(
            "cgi.fix_pathinfo",
            v.unwrap_or_default(),
            "historic RCE precondition under CGI/FastCGI with nginx (an uploaded file served as image.jpg/x.php runs as PHP); safe when the web server only passes existing .php files",
            "cgi.fix_pathinfo = 0 after checking the app does not rely on PATH_INFO",
        );
    }
    let disabled: Vec<String> = get("disable_functions")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let enabled: Vec<&str> = EXEC_FUNCS.iter().copied().filter(|f| !disabled.iter().any(|d| d == f)).collect();
    if !enabled.is_empty() {
        let value = if disabled.is_empty() { "(empty)".to_string() } else { get("disable_functions").unwrap_or_default() };
        out.push(Finding {
            setting: "disable_functions",
            value,
            why: "command-execution functions stay callable after any code-injection bug",
            fix: format!("add {} to disable_functions if the app does not use them", enabled.join(", ")),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn run(sapi: &str, ini: &[(&str, &str)], modes: &[(&str, u32)]) -> Vec<Finding> {
        let m: HashMap<String, String> = ini.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let d: HashMap<String, u32> = modes.iter().map(|(k, v)| (k.to_string(), *v)).collect();
        let get = move |n: &str| m.get(n).filter(|v| !v.is_empty()).cloned();
        let dir_mode = move |p: &str| d.get(p).copied();
        evaluate(&Env { sapi, get: &get, dir_mode: &dir_mode })
    }

    // All six exec functions disabled, so the baseline has nothing flagged.
    const SAFE_DF: (&str, &str) = ("disable_functions", "exec,system,passthru,shell_exec,popen,proc_open");

    fn names(f: &[Finding]) -> Vec<&'static str> {
        f.iter().map(|x| x.setting).collect()
    }

    #[test]
    fn clean_config_flags_nothing() {
        assert!(run("fpm-fcgi", &[SAFE_DF, ("expose_php", "0"), ("display_errors", "0")], &[]).is_empty());
    }

    #[test]
    fn register_argc_argv_flagged_only_outside_cli() {
        let ini = [SAFE_DF, ("register_argc_argv", "1")];
        assert_eq!(names(&run("fpm-fcgi", &ini, &[])), ["register_argc_argv"]);
        assert_eq!(names(&run("apache2handler", &ini, &[])), ["register_argc_argv"]);
        assert!(run("cli", &ini, &[]).is_empty());
        let f = run("fpm-fcgi", &ini, &[]);
        assert!(f[0].why.contains("CVE-2024-56145") && f[0].why.contains("CVE-2024-52301"));
    }

    #[test]
    fn simple_flags() {
        let f = run(
            "apache2handler",
            &[SAFE_DF, ("allow_url_include", "On"), ("expose_php", "1"), ("display_errors", "1"), ("enable_dl", "1"),
              ("session.upload_progress.enabled", "1")],
            &[],
        );
        assert_eq!(
            names(&f),
            ["allow_url_include", "session.upload_progress.enabled", "display_errors", "expose_php", "enable_dl"]
        );
    }

    #[test]
    fn display_errors_stderr_and_cli_are_not_flagged() {
        assert!(run("fpm-fcgi", &[SAFE_DF, ("display_errors", "stderr")], &[]).is_empty());
        assert!(run("cli", &[SAFE_DF, ("display_errors", "1")], &[]).is_empty());
    }

    #[test]
    fn fix_pathinfo_only_for_cgi_family() {
        let ini = [SAFE_DF, ("cgi.fix_pathinfo", "1")];
        assert_eq!(names(&run("fpm-fcgi", &ini, &[])), ["cgi.fix_pathinfo"]);
        assert_eq!(names(&run("cgi-fcgi", &ini, &[])), ["cgi.fix_pathinfo"]);
        assert!(run("apache2handler", &ini, &[]).is_empty());
        assert!(run("fpm-fcgi", &[SAFE_DF, ("cgi.fix_pathinfo", "0")], &[]).is_empty());
    }

    #[test]
    fn disable_functions_lists_what_is_still_enabled() {
        let f = run("fpm-fcgi", &[("disable_functions", "exec, system")], &[]);
        assert_eq!(names(&f), ["disable_functions"]);
        assert_eq!(f[0].fix, "add passthru, shell_exec, popen, proc_open to disable_functions if the app does not use them");
        let f = run("fpm-fcgi", &[], &[]);
        assert_eq!(f[0].value, "(empty)");
        assert!(f[0].fix.contains("exec, system, passthru"));
    }

    #[test]
    fn session_path_world_readable_or_in_docroot() {
        let base = [SAFE_DF, ("session.save_handler", "files")];
        // Private dir: fine.
        let mut ini = base.to_vec();
        ini.push(("session.save_path", "/var/lib/php/sessions"));
        assert!(run("fpm-fcgi", &ini, &[("/var/lib/php/sessions", 0o1733)]).is_empty());
        // World-readable dir.
        assert_eq!(names(&run("fpm-fcgi", &ini, &[("/var/lib/php/sessions", 0o755)])), ["session.save_path"]);
        // Docroot heuristic, with the "N;MODE;" prefix form.
        let mut ini = base.to_vec();
        ini.push(("session.save_path", "2;0600;/home/u/public_html/sess"));
        assert_eq!(names(&run("fpm-fcgi", &ini, &[])), ["session.save_path"]);
        // Unset path: system temp dir, world-readable.
        assert_eq!(names(&run("fpm-fcgi", &base, &[("/tmp", 0o1777)])), ["session.save_path"]);
        // Non-files handler: not applicable.
        let ini = [SAFE_DF, ("session.save_handler", "redis"), ("session.save_path", "/tmp")];
        assert!(run("fpm-fcgi", &ini, &[("/tmp", 0o1777)]).is_empty());
    }

    #[test]
    fn row_value_is_one_line() {
        let f = run("fpm-fcgi", &[SAFE_DF, ("allow_url_include", "1")], &[]);
        assert_eq!(f[0].row_value(), "1 -- remote file inclusion. Set: allow_url_include = Off");
    }

    #[test]
    fn session_dir_strips_prefix() {
        assert_eq!(session_dir("/tmp"), "/tmp");
        assert_eq!(session_dir("2;/tmp"), "/tmp");
        assert_eq!(session_dir("2;0600;/tmp"), "/tmp");
    }
}
