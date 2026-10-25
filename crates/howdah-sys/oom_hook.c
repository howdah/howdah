/* The out-of-memory backstop's PHP-side piece (design:
 * docs/superpowers/specs/2026-10-24-howdah-php2shell-gaps-design.md, §4.6).
 *
 * On an unpatched engine PHP's out-of-memory handling longjmps out of the
 * current operation, which can leave request state half-built for later code to
 * read (PHP2Shell, CVE-2026-109618/109619). This shim saves and chains
 * `zend_error_cb`; on a matching error (an out-of-memory fatal, or any fatal
 * raised while PHP is still in request startup) it asks the Rust decide callback
 * — which logs one Howdah event line — and then `_exit()`s the worker BEFORE
 * PHP longjmps. php-fpm / Apache prefork start a fresh worker; the one request
 * that ran out of memory gets a dropped connection (nginx 502). Every other
 * error chains to the prior callback unchanged.
 *
 * `zend_error_cb`'s signature differs across generations:
 *   5.x : (int, const char *file, uint     line, const char *format, va_list)
 *   7.x : (int, const char *file, uint32_t line, const char *format, va_list)
 *   8.0 : (int, const char *file, uint32_t line, zend_string *message)
 *   8.1+: (int, zend_string *file, uint32_t line, zend_string *message)
 * 5.x/7.x carry a `format` string plus a `va_list`; we check the FORMAT prefix
 * and never consume `args` (it is forwarded to the prior handler untouched).
 * 8.0/8.1+ carry a pre-rendered `zend_string *message`; we check its bytes.
 *
 * NTS only, like the rest of Howdah. The install is process-global (MINIT);
 * MSHUTDOWN restores the prior callback. */
#include "main/php.h"
#include <string.h>   /* strlen */
#include <unistd.h>   /* _exit */
#include <stdarg.h>

/* Exit 0 is the safe code: php-fpm's emergency_restart_threshold counts only
 * SIGSEGV/SIGBUS (no exit code affects it), and Apache prefork treats child
 * exit codes 3/7/15 specially (15 shuts the whole server down) — 0 avoids all
 * of that and logs a clean child exit. nginx answers the dropped FastCGI
 * connection with 502; the master forks a replacement worker. The event is
 * recorded in Howdah's own log. */
#define HOWDAH_OOM_EXIT_CODE 0

/* Rust decide callback: returns 1 to end the worker (after logging), 0 to chain
 * to the prior zend_error_cb. `file`/`file_len`/`line` are the error's location
 * (the script path and line, for the event's reason). See
 * crates/howdah-ext/src/oom_filter.rs. */
typedef int (*howdah_oom_decide_t)(int type, const char *msg, size_t msg_len, int during_startup,
                                   const char *file, size_t file_len, uint32_t line);
static howdah_oom_decide_t howdah_oom_decide = NULL;

/* Per-generation argument types for zend_error_cb. */
#if PHP_VERSION_ID >= 80100
#  define HOWDAH_FILE_T zend_string *
#  define HOWDAH_LINE_T const uint32_t
#  define HOWDAH_MSG_IS_ZSTR 1
#  define HOWDAH_FILE_IS_ZSTR 1
#elif PHP_VERSION_ID >= 80000
#  define HOWDAH_FILE_T const char *
#  define HOWDAH_LINE_T const uint32_t
#  define HOWDAH_MSG_IS_ZSTR 1
#  define HOWDAH_FILE_IS_ZSTR 0
#elif PHP_VERSION_ID >= 70000
#  define HOWDAH_FILE_T const char *
#  define HOWDAH_LINE_T const uint32_t
#  define HOWDAH_MSG_IS_ZSTR 0
#  define HOWDAH_FILE_IS_ZSTR 0
#else
#  define HOWDAH_FILE_T const char *
#  define HOWDAH_LINE_T const uint
#  define HOWDAH_MSG_IS_ZSTR 0
#  define HOWDAH_FILE_IS_ZSTR 0
#endif

/* Extract the error location as (const char *, len) for the decide callback;
 * `file` is a zend_string* on 8.1+, a const char* elsewhere, and may be NULL. */
#if HOWDAH_FILE_IS_ZSTR
#  define HOWDAH_FILE_PTR(f) ((f) ? ZSTR_VAL(f) : NULL)
#  define HOWDAH_FILE_LEN(f) ((f) ? ZSTR_LEN(f) : 0)
#else
#  define HOWDAH_FILE_PTR(f) (f)
#  define HOWDAH_FILE_LEN(f) ((f) ? strlen(f) : 0)
#endif

#if HOWDAH_MSG_IS_ZSTR
typedef void (*howdah_zend_error_cb_t)(int, HOWDAH_FILE_T, HOWDAH_LINE_T, zend_string *);
#else
typedef void (*howdah_zend_error_cb_t)(int, HOWDAH_FILE_T, HOWDAH_LINE_T, const char *, va_list);
#endif
static howdah_zend_error_cb_t howdah_oom_prev_error_cb = NULL;

/* 1 while PG(during_request_startup) is set. PHP sets it at the top of
 * php_request_startup() and clears it only in php_execute_script(), never in
 * php_request_shutdown(), so it also reads 1 for a request that never runs a
 * script (an FPM "Primary script unknown" 404, a status/ping page). The
 * backstop treats a fatal in that window as startup_fatal; such requests are
 * practically fatal-free, so this is a safe over-approximation of "startup". */
static int howdah_oom_during_startup(void) {
    return PG(during_request_startup) ? 1 : 0;
}

#if HOWDAH_MSG_IS_ZSTR
static void howdah_oom_error_cb(int type, HOWDAH_FILE_T file, HOWDAH_LINE_T line, zend_string *message) {
    if (howdah_oom_decide && message &&
        howdah_oom_decide(type, ZSTR_VAL(message), ZSTR_LEN(message), howdah_oom_during_startup(),
                          HOWDAH_FILE_PTR(file), HOWDAH_FILE_LEN(file), (uint32_t) line)) {
        _exit(HOWDAH_OOM_EXIT_CODE);
    }
    if (howdah_oom_prev_error_cb) howdah_oom_prev_error_cb(type, file, line, message);
}
#else
static void howdah_oom_error_cb(int type, HOWDAH_FILE_T file, HOWDAH_LINE_T line, const char *format, va_list args) {
    /* Check the FORMAT prefix; do NOT consume args — forward it untouched. */
    if (howdah_oom_decide &&
        howdah_oom_decide(type, format, format ? strlen(format) : 0, howdah_oom_during_startup(),
                          HOWDAH_FILE_PTR(file), HOWDAH_FILE_LEN(file), (uint32_t) line)) {
        _exit(HOWDAH_OOM_EXIT_CODE);
    }
    if (howdah_oom_prev_error_cb) howdah_oom_prev_error_cb(type, file, line, format, args);
}
#endif

/* Save the current zend_error_cb and install Howdah's. Call once at MINIT, and
 * only when the backstop is armed (web SAPI, unpatched engine, oom_exit on).
 * Idempotent: a second call (a dl() or a re-MINIT without MSHUTDOWN) that found
 * our own hook already installed must not save it as the "prior" and recurse. */
void howdah_install_oom_hook(howdah_oom_decide_t cb) {
    if (zend_error_cb == howdah_oom_error_cb) {
        howdah_oom_decide = cb;
        return;
    }
    howdah_oom_decide = cb;
    howdah_oom_prev_error_cb = (howdah_zend_error_cb_t) zend_error_cb;
    zend_error_cb = howdah_oom_error_cb;
}

/* Restore the saved callback. A no-op when not installed. Only restores when
 * OUR hook is still the installed one: if a later-loaded extension replaced
 * zend_error_cb without chaining, we must not clobber its handler at shutdown.
 * Called from MSHUTDOWN. */
void howdah_uninstall_oom_hook(void) {
    if (zend_error_cb == howdah_oom_error_cb) {
        zend_error_cb = (void *) howdah_oom_prev_error_cb;
    }
    howdah_oom_prev_error_cb = NULL;
    howdah_oom_decide = NULL;
}

/* 1 iff the `memory_hard_limit_percent` ini directive is registered. Upstream's
 * out-of-memory fix (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) adds it; its presence
 * means the engine already handles out-of-memory safely, so the backstop stays
 * off. A runtime check on the registered directives, so distro backports count
 * too. Core ini entries are registered during php_module_startup(), before an
 * extension's MINIT, so this is accurate at the install site. */
int howdah_memory_hard_limit_percent_exists(void) {
#if PHP_VERSION_ID >= 70000
    return zend_hash_str_exists(EG(ini_directives),
        "memory_hard_limit_percent", sizeof("memory_hard_limit_percent") - 1) ? 1 : 0;
#else
    /* PHP 5.x has no `zend_hash_str_exists` (7.0+), and its key length includes
     * the trailing NUL. 5.x is never patched, so this always returns 0 there —
     * but it must still COMPILE and LINK, or the whole extension fails to load. */
    return zend_hash_exists(EG(ini_directives),
        "memory_hard_limit_percent", sizeof("memory_hard_limit_percent")) ? 1 : 0;
#endif
}
