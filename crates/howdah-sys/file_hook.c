/* Layer 3 file-operation hook foundation (T4 include/open wrapper-scheme
 * firewall; the reusable base T5 will extend with delete/read/write-target
 * guards). A function-table handler swap (same mechanism as sink_hook.c /
 * ssrf_hook.c) over the file-OPEN sinks that are NOT already swapped by
 * ssrf_hook.c:
 *
 *   readfile  — reads a file straight to the output buffer (arg1 = path/URL).
 *
 * fopen and file_get_contents are already swapped by ssrf_hook.c (for the SSRF
 * egress + Layer-4 php-write checks); those trampolines call
 * howdah_file_firewall_check (exported here) after their own checks, so the
 * file-open firewall sees them WITHOUT a second swap of the same function.
 *
 * Per call the C does NO classification: it hands the fully-resolved target to
 * Rust (howdah-core via the glue callback), which classifies the stream-wrapper
 * scheme and the poisonable-local-target set and returns the action. On BLOCK
 * the trampoline neutralizes the call the disable_functions way (RETVAL_FALSE,
 * do not call the original), so the script continues with no mid-VM bailout.
 *
 * ABI: the PHP 5 vs 7/8 argument access differs; both handled with the real PHP
 * macros, as in sink_hook.c. NTS only, like the rest of Howdah.
 *
 * EXTENSION POINT FOR T5: add a HOWDAH_DEFINE_FILE_READ_SINK (read-open, arg1 =
 * path) or a new macro for unlink/rmdir (delete) / write-target sinks, give it a
 * HOWDAH_FILE_OP_* code, and swap it in howdah_install_file_hooks. The shared
 * howdah_g_file_decide callback and howdah_file_firewall_check already carry the
 * op code through to the core, so no new glue plumbing is needed.
 */
#include "main/php.h"
#include "Zend/zend_API.h"
#include "Zend/zend_execute.h"

#include <string.h>
#include <stddef.h>

#include "howdah_sink.h"

/* The file-op decision callback (ext glue file_filter::decide). NULL => the
 * firewall is disarmed and every trampoline chains unguarded (fail-open). */
static howdah_file_decide_t howdah_g_file_decide = NULL;

typedef void (*howdah_zif)(INTERNAL_FUNCTION_PARAMETERS);

/* Read the call's first argument as a string into (p,len); ok=1 on success.
 * Same split as sink_hook.c's HOWDAH_ARG1_STR (PHP 7/8 use execute_data in
 * scope; PHP 5 uses zend_get_parameters_ex). */
#if PHP_VERSION_ID >= 70000
#define HOWDAH_FILE_ARG1(p, len, ok)                                           \
    do {                                                                       \
        (ok) = 0;                                                              \
        if (ZEND_NUM_ARGS() >= 1) {                                            \
            zval *_a = ZEND_CALL_ARG(execute_data, 1);                         \
            if (_a && Z_TYPE_P(_a) == IS_STRING) {                             \
                (p) = Z_STRVAL_P(_a);                                          \
                (len) = Z_STRLEN_P(_a);                                        \
                (ok) = 1;                                                      \
            }                                                                  \
        }                                                                      \
    } while (0)
#else
#define HOWDAH_FILE_ARG1(p, len, ok)                                           \
    do {                                                                       \
        zval **_a;                                                             \
        (ok) = 0;                                                              \
        if (ZEND_NUM_ARGS() >= 1 && zend_get_parameters_ex(1, &_a) == SUCCESS  \
            && Z_TYPE_PP(_a) == IS_STRING) {                                   \
            (p) = Z_STRVAL_PP(_a);                                             \
            (len) = Z_STRLEN_PP(_a);                                           \
            (ok) = 1;                                                          \
        }                                                                      \
    } while (0)
#endif

/* Shared file-open firewall check: 1 iff the call must be neutralized. Exported
 * for ssrf_hook.c's fopen / file_get_contents trampolines. Fail-open (0) when
 * the firewall is disarmed (callback NULL) or the target is NULL. */
int howdah_file_firewall_check(const char *name, size_t name_len,
                               const char *target, size_t target_len, int op) {
    if (!howdah_g_file_decide || !target) {
        return 0;
    }
    return howdah_g_file_decide(name, name_len, target, target_len, op)
           == HOWDAH_ACTION_BLOCK;
}

/* Define a saved-original slot and a trampoline for one read-open sink whose
 * arg1 is the path (op = HOWDAH_FILE_OP_READ). */
#define HOWDAH_DEFINE_FILE_READ_SINK(cname, phpname)                           \
    static howdah_zif howdah_orig_##cname = NULL;                              \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {            \
        const char *arg = NULL;                                               \
        size_t arglen = 0;                                                    \
        int ok = 0;                                                           \
        HOWDAH_FILE_ARG1(arg, arglen, ok);                                    \
        if (ok                                                                \
            && howdah_file_firewall_check((phpname), sizeof(phpname) - 1, arg, \
                                          arglen, HOWDAH_FILE_OP_READ)) {      \
            RETVAL_FALSE;                                                      \
            return; /* neutralize: do not call the original */                \
        }                                                                     \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                 \
    }

HOWDAH_DEFINE_FILE_READ_SINK(readfile, "readfile")

/* Look up `phpname` in the function table and swap its handler, saving the
 * original. PHP 5 hash keys include the trailing NUL (sizeof); PHP 7/8 do not
 * (sizeof-1). An absent / non-internal function is skipped. */
#if PHP_VERSION_ID >= 70000
#define HOWDAH_FILE_SWAP(cname, phpname)                                       \
    do {                                                                       \
        zend_function *_f = (zend_function *)zend_hash_str_find_ptr(            \
            CG(function_table), (phpname), sizeof(phpname) - 1);               \
        if (_f && _f->type == ZEND_INTERNAL_FUNCTION) {                        \
            howdah_orig_##cname = _f->internal_function.handler;               \
            _f->internal_function.handler = howdah_hook_##cname;               \
        }                                                                      \
    } while (0)
#else
#define HOWDAH_FILE_SWAP(cname, phpname)                                       \
    do {                                                                       \
        zend_function *_f = NULL;                                              \
        if (zend_hash_find(CG(function_table), (phpname), sizeof(phpname),     \
                           (void **)&_f) == SUCCESS                            \
            && _f && _f->type == ZEND_INTERNAL_FUNCTION) {                     \
            howdah_orig_##cname = _f->internal_function.handler;               \
            _f->internal_function.handler = howdah_hook_##cname;               \
        }                                                                      \
    } while (0)
#endif

/* Install the file-op foundation. Sets the shared decide callback and swaps the
 * read-open sinks owned here (readfile). fopen / file_get_contents are swapped
 * by howdah_install_ssrf_hooks and call howdah_file_firewall_check once the
 * callback is set. Call once at first RINIT when the firewall is armed.
 * Idempotent: a second call just refreshes the callback (the swap is guarded by
 * the saved-original being overwritten only via the function table, so a repeat
 * swap would re-save our own trampoline — hence the static guard below). */
void howdah_install_file_hooks(howdah_file_decide_t decide) {
    static int installed = 0;
    howdah_g_file_decide = decide;
    if (installed) {
        return;
    }
    installed = 1;
    HOWDAH_FILE_SWAP(readfile, "readfile");
    /* T5 extension point: add unlink/rmdir/write-target swaps here. */
}
