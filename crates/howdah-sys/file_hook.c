/* File-operation hub: the T4 include/open wrapper-scheme firewall and the T5
 * Layer-4 delete / secret-read guards. A function-table handler swap (same
 * mechanism as sink_hook.c / ssrf_hook.c) over the file sinks that are NOT
 * already swapped by ssrf_hook.c:
 *
 *   readfile, file   read a file (arg1 = path/URL)              op READ
 *   unlink, rmdir    delete a file / directory (arg1 = path)    op DELETE
 *                    (swapped only when the delete guard is armed)
 *
 * fopen and file_get_contents are already swapped by ssrf_hook.c (for the SSRF
 * egress + Layer-4 php-write checks); those trampolines call
 * howdah_file_firewall_check (exported here) after their own checks, so the hub
 * sees them WITHOUT a second swap of the same function. rename is swapped in
 * ssrf_hook.c too; its SOURCE operand goes to the same hub (op MOVE_SRC).
 *
 * Per call the C does NO classification: it hands the target string to Rust
 * (howdah-core via the glue callback), which classifies it (stream-wrapper
 * scheme, poisonable local target, sensitive file name, traversal) and returns
 * the action. The Layer-4 origin (executing script + line) is read by the glue
 * from zend_get_executed_filename()/lineno() inside the same call. On BLOCK the
 * trampoline neutralizes the call the disable_functions way (RETVAL_FALSE, do
 * not call the original), so the script continues with no mid-VM bailout.
 *
 * ABI: the PHP 5 vs 7/8 argument access differs; both handled with the real PHP
 * macros, as in sink_hook.c. NTS only, like the rest of Howdah.
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

/* Define a saved-original slot and a trampoline for one file sink whose arg1 is
 * the path, classified as `op` (a HOWDAH_FILE_OP_* code). */
#define HOWDAH_DEFINE_FILE_SINK(cname, phpname, op)                            \
    static howdah_zif howdah_orig_##cname = NULL;                              \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {            \
        const char *arg = NULL;                                               \
        size_t arglen = 0;                                                    \
        int ok = 0;                                                           \
        HOWDAH_FILE_ARG1(arg, arglen, ok);                                    \
        if (ok                                                                \
            && howdah_file_firewall_check((phpname), sizeof(phpname) - 1, arg, \
                                          arglen, (op))) {                     \
            RETVAL_FALSE;                                                      \
            return; /* neutralize: do not call the original */                \
        }                                                                     \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                 \
    }

HOWDAH_DEFINE_FILE_SINK(readfile, "readfile", HOWDAH_FILE_OP_READ)
HOWDAH_DEFINE_FILE_SINK(file, "file", HOWDAH_FILE_OP_READ)
HOWDAH_DEFINE_FILE_SINK(unlink, "unlink", HOWDAH_FILE_OP_DELETE)
HOWDAH_DEFINE_FILE_SINK(rmdir, "rmdir", HOWDAH_FILE_OP_DELETE)

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

/* Install the file-op hub. Sets the shared decide callback and swaps the sinks
 * owned here: the read sinks (readfile, file) always, and per `ops` the delete
 * sinks (unlink, rmdir). fopen / file_get_contents / rename are swapped by
 * ssrf_hook.c and call howdah_file_firewall_check once the callback is set.
 * Call once at first RINIT when the hub is armed. Idempotent: a second call
 * just refreshes the callback (a repeat swap would re-save our own trampoline
 * as the "original" — hence the static guard below). */
void howdah_install_file_hooks(howdah_file_decide_t decide, int ops) {
    static int installed = 0;
    howdah_g_file_decide = decide;
    if (installed) {
        return;
    }
    installed = 1;
    HOWDAH_FILE_SWAP(readfile, "readfile");
    HOWDAH_FILE_SWAP(file, "file");
    if (ops & HOWDAH_FILE_HOOK_DELETE) {
        HOWDAH_FILE_SWAP(unlink, "unlink");
        HOWDAH_FILE_SWAP(rmdir, "rmdir");
    }
}
