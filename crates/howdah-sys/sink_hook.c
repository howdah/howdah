/* Layer 3 sink hooks (productized from the proven spike; see the Layer-3 design
 * §9/§10.4). Installs a function-table handler swap over the dangerous
 * command/code-exec functions and `unserialize`, extracts the call's first
 * string argument, and asks Rust (`howdah-core` via the glue callback) for a
 * decision. On BLOCK it neutralizes the call the `disable_functions` way — sets
 * the return value false and returns without invoking the original, so the
 * dangerous operation never runs and the script continues (no mid-VM bailout).
 *
 * ABI: the PHP 5 vs 7/8 internal-function ABIs differ (hash-find key length,
 * argument access, handler signature); both are handled here with the real PHP
 * macros, which is why this lives in C (like `shim.c`) rather than in bindgen.
 * NTS only, like the rest of Howdah.
 *
 * 1.2 scope: this installs ONLY the function-table-swap sinks. include/eval
 * (the ZEND_INCLUDE_OR_EVAL opcode) are NOT hooked in 1.2 — see design §10.4.
 */
#include "main/php.h"
#include "Zend/zend_API.h"

#include <stddef.h>

/* Must match HOWDAH_SINK_* in howdah-core's ffi.rs and the glue's action codes
 * (0 ALLOW, 1 LOG, 2 BLOCK). */
#define HOWDAH_SINK_COMMAND_EXEC 0
#define HOWDAH_SINK_UNSERIALIZE  3
#define HOWDAH_SINK_BLOCK        2

/* The glue callback: decides for one intercepted call. Returns 0/1/2. */
typedef int (*howdah_sink_decide_t)(int sink, const char *name, size_t name_len,
                                    const char *arg, size_t arg_len);
static howdah_sink_decide_t howdah_g_decide = NULL;

typedef void (*howdah_zif)(INTERNAL_FUNCTION_PARAMETERS);

/* Read the call's first argument as a string into (p,len); ok=1 on success.
 * `execute_data` is in scope inside the handler on PHP 7/8; PHP 5 uses
 * zend_get_parameters_ex with the handler's threaded TSRMLS. A non-string or
 * absent first arg leaves ok=0 and the call is chained unguarded (fail-open). */
#if PHP_VERSION_ID >= 70000
#define HOWDAH_ARG1_STR(p, len, ok)                                            \
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
#define HOWDAH_ARG1_STR(p, len, ok)                                            \
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

/* Define a saved-original slot and a trampoline for one hooked function. */
#define HOWDAH_DEFINE_SINK(cname, phpname, sinkid)                             \
    static howdah_zif howdah_orig_##cname = NULL;                             \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {           \
        const char *arg = NULL;                                              \
        size_t arglen = 0;                                                   \
        int ok = 0;                                                          \
        HOWDAH_ARG1_STR(arg, arglen, ok);                                   \
        if (ok && howdah_g_decide) {                                         \
            int d = howdah_g_decide((sinkid), (phpname), sizeof(phpname) - 1, \
                                    arg, arglen);                            \
            if (d == HOWDAH_SINK_BLOCK) {                                    \
                RETVAL_FALSE;                                                \
                return; /* neutralize: do not call the original */          \
            }                                                               \
        }                                                                   \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);              \
    }

/* command/code execution sinks (first string arg is the command) + unserialize
 * (first string arg is the serialized payload). */
HOWDAH_DEFINE_SINK(system, "system", HOWDAH_SINK_COMMAND_EXEC)
HOWDAH_DEFINE_SINK(exec, "exec", HOWDAH_SINK_COMMAND_EXEC)
HOWDAH_DEFINE_SINK(shell_exec, "shell_exec", HOWDAH_SINK_COMMAND_EXEC)
HOWDAH_DEFINE_SINK(passthru, "passthru", HOWDAH_SINK_COMMAND_EXEC)
HOWDAH_DEFINE_SINK(popen, "popen", HOWDAH_SINK_COMMAND_EXEC)
HOWDAH_DEFINE_SINK(proc_open, "proc_open", HOWDAH_SINK_COMMAND_EXEC)
HOWDAH_DEFINE_SINK(unserialize, "unserialize", HOWDAH_SINK_UNSERIALIZE)

/* Look up `phpname` in the function table and swap its handler, saving the
 * original. PHP 5 hash keys include the trailing NUL (sizeof); PHP 7/8 do not
 * (sizeof-1). A function that is absent or not internal is skipped. */
#if PHP_VERSION_ID >= 70000
#define HOWDAH_INSTALL_SINK(cname, phpname)                                    \
    do {                                                                       \
        zend_function *_f = (zend_function *)zend_hash_str_find_ptr(            \
            CG(function_table), (phpname), sizeof(phpname) - 1);               \
        if (_f && _f->type == ZEND_INTERNAL_FUNCTION) {                        \
            howdah_orig_##cname = _f->internal_function.handler;               \
            _f->internal_function.handler = howdah_hook_##cname;               \
        }                                                                      \
    } while (0)
#else
#define HOWDAH_INSTALL_SINK(cname, phpname)                                    \
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

/* Install all Layer-3 function-table hooks. Call once at MINIT, after the
 * builtin modules have registered their functions. `cb` is the glue decision
 * callback; a NULL cb leaves the trampolines chaining unguarded. */
void howdah_install_sink_hooks(howdah_sink_decide_t cb) {
    howdah_g_decide = cb;
    HOWDAH_INSTALL_SINK(system, "system");
    HOWDAH_INSTALL_SINK(exec, "exec");
    HOWDAH_INSTALL_SINK(shell_exec, "shell_exec");
    HOWDAH_INSTALL_SINK(passthru, "passthru");
    HOWDAH_INSTALL_SINK(popen, "popen");
    HOWDAH_INSTALL_SINK(proc_open, "proc_open");
    HOWDAH_INSTALL_SINK(unserialize, "unserialize");
}
