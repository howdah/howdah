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
 * Two mechanisms:
 *  - a function-table handler swap over the command/code-exec functions and
 *    `unserialize` (all PHP versions), and
 *  - a ZEND_INCLUDE_OR_EVAL user opcode handler for include/require/eval
 *    (PHP 7.0+). On BLOCK the opcode is skipped (result set NULL, opline
 *    advanced) so the include/eval never runs and the script continues.
 *  - PHP 5.x: the VM keeps opcode operands behind a static-inline accessor not
 *    callable from an extension, so instead the global zend_compile_file /
 *    zend_compile_string pointers are swapped (scoped to real runtime
 *    include/eval; see the 5.x block below).
 */
#include "main/php.h"
#include "Zend/zend_API.h"
#include "Zend/zend_compile.h"
#include "Zend/zend_execute.h"

#include <string.h>
#include <stddef.h>

/* Sink ids: must match HOWDAH_SINK_* in howdah-core's ffi.rs. */
#define HOWDAH_SINK_COMMAND_EXEC 0
#define HOWDAH_SINK_INCLUDE      1
#define HOWDAH_SINK_EVAL         2
#define HOWDAH_SINK_UNSERIALIZE  3
/* Action code returned by the decide callback (0 ALLOW, 1 LOG, 2 BLOCK) — this
 * is an ACTION, not a sink id (hence not in the HOWDAH_SINK_* family). */
#define HOWDAH_ACTION_BLOCK      2

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
            if (d == HOWDAH_ACTION_BLOCK) {                                    \
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

#if PHP_VERSION_ID >= 70000
/* ---- include/require/eval: ZEND_INCLUDE_OR_EVAL user opcode handler (7.0+) ----
 * op1 is the filename (include/require) or the code (eval). Read it as a string,
 * classify via extended_value, and ask the glue. On BLOCK, skip the opcode: set
 * its result NULL (if used) and advance the instruction pointer, so the
 * include/eval never runs and the VM continues. Fail-open (DISPATCH) on anything
 * unexpected — a non-string op1, no callback, or a non-block decision. */
static zval *howdah_op1_zval(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    switch (opline->op1_type) {
        case IS_CONST:
#if PHP_VERSION_ID >= 70300
            return RT_CONSTANT(opline, opline->op1);
#else
            return EX_CONSTANT(opline->op1);
#endif
        case IS_CV:
        case IS_VAR:
        case IS_TMP_VAR:
            return EX_VAR(opline->op1.var);
        default:
            return NULL;
    }
}

static int howdah_include_or_eval(zend_execute_data *execute_data) {
    const zend_op *opline = EX(opline);
    int is_eval = (opline->extended_value == ZEND_EVAL);
    zval *v;
    if (!howdah_g_decide) {
        return ZEND_USER_OPCODE_DISPATCH;
    }
    v = howdah_op1_zval(execute_data);
    if (!v || Z_TYPE_P(v) != IS_STRING) {
        return ZEND_USER_OPCODE_DISPATCH; /* non-string operand: fail open */
    }
    {
        int sink = is_eval ? HOWDAH_SINK_EVAL : HOWDAH_SINK_INCLUDE;
        const char *name = is_eval ? "eval" : "include";
        int d = howdah_g_decide(sink, name, strlen(name), Z_STRVAL_P(v), Z_STRLEN_P(v));
        if (d == HOWDAH_ACTION_BLOCK) {
            /* Free a computed op1 (IS_TMP_VAR/IS_VAR, e.g. `include $a.$b`) that
             * the skipped opcode would otherwise have freed — avoids a bounded
             * per-blocked-call leak. CV/CONST operands own nothing to free. */
            if (opline->op1_type & (IS_TMP_VAR | IS_VAR)) {
                zval_ptr_dtor_nogc(EX_VAR(opline->op1.var));
            }
            if (opline->result_type != IS_UNUSED) {
                ZVAL_NULL(EX_VAR(opline->result.var));
            }
            EX(opline) = opline + 1; /* skip the include/eval */
            return ZEND_USER_OPCODE_CONTINUE;
        }
    }
    return ZEND_USER_OPCODE_DISPATCH;
}
#endif

#if PHP_VERSION_ID < 70000
/* ---- include/require/eval on PHP 5.x: compile-pointer swap ----
 * Spike-proven on 5.6. We swap the global zend_compile_file/zend_compile_string
 * pointers. BLOCK = return NULL (no compile): include -> false, require does NOT
 * fatal (the require fatal lives in the opcode's open step, not the compile
 * step), eval -> false.
 *
 * SCOPING (critical): these pointers are ALSO used for the main script,
 * auto_prepend/append_file, create_function, assert("..."), preg /e and CLI -r.
 * Verified on 5.6.40:
 *  - the main script is compiled via zend_compile_file(h, ZEND_INCLUDE) too, so
 *    `type` alone cannot tell it apart; but at that point nothing is executing:
 *    EG(current_execute_data) == NULL. A runtime include/require(_once) is always
 *    called from inside the VM, so current_execute_data != NULL.
 *  - eval passes the description "<file>(<line>) : eval()'d code" (built by
 *    zend_make_compiled_string_description), NOT the bare literal; so we match
 *    the " : eval()'d code" SUFFIX. create_function, assert, preg /e and -r use
 *    different descriptions.
 *
 * OPCACHE CAVEAT: with opcache, an already-cached file is served without calling
 * zend_compile_file, so include guarding only sees the FIRST compile of a file
 * (cache misses). eval is never cached and is always seen. */
static zend_op_array *(*howdah_orig_compile_file)(zend_file_handle *fh, int type TSRMLS_DC) = NULL;
static zend_op_array *(*howdah_orig_compile_string)(zval *src, char *filename TSRMLS_DC) = NULL;

#define HOWDAH_EVAL_DESC_SUFFIX " : eval()'d code"

static zend_op_array *howdah_compile_file(zend_file_handle *fh, int type TSRMLS_DC) {
    if (howdah_g_decide && EG(current_execute_data) != NULL
        && (type == ZEND_INCLUDE || type == ZEND_REQUIRE
            || type == ZEND_INCLUDE_ONCE || type == ZEND_REQUIRE_ONCE)
        && fh && fh->filename) {
        int d = howdah_g_decide(HOWDAH_SINK_INCLUDE, "include", 7,
                                fh->filename, strlen(fh->filename));
        if (d == HOWDAH_ACTION_BLOCK) {
            return NULL;
        }
    }
    return howdah_orig_compile_file(fh, type TSRMLS_CC);
}

static zend_op_array *howdah_compile_string(zval *src, char *filename TSRMLS_DC) {
    if (howdah_g_decide && src && Z_TYPE_P(src) == IS_STRING && filename) {
        size_t fl = strlen(filename);
        size_t sl = sizeof(HOWDAH_EVAL_DESC_SUFFIX) - 1;
        if (fl >= sl && memcmp(filename + fl - sl, HOWDAH_EVAL_DESC_SUFFIX, sl) == 0) {
            int d = howdah_g_decide(HOWDAH_SINK_EVAL, "eval", 4,
                                    Z_STRVAL_P(src), Z_STRLEN_P(src));
            if (d == HOWDAH_ACTION_BLOCK) {
                return NULL;
            }
        }
    }
    return howdah_orig_compile_string(src, filename TSRMLS_CC);
}
#endif

/* Install all Layer-3 hooks. Call once at MINIT, after the builtin modules have
 * registered their functions. `cb` is the glue decision callback; a NULL cb
 * leaves the trampolines chaining unguarded. */
void howdah_install_sink_hooks(howdah_sink_decide_t cb) {
    howdah_g_decide = cb;
    HOWDAH_INSTALL_SINK(system, "system");
    HOWDAH_INSTALL_SINK(exec, "exec");
    HOWDAH_INSTALL_SINK(shell_exec, "shell_exec");
    HOWDAH_INSTALL_SINK(passthru, "passthru");
    HOWDAH_INSTALL_SINK(popen, "popen");
    HOWDAH_INSTALL_SINK(proc_open, "proc_open");
    HOWDAH_INSTALL_SINK(unserialize, "unserialize");
#if PHP_VERSION_ID >= 70000
    zend_set_user_opcode_handler(ZEND_INCLUDE_OR_EVAL, howdah_include_or_eval);
#else
    /* Always swap on 5.x; per-call decide + scoping handle off/armed. Guard
     * against double-install so we never chain to ourselves. */
    if (!howdah_orig_compile_file) {
        howdah_orig_compile_file = zend_compile_file;
        zend_compile_file = howdah_compile_file;
    }
    if (!howdah_orig_compile_string) {
        howdah_orig_compile_string = zend_compile_string;
        zend_compile_string = howdah_compile_string;
    }
#endif
}
