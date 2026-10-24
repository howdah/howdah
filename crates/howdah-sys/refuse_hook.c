/* The deferred refusal's PHP-side pieces (design:
 * docs/superpowers/specs/2026-10-24-howdah-refusal-path-design.md).
 *
 * A refusal decided during php_request_startup() (the multipart callback, a
 * RINIT check) must not zend_bailout(): startup runs inside one zend_try, the
 * longjmp makes php_request_startup() return FAILURE, and php-fpm answers that
 * with a forced close and exit(70). The ext glue records the verdict and
 * delivers it at the end of its RINIT: the response goes out through the SAPI,
 * and the script is kept from running by swapping zend_compile_file for one
 * request so the main script (and auto_prepend/append) compile to NULL.
 * zend_execute_scripts() treats a NULL op_array as "nothing to run" and
 * returns FAILURE without a message or a bailout; every SAPI ignores that
 * return and goes to php_request_shutdown(). Returning NULL from a compile
 * hook is the same neutralisation sink_hook.c uses for a blocked include on
 * PHP 5.x.
 *
 * The swap is per request, installed on top of whatever is there (opcache
 * included: a cached script would otherwise be served without calling the
 * next compile function), and restored by RSHUTDOWN. NTS only, like the rest
 * of Howdah. PHP 5 threads TSRMLS through these signatures; 7/8 do not. */
#include "main/php.h"
#include "main/php_output.h"
#include "Zend/zend_compile.h"

#if PHP_VERSION_ID < 70000
# define HOWDAH_TSRMLS_DC TSRMLS_DC
#else
# define HOWDAH_TSRMLS_DC
#endif

/* shim.c: one line to the SAPI error log. */
extern void howdah_sys_log_err(const char *msg);

static zend_op_array *(*howdah_refuse_prev_compile_file)(zend_file_handle *fh, int type HOWDAH_TSRMLS_DC) = NULL;
static int howdah_refuse_armed = 0;

/* The request is refused: nothing compiles, so nothing runs. The file handle
 * is left as the SAPI opened it; zend_execute_scripts() destroys it. */
static zend_op_array *howdah_refuse_compile_file(zend_file_handle *fh, int type HOWDAH_TSRMLS_DC) {
    (void)fh;
    (void)type;
    return NULL;
}

/* Install the per-request compile swap. Idempotent within a request. */
void howdah_refuse_arm(void) {
    if (howdah_refuse_armed) {
        return;
    }
    howdah_refuse_prev_compile_file = zend_compile_file;
    zend_compile_file = howdah_refuse_compile_file;
    howdah_refuse_armed = 1;
}

/* Restore the saved compile function. A no-op when not armed. The restore is
 * unconditional (the way opcache restores its own swap at shutdown): if some
 * other hook replaced the pointer during the refused request and did not put
 * ours back, leaving ours installed would compile EVERY later request on this
 * worker to NULL. That case is reported once per process to the SAPI error
 * log, since the other hook is dropped for the rest of the process. */
void howdah_refuse_disarm(void) {
    static int warned = 0;
    if (!howdah_refuse_armed) {
        return;
    }
    if (zend_compile_file != howdah_refuse_compile_file && !warned) {
        warned = 1;
        howdah_sys_log_err("howdah: zend_compile_file was replaced by another hook during a "
                           "refused request; restoring the compile function Howdah saved "
                           "(the other hook is no longer installed in this process)");
    }
    zend_compile_file = howdah_refuse_prev_compile_file;
    howdah_refuse_prev_compile_file = NULL;
    howdah_refuse_armed = 0;
}

/* Discard every active output handler (php_output_discard_all, PHP 5.4+).
 * Called right after the refusal body went out through ub_write: a handler
 * started at request startup (output_handler = ob_gzhandler, or
 * zlib.output_compression) would otherwise try to add Content-Encoding at
 * php_output_end_all, after our headers were sent, and warn "headers already
 * sent" on every refused request. Nothing of ours is in those buffers. */
void howdah_sys_output_discard_all(void) {
#if PHP_VERSION_ID < 70000
    TSRMLS_FETCH();
    php_output_discard_all(TSRMLS_C);
#else
    php_output_discard_all();
#endif
}

/* 1 while PHP is inside php_request_startup() (PG(during_request_startup),
 * set at the top of startup and cleared by php_execute_script()). This is the
 * phase the glue uses to decide "record for RINIT" versus "deliver now". */
int howdah_during_request_startup(void) {
#if PHP_VERSION_ID < 70000
    TSRMLS_FETCH();
#endif
    return PG(during_request_startup) ? 1 : 0;
}

/* Build $_SERVER now if auto_globals_jit has deferred it, so its variables
 * (REQUEST_URI, PATH_INFO, the HTTP_* headers) pass through the chained
 * input_filter before the script runs. A no-op when $_SERVER already exists.
 * Called at RINIT only when Layer 2 is armed. */
void howdah_force_server_global(void) {
#if PHP_VERSION_ID >= 70000
    zend_is_auto_global_str((char *)"_SERVER", sizeof("_SERVER") - 1);
#else
    TSRMLS_FETCH();
    zend_is_auto_global("_SERVER", sizeof("_SERVER") - 1 TSRMLS_CC);
#endif
}
