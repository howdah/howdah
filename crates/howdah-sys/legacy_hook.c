/* Layer 3 legacy-era sinks (Howdah 1.5). Function-table handler swaps, the
 * mechanism of sink_hook.c, over the cheap legacy sinks:
 *
 *   mail            mail(): 4th arg (additional_headers) and 5th
 *                   (additional_parameters), both scanned by the core
 *   preg_eval       preg_replace / preg_filter pattern with /e (PHP 5.x only;
 *                   7.0 removed the modifier, so nothing is installed there)
 *   create_function create_function() body (5.x and 7.x; absent on 8.x)
 *   assert          assert() with a string argument (5.x and 7.x; 8.0 stopped
 *                   evaluating strings, so nothing is installed there)
 *   callback        a string callback naming a command/code-exec function
 *                   passed to call_user_func(_array), array_map, array_filter,
 *                   array_walk, usort/uasort/uksort, preg_replace_callback,
 *                   register_shutdown_function, ob_start
 *   xml             an XML document (simplexml_load_string, DOMDocument::loadXML)
 *                   declaring an external entity / DTD, plus the libxml-level
 *                   `external_entities = "deny"` toggle (howdah_xml_deny_...)
 *   tls             curl_setopt / curl_setopt_array turning
 *                   CURLOPT_SSL_VERIFYPEER off or CURLOPT_SSL_VERIFYHOST to 0
 *                   (detect-only: the chain is never neutralized)
 *
 * Per call the trampoline reads the one argument the sink is about, asks the
 * glue (which asks the core) and on BLOCK returns the function's failure value
 * without calling the original (the disable_functions model); otherwise it
 * chains. No policy lives here; argument bytes go to the core and are never
 * logged. Each swap is installed at first RINIT only when its sink is armed
 * (zero overhead when off) and only when the function exists on this PHP.
 * NTS only, like the rest of Howdah. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* RTLD_DEFAULT */
#endif
#include "main/php.h"
#include "Zend/zend_API.h"
#include "Zend/zend_execute.h"

#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <dlfcn.h>

#include "howdah_sink.h"

typedef int (*howdah_sink_decide_t)(int sink, const char *name, size_t name_len,
                                    const char *arg, size_t arg_len);
/* mail(): two arguments, either may be absent (NULL/0). */
typedef int (*howdah_mail_decide_t)(const char *headers, size_t headers_len,
                                    const char *params, size_t params_len);

static howdah_sink_decide_t g_decide = NULL;
static howdah_mail_decide_t g_mail_decide = NULL;

typedef void (*howdah_zif)(INTERNAL_FUNCTION_PARAMETERS);

/* ARG(n, var): the n-th call argument (dereferenced), or NULL if absent.
 * (Same accessor as ssrf_hook.c; 5.x reads up to 8 arguments.) */
#if PHP_VERSION_ID >= 70000
#define HOWDAH_ARG(n, var)                                                     \
    do {                                                                       \
        (var) = NULL;                                                          \
        if (ZEND_NUM_ARGS() >= (n)) {                                          \
            (var) = ZEND_CALL_ARG(execute_data, (n));                          \
            if (var) ZVAL_DEREF(var);                                          \
        }                                                                      \
    } while (0)
#else
#define HOWDAH_ARG(n, var)                                                     \
    do {                                                                       \
        zval **_all[8];                                                        \
        (var) = NULL;                                                          \
        if (ZEND_NUM_ARGS() >= (n) && ZEND_NUM_ARGS() <= 8                     \
            && zend_get_parameters_array_ex(ZEND_NUM_ARGS(), _all) == SUCCESS) \
            (var) = *_all[(n) - 1];                                            \
    } while (0)
#endif

#define HOWDAH_IS_STR(z) ((z) && Z_TYPE_P(z) == IS_STRING)

/* The longest dangerous callback name plus a leading backslash (mirrors
 * MAX_DANGEROUS_CALLBACK_LEN in howdah-core): longer strings skip the call
 * into the core entirely, so hot `array_map('trim', ...)`-style callers pay
 * one length compare. */
#define HOWDAH_CALLBACK_MAX 16

/* One string-argument sink: argument `argn`, sink id, the value a blocked
 * call returns, and an optional length prefilter (0 = none). */
#define HOWDAH_DEFINE_LEGACY_SINK(cname, phpname, sinkid, argn, blockret, maxlen)   \
    static howdah_zif howdah_orig_##cname = NULL;                                 \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {               \
        zval *_a;                                                                 \
        HOWDAH_ARG((argn), _a);                                                   \
        if (g_decide && HOWDAH_IS_STR(_a)                                         \
            && ((maxlen) == 0 || Z_STRLEN_P(_a) <= (size_t)(maxlen))               \
            && g_decide((sinkid), (phpname), sizeof(phpname) - 1,                  \
                        Z_STRVAL_P(_a), Z_STRLEN_P(_a)) == HOWDAH_ACTION_BLOCK) {  \
            blockret;                                                             \
            return; /* neutralize: do not call the original */                    \
        }                                                                         \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                    \
    }

/* ---- create_function / string assert (gone or inert on 8.x) ------------- */
#if PHP_VERSION_ID < 80000
HOWDAH_DEFINE_LEGACY_SINK(create_function, "create_function", HOWDAH_SINK_CREATE_FUNCTION, 2, RETVAL_FALSE, 0)
HOWDAH_DEFINE_LEGACY_SINK(assert, "assert", HOWDAH_SINK_ASSERT, 1, RETVAL_FALSE, 0)
#endif

/* ---- string callbacks ---------------------------------------------------- */
HOWDAH_DEFINE_LEGACY_SINK(call_user_func, "call_user_func", HOWDAH_SINK_CALLBACK, 1, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(call_user_func_array, "call_user_func_array", HOWDAH_SINK_CALLBACK, 1, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(array_map, "array_map", HOWDAH_SINK_CALLBACK, 1, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(array_filter, "array_filter", HOWDAH_SINK_CALLBACK, 2, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(array_walk, "array_walk", HOWDAH_SINK_CALLBACK, 2, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(usort, "usort", HOWDAH_SINK_CALLBACK, 2, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(uasort, "uasort", HOWDAH_SINK_CALLBACK, 2, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(uksort, "uksort", HOWDAH_SINK_CALLBACK, 2, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(preg_replace_callback, "preg_replace_callback", HOWDAH_SINK_CALLBACK, 2, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(register_shutdown_function, "register_shutdown_function", HOWDAH_SINK_CALLBACK, 1, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)
HOWDAH_DEFINE_LEGACY_SINK(ob_start, "ob_start", HOWDAH_SINK_CALLBACK, 1, RETVAL_FALSE, HOWDAH_CALLBACK_MAX)

/* ---- XML documents ------------------------------------------------------- */
HOWDAH_DEFINE_LEGACY_SINK(simplexml_load_string, "simplexml_load_string", HOWDAH_SINK_XML, 1, RETVAL_FALSE, 0)
HOWDAH_DEFINE_LEGACY_SINK(domdocument_loadxml, "DOMDocument::loadXML", HOWDAH_SINK_XML, 1, RETVAL_FALSE, 0)

/* ---- mail ---------------------------------------------------------------- */
static howdah_zif howdah_orig_mail = NULL;
static void howdah_hook_mail(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h, *p;
    HOWDAH_ARG(4, h);
    HOWDAH_ARG(5, p);
    /* An array of headers (7.2+) is validated by PHP itself; only string
     * arguments are offered to the core. */
    if (g_mail_decide && (HOWDAH_IS_STR(h) || HOWDAH_IS_STR(p))) {
        int d = g_mail_decide(HOWDAH_IS_STR(h) ? Z_STRVAL_P(h) : NULL,
                              HOWDAH_IS_STR(h) ? Z_STRLEN_P(h) : 0,
                              HOWDAH_IS_STR(p) ? Z_STRVAL_P(p) : NULL,
                              HOWDAH_IS_STR(p) ? Z_STRLEN_P(p) : 0);
        if (d == HOWDAH_ACTION_BLOCK) {
            RETVAL_FALSE; /* refused: nothing is handed to sendmail */
            return;
        }
    }
    howdah_orig_mail(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ---- preg /e (PHP 5.x only) ---------------------------------------------- */
#if PHP_VERSION_ID < 70000
/* 1 iff any pattern (a string, or each string in an array) is blocked. */
static int howdah_preg_blocked(zval *pat, const char *fn, size_t fnlen) {
    if (!g_decide || !pat) return 0;
    if (Z_TYPE_P(pat) == IS_STRING) {
        return g_decide(HOWDAH_SINK_PREG_EVAL, fn, fnlen, Z_STRVAL_P(pat), Z_STRLEN_P(pat))
               == HOWDAH_ACTION_BLOCK;
    }
    if (Z_TYPE_P(pat) == IS_ARRAY) {
        HashPosition pos;
        zval **v;
        HashTable *ht = Z_ARRVAL_P(pat);
        for (zend_hash_internal_pointer_reset_ex(ht, &pos);
             zend_hash_get_current_data_ex(ht, (void **)&v, &pos) == SUCCESS;
             zend_hash_move_forward_ex(ht, &pos)) {
            if (v && *v && Z_TYPE_PP(v) == IS_STRING
                && g_decide(HOWDAH_SINK_PREG_EVAL, fn, fnlen, Z_STRVAL_PP(v), Z_STRLEN_PP(v))
                   == HOWDAH_ACTION_BLOCK) {
                return 1;
            }
        }
    }
    return 0;
}
#define HOWDAH_DEFINE_PREG_SINK(cname, phpname)                                \
    static howdah_zif howdah_orig_##cname = NULL;                              \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {            \
        zval *_p;                                                              \
        HOWDAH_ARG(1, _p);                                                     \
        if (howdah_preg_blocked(_p, (phpname), sizeof(phpname) - 1)) {         \
            RETVAL_NULL(); /* what preg_replace returns on error */            \
            return;                                                            \
        }                                                                      \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                 \
    }
HOWDAH_DEFINE_PREG_SINK(preg_replace, "preg_replace")
HOWDAH_DEFINE_PREG_SINK(preg_filter, "preg_filter")
#endif

/* ---- curl TLS verification (detect-only) --------------------------------- */
#define HOWDAH_CURLOPT_SSL_VERIFYPEER 64
#define HOWDAH_CURLOPT_SSL_VERIFYHOST 81

/* 1 iff a curl_setopt value means "off": false, 0, "0", "", null. */
static int howdah_tls_off(zval *v) {
    if (!v) return 0;
    switch (Z_TYPE_P(v)) {
#if PHP_VERSION_ID >= 70000
        case IS_FALSE: return 1;
#else
        case IS_BOOL: return Z_BVAL_P(v) == 0;
#endif
        case IS_NULL: return 1;
        case IS_LONG: return Z_LVAL_P(v) == 0;
        case IS_STRING: return Z_STRLEN_P(v) == 0 || (Z_STRLEN_P(v) == 1 && Z_STRVAL_P(v)[0] == '0');
        default: return 0;
    }
}

/* Offer one (option, value) pair to the core. The verdict is ignored: the
 * tls sink is detect-only, the core clamps block to log, and the call always
 * chains. The core receives an option TOKEN, never the URL or the handle. */
static void howdah_tls_check(long opt, zval *v, const char *fn, size_t fnlen) {
    if (!g_decide || !howdah_tls_off(v)) return;
    if (opt == HOWDAH_CURLOPT_SSL_VERIFYPEER) {
        g_decide(HOWDAH_SINK_TLS, fn, fnlen, "verifypeer", 10);
    } else if (opt == HOWDAH_CURLOPT_SSL_VERIFYHOST) {
        g_decide(HOWDAH_SINK_TLS, fn, fnlen, "verifyhost", 10);
    }
}

static howdah_zif howdah_orig_curl_setopt = NULL, howdah_orig_curl_setopt_array = NULL;

static void howdah_hook_curl_setopt(INTERNAL_FUNCTION_PARAMETERS) {
    zval *o, *v;
    HOWDAH_ARG(2, o);
    HOWDAH_ARG(3, v);
    if (o && Z_TYPE_P(o) == IS_LONG) {
        howdah_tls_check((long)Z_LVAL_P(o), v, "curl_setopt", 11);
    }
    howdah_orig_curl_setopt(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static void howdah_hook_curl_setopt_array(INTERNAL_FUNCTION_PARAMETERS) {
    zval *arr;
    HOWDAH_ARG(2, arr);
    if (arr && Z_TYPE_P(arr) == IS_ARRAY) {
        long opts[2] = { HOWDAH_CURLOPT_SSL_VERIFYPEER, HOWDAH_CURLOPT_SSL_VERIFYHOST };
        int i;
        for (i = 0; i < 2; i++) {
#if PHP_VERSION_ID >= 70000
            zval *v = zend_hash_index_find(Z_ARRVAL_P(arr), (zend_ulong)opts[i]);
            if (v) {
                ZVAL_DEREF(v);
                howdah_tls_check(opts[i], v, "curl_setopt_array", 17);
            }
#else
            zval **pv;
            if (zend_hash_index_find(Z_ARRVAL_P(arr), (ulong)opts[i], (void **)&pv) == SUCCESS) {
                howdah_tls_check(opts[i], *pv, "curl_setopt_array", 17);
            }
#endif
        }
    }
    howdah_orig_curl_setopt_array(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ---- install ------------------------------------------------------------- */
/* Swap one function; evaluates to 1 if it was found and swapped. */
#if PHP_VERSION_ID >= 70000
static int howdah_swap(const char *name, size_t len, howdah_zif hook, howdah_zif *orig) {
    zend_function *f = (zend_function *)zend_hash_str_find_ptr(CG(function_table), name, len);
    if (!f || f->type != ZEND_INTERNAL_FUNCTION || *orig) return *orig != NULL;
    *orig = f->internal_function.handler;
    f->internal_function.handler = hook;
    return 1;
}
static int howdah_swap_method(const char *cls, size_t clen, const char *m, size_t mlen,
                              howdah_zif hook, howdah_zif *orig) {
    zend_class_entry *ce = (zend_class_entry *)zend_hash_str_find_ptr(CG(class_table), cls, clen);
    zend_function *f;
    if (!ce) return 0;
    f = (zend_function *)zend_hash_str_find_ptr(&ce->function_table, m, mlen);
    if (!f || f->type != ZEND_INTERNAL_FUNCTION || *orig) return *orig != NULL;
    *orig = f->internal_function.handler;
    f->internal_function.handler = hook;
    return 1;
}
#else
static int howdah_swap(const char *name, size_t len, howdah_zif hook, howdah_zif *orig) {
    zend_function *f = NULL;
    if (zend_hash_find(CG(function_table), name, (uint)len + 1, (void **)&f) != SUCCESS
        || !f || f->type != ZEND_INTERNAL_FUNCTION || *orig) return *orig != NULL;
    *orig = f->internal_function.handler;
    f->internal_function.handler = hook;
    return 1;
}
static int howdah_swap_method(const char *cls, size_t clen, const char *m, size_t mlen,
                              howdah_zif hook, howdah_zif *orig) {
    zend_class_entry **pce = NULL;
    zend_function *f = NULL;
    if (zend_hash_find(CG(class_table), cls, (uint)clen + 1, (void **)&pce) != SUCCESS || !pce || !*pce)
        return 0;
    if (zend_hash_find(&(*pce)->function_table, m, (uint)mlen + 1, (void **)&f) != SUCCESS
        || !f || f->type != ZEND_INTERNAL_FUNCTION || *orig) return *orig != NULL;
    *orig = f->internal_function.handler;
    f->internal_function.handler = hook;
    return 1;
}
#endif
#define HOWDAH_SWAP(cname, phpname) howdah_swap((phpname), sizeof(phpname) - 1, howdah_hook_##cname, &howdah_orig_##cname)

/* Install the legacy sinks named by `mask` (HOWDAH_LEGACY_* bits). Call once
 * at first RINIT (shared curl/dom/simplexml extensions may load after howdah
 * at MINIT). A sink whose function does not exist on this PHP is skipped;
 * the returned mask says what was actually installed (for phpinfo). */
int howdah_install_legacy_hooks(howdah_sink_decide_t cb, howdah_mail_decide_t mail_cb, int mask) {
    int done = 0;
    g_decide = cb;
    g_mail_decide = mail_cb;
    if ((mask & HOWDAH_LEGACY_MAIL) && HOWDAH_SWAP(mail, "mail")) done |= HOWDAH_LEGACY_MAIL;
#if PHP_VERSION_ID < 70000
    if (mask & HOWDAH_LEGACY_PREG_EVAL) {
        int a = HOWDAH_SWAP(preg_replace, "preg_replace");
        int b = HOWDAH_SWAP(preg_filter, "preg_filter");
        if (a || b) done |= HOWDAH_LEGACY_PREG_EVAL;
    }
#endif
#if PHP_VERSION_ID < 80000
    if ((mask & HOWDAH_LEGACY_CREATE_FUNCTION) && HOWDAH_SWAP(create_function, "create_function"))
        done |= HOWDAH_LEGACY_CREATE_FUNCTION;
    if ((mask & HOWDAH_LEGACY_ASSERT) && HOWDAH_SWAP(assert, "assert")) done |= HOWDAH_LEGACY_ASSERT;
#endif
    if (mask & HOWDAH_LEGACY_CALLBACK) {
        int n = 0;
        n += HOWDAH_SWAP(call_user_func, "call_user_func");
        n += HOWDAH_SWAP(call_user_func_array, "call_user_func_array");
        n += HOWDAH_SWAP(array_map, "array_map");
        n += HOWDAH_SWAP(array_filter, "array_filter");
        n += HOWDAH_SWAP(array_walk, "array_walk");
        n += HOWDAH_SWAP(usort, "usort");
        n += HOWDAH_SWAP(uasort, "uasort");
        n += HOWDAH_SWAP(uksort, "uksort");
        n += HOWDAH_SWAP(preg_replace_callback, "preg_replace_callback");
        n += HOWDAH_SWAP(register_shutdown_function, "register_shutdown_function");
        n += HOWDAH_SWAP(ob_start, "ob_start");
        if (n) done |= HOWDAH_LEGACY_CALLBACK;
    }
    if (mask & HOWDAH_LEGACY_XML) {
        int a = HOWDAH_SWAP(simplexml_load_string, "simplexml_load_string");
        int b = howdah_swap_method("domdocument", 11, "loadxml", 7, howdah_hook_domdocument_loadxml,
                                   &howdah_orig_domdocument_loadxml);
        if (a || b) done |= HOWDAH_LEGACY_XML;
    }
    if (mask & HOWDAH_LEGACY_TLS) {
        int a = HOWDAH_SWAP(curl_setopt, "curl_setopt");
        int b = HOWDAH_SWAP(curl_setopt_array, "curl_setopt_array");
        if (a || b) done |= HOWDAH_LEGACY_TLS;
    }
    return done;
}

/* ext/libxml's C-level setter, PHP_LIBXML_API on every supported version
 * (5.4: `zend_bool f(zend_bool)`; 7.x/8.0: the same; 8.1+: `bool f(bool)`). The
 * one-byte boolean argument and result are int-compatible in the C calling
 * conventions Howdah ships for (x86_64 SysV, aarch64 AAPCS64). Resolved at
 * run time with dlsym, not linked: a PHP built without libxml must still load
 * howdah.so. The lab images carry ext/libxml/php_libxml.h but not libxml2's
 * own headers, so the prototype is declared here rather than included. */
typedef int (*howdah_libxml_disable_t)(int disable);

/* `[sinks.xml] external_entities = "deny"`: turn libxml's external entity
 * loader off for the current request. Called at every RINIT (after
 * ext/libxml's, which resets the flag per request).
 *
 * Preferred path: php_libxml_disable_entity_loader(1) directly (the C setter
 * behind the userland function), found once with dlsym. It carries no
 * deprecation, so on PHP 8 nothing lands in error_get_last() or the error
 * log. Fallback, when the symbol is not exported (no ext/libxml, or a future
 * PHP that removed it): the userland libxml_disable_entity_loader(true)
 * through the function table, with error_reporting at 0 so PHP 8's
 * deprecation is not logged (it still sets error_get_last() for that request;
 * documented). Returns 1 when either call was made, 0 when neither exists. */
int howdah_xml_deny_external_entities(void) {
    static const char fn_name[] = "libxml_disable_entity_loader";
    static howdah_libxml_disable_t direct = NULL;
    static int looked_up = 0;
    int saved, ok;
    if (!looked_up) {
        looked_up = 1;
        direct = (howdah_libxml_disable_t)(uintptr_t)dlsym(RTLD_DEFAULT, "php_libxml_disable_entity_loader");
    }
    if (direct) {
        direct(1);
        return 1;
    }
#if PHP_VERSION_ID >= 70000
    zval fname, retval, arg;
    if (!zend_hash_str_find_ptr(CG(function_table), fn_name, sizeof(fn_name) - 1)) return 0;
    ZVAL_STRINGL(&fname, fn_name, sizeof(fn_name) - 1);
    ZVAL_TRUE(&arg);
    ZVAL_UNDEF(&retval);
    saved = EG(error_reporting);
    EG(error_reporting) = 0;
    ok = call_user_function(CG(function_table), NULL, &fname, &retval, 1, &arg) == SUCCESS;
    EG(error_reporting) = saved;
    zval_ptr_dtor(&retval);
    zval_ptr_dtor(&fname);
    return ok;
#else
    zval *fname, *arg, retval;
    zval *params[1];
    zend_function *f = NULL;
    TSRMLS_FETCH();
    if (zend_hash_find(CG(function_table), fn_name, sizeof(fn_name), (void **)&f) != SUCCESS) return 0;
    MAKE_STD_ZVAL(fname);
    ZVAL_STRINGL(fname, fn_name, sizeof(fn_name) - 1, 1);
    MAKE_STD_ZVAL(arg);
    ZVAL_BOOL(arg, 1);
    params[0] = arg;
    INIT_ZVAL(retval);
    saved = EG(error_reporting);
    EG(error_reporting) = 0;
    ok = call_user_function(CG(function_table), NULL, fname, &retval, 1, params TSRMLS_CC) == SUCCESS;
    EG(error_reporting) = saved;
    zval_dtor(&retval);
    zval_ptr_dtor(&arg);
    zval_ptr_dtor(&fname);
    return ok;
#endif
}
