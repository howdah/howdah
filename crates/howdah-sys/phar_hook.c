/* Layer 3 phar:// guard (productized from the proven spike; see the Layer-3
 * fast-follow design §5.1). Proxies the `phar` stream wrapper's ops so every
 * phar:// access (open, stat, opendir, unlink, rename, mkdir, rmdir) is first
 * offered to Rust (`howdah-core` via the glue callback) with the FULL
 * `phar://...` URL. On BLOCK the op returns its "missing file" sentinel
 * (NULL / -1 / 0) without calling phar, so the archive is never parsed and no
 * metadata is unserialized; otherwise the call chains to phar's original op.
 *
 * phar's wrapper struct and ops table are `static const` (read-only memory):
 * patching them in place SEGVs. We memcpy both into our own statics, point our
 * wrapper copy at our ops, then unregister + re-register "phar".
 *
 * ABI: PHP 5 uses `char *` paths, `char **opened_path` and threads TSRMLS; PHP
 * 7/8 use `const char *`, `zend_string **opened_path` and no TSRMLS. Handled
 * behind PHP_VERSION_ID. NTS only, like the rest of Howdah.
 */
#include "main/php.h"
#include "main/php_streams.h"
#include "Zend/zend_API.h"
#include "Zend/zend_exceptions.h"
#include "Zend/zend_compile.h"

#include <string.h>
#include <stddef.h>

#include "howdah_sink.h"

/* Same type as sink_hook.c. */
typedef int (*howdah_sink_decide_t)(int sink, const char *name, size_t name_len,
                                    const char *arg, size_t arg_len);

/* Path constness: char * through 5.5, const char * from 5.6 (verified against
 * the 5.4 and 5.6 php_streams.h). opened_path: char ** until 7.0, zend_string **
 * from 7.0. TSRMLS is threaded only on PHP 5. */
#if PHP_VERSION_ID >= 50600
# define HOWDAH_CP  const char *
#else
# define HOWDAH_CP  char *
#endif
#if PHP_VERSION_ID >= 70000
# define HOWDAH_TSD
# define HOWDAH_TSC
# define HOWDAH_OPP zend_string **
#else
# define HOWDAH_TSD TSRMLS_DC
# define HOWDAH_TSC TSRMLS_CC
# define HOWDAH_OPP char **
#endif

static howdah_sink_decide_t howdah_phar_decide = NULL;
static php_stream_wrapper_ops howdah_phar_orig_ops;
static php_stream_wrapper_ops howdah_phar_our_ops;
static php_stream_wrapper howdah_phar_our_wrapper;

/* ---- CVE-2026-128090: phar signature-type guard ------------------------------
 * When `<archive>.pubkey` exists beside an archive, the owner pinned an OpenSSL
 * key, but phar takes the signature TYPE from the archive itself, so a keyless
 * digest (MD5/SHA1/SHA256/SHA512) skips the key check. Before phar parses the
 * archive we read the declared type (core classifier, fed by plain pread() on
 * the archive path: no php_stream internals, so it is ABI-stable 5.4-8.6) and
 * refuse anything that is not an OpenSSL type.
 *
 * Reached from: every phar:// wrapper op (below), and the Phar / PharData
 * constructors, Phar::loadPhar and Phar::mapPhar (new Phar('x.phar') never
 * touches the phar:// wrapper). A plain `include 'x.phar'` is NOT guarded: it
 * runs the archive's stub as ordinary PHP, which no signature ever protected.
 *
 * Cost with no sibling .pubkey: one expand_filepath + one stat, cached per
 * request. The verdict is cached per archive path for the request. The glue
 * logs once (path and bytes are never logged); detect/indeterminate chains. */
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/stat.h>

typedef int (*howdah_phar_read_cb)(void *ctx, uint64_t off, uint8_t *buf, size_t len);
typedef int (*howdah_phar_classify_t)(uint64_t size, howdah_phar_read_cb rd, void *ctx);

extern const char *howdah_sys_current_script(void);

static int hp_sig_on = 0;
static howdah_phar_classify_t hp_classify = NULL;

#define HP_CACHE_N    8
#define HP_CACHE_PATH 1024
static struct { char path[HP_CACHE_PATH]; int blocked; } hp_cache[HP_CACHE_N];
static int hp_cache_n = 0;

/* Call at every RINIT: verdicts are per request. */
void howdah_phar_sig_reset(void) {
    hp_cache_n = 0;
}

static int hp_read(void *ctx, uint64_t off, uint8_t *buf, size_t len) {
    int fd = *(int *)ctx;
    size_t got = 0;
    while (got < len) {
        ssize_t r = pread(fd, buf + got, len - got, (off_t)(off + got));
        if (r <= 0) {
            return 0;
        }
        got += (size_t)r;
    }
    return 1;
}

static int hp_cache_get(const char *abs, int *blocked) {
    int i;
    for (i = 0; i < hp_cache_n; i++) {
        if (strcmp(hp_cache[i].path, abs) == 0) {
            *blocked = hp_cache[i].blocked;
            return 1;
        }
    }
    return 0;
}

static void hp_cache_put(const char *abs, int blocked) {
    if (hp_cache_n < HP_CACHE_N && strlen(abs) < HP_CACHE_PATH) {
        strcpy(hp_cache[hp_cache_n].path, abs);
        hp_cache[hp_cache_n].blocked = blocked;
        hp_cache_n++;
    }
}

/* 1 = refuse this archive. Fail-open on anything unexpected. */
static int hp_sig_check_archive(const char *path) {
    char *abs;
    char *pk = NULL;
    struct stat st;
    int blocked = 0, fd, cls;
    size_t n;

    if (!hp_sig_on || !hp_classify || !howdah_phar_decide || !path || !*path) {
        return 0;
    }
    abs = expand_filepath(path, NULL HOWDAH_TSC);
    if (!abs) {
        return 0;
    }
    if (hp_cache_get(abs, &blocked)) {
        efree(abs);
        return blocked;
    }
    n = strlen(abs);
    pk = emalloc(n + 8);
    memcpy(pk, abs, n);
    memcpy(pk + n, ".pubkey", 8);
    if (VCWD_STAT(pk, &st) != 0) {
        hp_cache_put(abs, 0); /* no pinned key: nothing to enforce */
    } else if (VCWD_STAT(abs, &st) != 0 || !S_ISREG(st.st_mode)) {
        /* archive absent/not a file: phar will fail by itself; do not cache */
    } else if ((fd = VCWD_OPEN(abs, O_RDONLY)) >= 0) {
        cls = hp_classify((uint64_t)st.st_size, hp_read, &fd);
        close(fd);
        if (cls == 1) {
            blocked = howdah_phar_decide(HOWDAH_SINK_PHAR_SIG, "phar", 4,
                                         "downgrade", 9) == HOWDAH_ACTION_BLOCK;
        } else if (cls == 2) {
            (void)howdah_phar_decide(HOWDAH_SINK_PHAR_SIG, "phar", 4,
                                     "indeterminate", 13); /* detect only */
        }
        hp_cache_put(abs, blocked);
    }
    efree(pk);
    efree(abs);
    return blocked;
}

/* phar:// URL -> archive: the first leading component of the path that is a
 * regular file is the archive (what phar does for an existing archive). */
static int hp_sig_blocked_url(const char *url) {
    const char *p, *q;
    char buf[HP_CACHE_PATH];
    struct stat st;
    if (!hp_sig_on || !url || strncasecmp(url, "phar://", 7) != 0) {
        return 0;
    }
    p = url + 7;
    for (q = p;; q++) {
        if (*q == '/' || *q == '\0') {
            size_t l = (size_t)(q - p);
            if (l > 0 && l < sizeof(buf)) {
                memcpy(buf, p, l);
                buf[l] = '\0';
                if (VCWD_STAT(buf, &st) == 0 && S_ISREG(st.st_mode)) {
                    return hp_sig_check_archive(buf);
                }
            }
            if (*q == '\0') {
                break;
            }
        }
    }
    return 0;
}

/* ---- Phar / PharData constructors, loadPhar, mapPhar ----------------------- */
typedef void (*howdah_zif)(INTERNAL_FUNCTION_PARAMETERS);
static howdah_zif hp_orig_phar_ctor, hp_orig_pharda_ctor, hp_orig_loadphar, hp_orig_mapphar;

#if PHP_VERSION_ID >= 70000
# define HP_ARG1_STR(p, ok)                                                    \
    do {                                                                       \
        (ok) = 0;                                                              \
        if (ZEND_NUM_ARGS() >= 1) {                                            \
            zval *_a = ZEND_CALL_ARG(execute_data, 1);                         \
            if (_a && Z_TYPE_P(_a) == IS_STRING) {                             \
                (p) = Z_STRVAL_P(_a);                                          \
                (ok) = 1;                                                      \
            }                                                                  \
        }                                                                      \
    } while (0)
# define HP_EXC() zend_ce_exception
#else
# define HP_ARG1_STR(p, ok)                                                    \
    do {                                                                       \
        zval **_a;                                                             \
        (ok) = 0;                                                              \
        if (ZEND_NUM_ARGS() >= 1 && zend_get_parameters_ex(1, &_a) == SUCCESS  \
            && Z_TYPE_PP(_a) == IS_STRING) {                                   \
            (p) = Z_STRVAL_PP(_a);                                             \
            (ok) = 1;                                                          \
        }                                                                      \
    } while (0)
# define HP_EXC() zend_exception_get_default(TSRMLS_C)
#endif

/* kind 0: constructor (throw), 1: loadPhar (false), 2: mapPhar (current script) */
#define HP_PHAR_METHOD(cname, kind)                                                   \
static void howdah_phar_##cname(INTERNAL_FUNCTION_PARAMETERS) {                       \
    const char *a = NULL;                                                             \
    int ok = 0;                                                                       \
    if ((kind) == 2) {                                                                \
        a = howdah_sys_current_script();                                              \
        ok = a != NULL;                                                               \
    } else {                                                                          \
        HP_ARG1_STR(a, ok);                                                           \
    }                                                                                 \
    if (ok && hp_sig_check_archive(a)) {                                              \
        if ((kind) == 0) {                                                            \
            zend_throw_exception(HP_EXC(), "phar signature check failed", 0           \
                                 HOWDAH_TSC);                                          \
        } else {                                                                      \
            RETVAL_FALSE;                                                             \
        }                                                                             \
        return;                                                                       \
    }                                                                                 \
    hp_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                                \
}
HP_PHAR_METHOD(phar_ctor, 0)
HP_PHAR_METHOD(pharda_ctor, 0)
HP_PHAR_METHOD(loadphar, 1)
HP_PHAR_METHOD(mapphar, 2)

static int hp_swap_method(const char *cls, size_t cl, const char *meth, size_t ml,
                          howdah_zif *orig, howdah_zif hook) {
    zend_class_entry *ce = NULL;
    zend_function *f = NULL;
#if PHP_VERSION_ID >= 70000
    ce = (zend_class_entry *)zend_hash_str_find_ptr(CG(class_table), cls, cl);
    if (ce) {
        f = (zend_function *)zend_hash_str_find_ptr(&ce->function_table, meth, ml);
    }
#else
    {
        zend_class_entry **cep = NULL;
        if (zend_hash_find(CG(class_table), cls, cl + 1, (void **)&cep) == SUCCESS && cep) {
            ce = *cep;
            if (zend_hash_find(&ce->function_table, meth, ml + 1, (void **)&f) != SUCCESS) {
                f = NULL;
            }
        }
    }
#endif
    if (!f || f->type != ZEND_INTERNAL_FUNCTION || *orig) {
        return 0;
    }
    *orig = f->internal_function.handler;
    f->internal_function.handler = hook;
    return 1;
}

static int hp_phar_armed = 0; /* [sinks.phar] mode (deserialization guard) armed */

/* 1 if the phar:// URL must be refused: the signature-downgrade guard
 * (CVE-2026-128090) first, then the callback's allowlist decision when the
 * deserialization sink is armed. Fail-open when no callback or no URL. */
static int howdah_phar_blocked(HOWDAH_CP url) {
    if (!howdah_phar_decide || !url) {
        return 0;
    }
    if (hp_sig_on && hp_sig_blocked_url(url)) {
        return 1;
    }
    if (!hp_phar_armed) {
        return 0;
    }
    return howdah_phar_decide(HOWDAH_SINK_PHAR, "phar", 4, url, strlen(url))
           == HOWDAH_ACTION_BLOCK;
}

static php_stream *howdah_phar_open(php_stream_wrapper *w, HOWDAH_CP fn, HOWDAH_CP mode,
                                    int options, HOWDAH_OPP op,
                                    php_stream_context *c STREAMS_DC HOWDAH_TSD) {
    if (howdah_phar_blocked(fn) || !howdah_phar_orig_ops.stream_opener) {
        return NULL;
    }
    return howdah_phar_orig_ops.stream_opener(w, fn, mode, options, op, c
                                              STREAMS_CC HOWDAH_TSC);
}

static int howdah_phar_stat(php_stream_wrapper *w, HOWDAH_CP url, int flags,
                            php_stream_statbuf *ssb, php_stream_context *c HOWDAH_TSD) {
    if (howdah_phar_blocked(url) || !howdah_phar_orig_ops.url_stat) {
        return -1;
    }
    return howdah_phar_orig_ops.url_stat(w, url, flags, ssb, c HOWDAH_TSC);
}

static php_stream *howdah_phar_dir(php_stream_wrapper *w, HOWDAH_CP fn, HOWDAH_CP mode,
                                   int options, HOWDAH_OPP op,
                                   php_stream_context *c STREAMS_DC HOWDAH_TSD) {
    if (howdah_phar_blocked(fn) || !howdah_phar_orig_ops.dir_opener) {
        return NULL;
    }
    return howdah_phar_orig_ops.dir_opener(w, fn, mode, options, op, c
                                           STREAMS_CC HOWDAH_TSC);
}

static int howdah_phar_unlink(php_stream_wrapper *w, HOWDAH_CP url, int options,
                              php_stream_context *c HOWDAH_TSD) {
    if (howdah_phar_blocked(url) || !howdah_phar_orig_ops.unlink) {
        return 0;
    }
    return howdah_phar_orig_ops.unlink(w, url, options, c HOWDAH_TSC);
}

static int howdah_phar_rename(php_stream_wrapper *w, HOWDAH_CP from, HOWDAH_CP to,
                              int options, php_stream_context *c HOWDAH_TSD) {
    if (howdah_phar_blocked(from) || howdah_phar_blocked(to)
        || !howdah_phar_orig_ops.rename) {
        return 0;
    }
    return howdah_phar_orig_ops.rename(w, from, to, options, c HOWDAH_TSC);
}

static int howdah_phar_mkdir(php_stream_wrapper *w, HOWDAH_CP url, int mode,
                             int options, php_stream_context *c HOWDAH_TSD) {
    if (howdah_phar_blocked(url) || !howdah_phar_orig_ops.stream_mkdir) {
        return 0;
    }
    return howdah_phar_orig_ops.stream_mkdir(w, url, mode, options, c HOWDAH_TSC);
}

static int howdah_phar_rmdir(php_stream_wrapper *w, HOWDAH_CP url, int options,
                             php_stream_context *c HOWDAH_TSD) {
    if (howdah_phar_blocked(url) || !howdah_phar_orig_ops.stream_rmdir) {
        return 0;
    }
    return howdah_phar_orig_ops.stream_rmdir(w, url, options, c HOWDAH_TSC);
}

static int howdah_phar_install_wrapper(howdah_sink_decide_t cb);

/* Arm the deserialization guard (`[sinks.phar] mode`). */
int howdah_install_phar_hook(howdah_sink_decide_t cb) {
    hp_phar_armed = 1;
    return howdah_phar_install_wrapper(cb);
}

/* Arm the signature-downgrade guard (CVE-2026-128090): proxy the phar wrapper
 * (shared with the deserialization guard) and the Phar / PharData open
 * entry points. `classify` is the core's howdah_phar_sig_classify. Returns the
 * number of entry points hooked (wrapper counts as one); 0 if phar is absent. */
int howdah_install_phar_sig_hook(howdah_sink_decide_t cb, howdah_phar_classify_t classify) {
    int n = 0;
    if (!cb || !classify) {
        return 0;
    }
    hp_classify = classify;
    n += howdah_phar_install_wrapper(cb);
    howdah_phar_decide = cb;
    hp_sig_on = 1;
    n += hp_swap_method("phar", 4, "__construct", 11, &hp_orig_phar_ctor, howdah_phar_phar_ctor);
    n += hp_swap_method("phardata", 8, "__construct", 11, &hp_orig_pharda_ctor, howdah_phar_pharda_ctor);
    n += hp_swap_method("phar", 4, "loadphar", 8, &hp_orig_loadphar, howdah_phar_loadphar);
    n += hp_swap_method("phar", 4, "mapphar", 7, &hp_orig_mapphar, howdah_phar_mapphar);
    return n;
}

/* Proxy the phar wrapper. Returns 1 if phar was found and proxied, 0 if phar is
 * not registered (honest no-op). Call once at first RINIT, after phar has registered. */
static int howdah_phar_install_wrapper(howdah_sink_decide_t cb) {
    php_stream_wrapper *pw = NULL;
    HashTable *h = php_stream_get_url_stream_wrappers_hash_global();
#if PHP_VERSION_ID < 70000
    TSRMLS_FETCH();
#endif

    if (!cb || !h) {
        return 0;
    }
#if PHP_VERSION_ID >= 70000
    pw = (php_stream_wrapper *)zend_hash_str_find_ptr(h, "phar", 4);
#else
    {
        php_stream_wrapper **pp = NULL;
        if (zend_hash_find(h, "phar", 5, (void **)&pp) == SUCCESS && pp) {
            pw = *pp;
        }
    }
#endif
    if (!pw || !pw->wops) {
        return 0;
    }
    if (pw == &howdah_phar_our_wrapper) {
        return 1; /* already installed: copying again would make orig_ops self-recurse */
    }

    howdah_phar_decide = cb;
    memcpy(&howdah_phar_orig_ops, pw->wops, sizeof(howdah_phar_orig_ops));
    memcpy(&howdah_phar_our_ops, pw->wops, sizeof(howdah_phar_our_ops));
    howdah_phar_our_ops.stream_opener = howdah_phar_open;
    howdah_phar_our_ops.url_stat = howdah_phar_stat;
    howdah_phar_our_ops.dir_opener = howdah_phar_dir;
    howdah_phar_our_ops.unlink = howdah_phar_unlink;
    howdah_phar_our_ops.rename = howdah_phar_rename;
    howdah_phar_our_ops.stream_mkdir = howdah_phar_mkdir;
    howdah_phar_our_ops.stream_rmdir = howdah_phar_rmdir;

    memcpy(&howdah_phar_our_wrapper, pw, sizeof(howdah_phar_our_wrapper));
    howdah_phar_our_wrapper.wops = &howdah_phar_our_ops;
    php_unregister_url_stream_wrapper("phar" HOWDAH_TSC);
    if (php_register_url_stream_wrapper("phar", &howdah_phar_our_wrapper HOWDAH_TSC)
        != SUCCESS) {
        /* Could not re-register: restore phar's own wrapper so it keeps working. */
        php_register_url_stream_wrapper("phar", pw HOWDAH_TSC);
        howdah_phar_decide = NULL;
        return 0;
    }
    return 1;
}
