/* Layer 3 mixed-case TLS URL scheme guard (CVE-2026-128064).
 *
 * PHP's http and ftp stream wrappers decide TLS from a LOWERCASE 's' at a fixed
 * offset of the URL scheme (http_fopen_wrapper.c: scheme[4]=='s'; ftp: scheme[3]),
 * but the wrapper LOOKUP lowercases the protocol, so `HTTPS://` reaches the
 * wrapper and is then connected in plaintext. We proxy the http/https and
 * ftp/ftps wrappers' ops the way phar_hook.c proxies phar: every url-taking op
 * checks the scheme (via the core's classifier, passed in as `lenfn`), reports
 * it, and in fix mode hands PHP a COPY of the URL with only the scheme
 * lowercased. The caller's buffer is never touched.
 *
 * Install only where the registrant is PHP's own wrapper object
 * (&php_stream_http_wrapper / &php_stream_ftp_wrapper); an app or extension
 * replacement is left alone. The structs are `const` (read-only memory), so
 * they are memcpy'd into writable statics and re-registered.
 *
 * Known gap: http redirects are followed by a direct recursive call inside
 * php_stream_url_wrap_http_ex, which never re-enters the wrapper op, so a
 * redirect Location of `HTTPS://...` is not seen here.
 *
 * ABI: same PHP 5 / 7+ split as phar_hook.c (const-ness, opened_path type,
 * TSRMLS). Only the ops struct is touched, never php_stream internals.
 */
#include "main/php.h"
#include "main/php_streams.h"
#include "ext/standard/php_fopen_wrappers.h"
#include "Zend/zend_API.h"

#include <string.h>
#include <stddef.h>

#include "howdah_sink.h"

typedef int (*howdah_sink_decide_t)(int sink, const char *name, size_t name_len,
                                    const char *arg, size_t arg_len);
typedef size_t (*howdah_scheme_len_t)(const char *url, size_t len);

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

static howdah_sink_decide_t hs_decide = NULL;
static howdah_scheme_len_t hs_lenfn = NULL;
static int hs_mode = 0; /* 1 detect (log only), 2 fix */

/* Returns `url` unchanged, or (fix mode) an emalloc'd copy with the scheme
 * lowercased which the caller must release with howdah_scheme_done(). */
static HOWDAH_CP howdah_scheme_fix(HOWDAH_CP url) {
    size_t len, n;
    char lname[8];
    int action;
    if (!url || !hs_lenfn || !hs_decide || !hs_mode) {
        return url;
    }
    len = strlen(url);
    n = hs_lenfn(url, len);
    if (n == 0 || n >= sizeof(lname)) {
        return url;
    }
    {
        size_t i;
        for (i = 0; i < n; i++) {
            char ch = url[i];
            lname[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
        }
    }
    action = hs_decide(HOWDAH_SINK_SCHEME_CASE, lname, n, url, len);
    if (hs_mode != 2 || action == 0 /* allow: scoped exception */) {
        return url; /* detect mode (or a scoped exception): report only */
    }
    {
        char *copy = estrndup(url, len);
        memcpy(copy, lname, n);
        return (HOWDAH_CP)copy;
    }
}

static void howdah_scheme_done(HOWDAH_CP orig, HOWDAH_CP used) {
    if (used != orig) {
        efree((void *)used);
    }
}

#define HOWDAH_SCHEME_PROXY(PFX)                                                          \
static php_stream_wrapper_ops PFX##_orig_ops;                                             \
static php_stream_wrapper_ops PFX##_our_ops;                                              \
static php_stream_wrapper PFX##_our_wrapper;                                              \
                                                                                          \
static php_stream *PFX##_open(php_stream_wrapper *w, HOWDAH_CP fn, HOWDAH_CP mode,        \
                              int options, HOWDAH_OPP op,                                 \
                              php_stream_context *c STREAMS_DC HOWDAH_TSD) {              \
    HOWDAH_CP u = howdah_scheme_fix(fn);                                                  \
    php_stream *r = PFX##_orig_ops.stream_opener(w, u, mode, options, op, c               \
                                                 STREAMS_CC HOWDAH_TSC);                  \
    howdah_scheme_done(fn, u);                                                            \
    return r;                                                                             \
}                                                                                         \
static int PFX##_stat(php_stream_wrapper *w, HOWDAH_CP url, int flags,                    \
                      php_stream_statbuf *ssb, php_stream_context *c HOWDAH_TSD) {        \
    HOWDAH_CP u = howdah_scheme_fix(url);                                                 \
    int r = PFX##_orig_ops.url_stat(w, u, flags, ssb, c HOWDAH_TSC);                      \
    howdah_scheme_done(url, u);                                                           \
    return r;                                                                             \
}                                                                                         \
static php_stream *PFX##_dir(php_stream_wrapper *w, HOWDAH_CP fn, HOWDAH_CP mode,         \
                             int options, HOWDAH_OPP op,                                  \
                             php_stream_context *c STREAMS_DC HOWDAH_TSD) {               \
    HOWDAH_CP u = howdah_scheme_fix(fn);                                                  \
    php_stream *r = PFX##_orig_ops.dir_opener(w, u, mode, options, op, c                  \
                                              STREAMS_CC HOWDAH_TSC);                     \
    howdah_scheme_done(fn, u);                                                            \
    return r;                                                                             \
}                                                                                         \
static int PFX##_unlink(php_stream_wrapper *w, HOWDAH_CP url, int options,                \
                        php_stream_context *c HOWDAH_TSD) {                               \
    HOWDAH_CP u = howdah_scheme_fix(url);                                                 \
    int r = PFX##_orig_ops.unlink(w, u, options, c HOWDAH_TSC);                           \
    howdah_scheme_done(url, u);                                                           \
    return r;                                                                             \
}                                                                                         \
static int PFX##_rename(php_stream_wrapper *w, HOWDAH_CP from, HOWDAH_CP to,              \
                        int options, php_stream_context *c HOWDAH_TSD) {                  \
    HOWDAH_CP uf = howdah_scheme_fix(from);                                               \
    HOWDAH_CP ut = howdah_scheme_fix(to);                                                 \
    int r = PFX##_orig_ops.rename(w, uf, ut, options, c HOWDAH_TSC);                      \
    howdah_scheme_done(from, uf);                                                         \
    howdah_scheme_done(to, ut);                                                           \
    return r;                                                                             \
}                                                                                         \
static int PFX##_mkdir(php_stream_wrapper *w, HOWDAH_CP url, int mode, int options,       \
                       php_stream_context *c HOWDAH_TSD) {                                \
    HOWDAH_CP u = howdah_scheme_fix(url);                                                 \
    int r = PFX##_orig_ops.stream_mkdir(w, u, mode, options, c HOWDAH_TSC);               \
    howdah_scheme_done(url, u);                                                           \
    return r;                                                                             \
}                                                                                         \
static int PFX##_rmdir(php_stream_wrapper *w, HOWDAH_CP url, int options,                 \
                       php_stream_context *c HOWDAH_TSD) {                                \
    HOWDAH_CP u = howdah_scheme_fix(url);                                                 \
    int r = PFX##_orig_ops.stream_rmdir(w, u, options, c HOWDAH_TSC);                     \
    howdah_scheme_done(url, u);                                                           \
    return r;                                                                             \
}

HOWDAH_SCHEME_PROXY(hs_http)
HOWDAH_SCHEME_PROXY(hs_ftp)

static php_stream_wrapper *howdah_find_wrapper(HashTable *h, const char *name) {
    size_t n = strlen(name);
#if PHP_VERSION_ID >= 70000
    return (php_stream_wrapper *)zend_hash_str_find_ptr(h, name, n);
#else
    {
        php_stream_wrapper **pp = NULL;
        if (zend_hash_find(h, name, (uint)(n + 1), (void **)&pp) == SUCCESS && pp) {
            return *pp;
        }
        return NULL;
    }
#endif
}

/* Re-register `names` (all currently PHP's `own` wrapper) under our proxy. */
static int howdah_scheme_reregister(const char *const *names, php_stream_wrapper *own,
                                    php_stream_wrapper *ours HOWDAH_TSD) {
    HashTable *h = php_stream_get_url_stream_wrappers_hash_global();
    int done = 0;
    int i;
    for (i = 0; names[i]; i++) {
        php_stream_wrapper *cur = howdah_find_wrapper(h, names[i]);
        if (cur != own) {
            continue; /* absent, replaced by an app/extension, or already ours */
        }
        php_unregister_url_stream_wrapper((char *)names[i] HOWDAH_TSC);
        if (php_register_url_stream_wrapper((char *)names[i], ours HOWDAH_TSC) != SUCCESS) {
            php_register_url_stream_wrapper((char *)names[i], own HOWDAH_TSC);
        } else {
            done++;
        }
    }
    return done;
}

/* Install once at first RINIT. `mode`: 1 detect, 2 fix. Returns the number of
 * scheme registrations proxied (0 when none were PHP's own wrapper). */
int howdah_install_scheme_hook(howdah_sink_decide_t cb, howdah_scheme_len_t lenfn, int mode) {
    static const char *const http_names[] = {"http", "https", NULL};
    static const char *const ftp_names[] = {"ftp", "ftps", NULL};
    php_stream_wrapper *http_own = (php_stream_wrapper *)&php_stream_http_wrapper;
    php_stream_wrapper *ftp_own = (php_stream_wrapper *)&php_stream_ftp_wrapper;
    int done = 0;
#if PHP_VERSION_ID < 70000
    TSRMLS_FETCH();
#endif
    if (!cb || !lenfn || (mode != 1 && mode != 2) || hs_decide) {
        return 0; /* hs_decide set = already installed */
    }
    hs_decide = cb;
    hs_lenfn = lenfn;
    hs_mode = mode;

    if (http_own->wops && http_own->wops->stream_opener) {
        memcpy(&hs_http_orig_ops, http_own->wops, sizeof(hs_http_orig_ops));
        memcpy(&hs_http_our_ops, http_own->wops, sizeof(hs_http_our_ops));
        hs_http_our_ops.stream_opener = hs_http_open;
        if (hs_http_orig_ops.url_stat) hs_http_our_ops.url_stat = hs_http_stat;
        if (hs_http_orig_ops.dir_opener) hs_http_our_ops.dir_opener = hs_http_dir;
        if (hs_http_orig_ops.unlink) hs_http_our_ops.unlink = hs_http_unlink;
        if (hs_http_orig_ops.rename) hs_http_our_ops.rename = hs_http_rename;
        if (hs_http_orig_ops.stream_mkdir) hs_http_our_ops.stream_mkdir = hs_http_mkdir;
        if (hs_http_orig_ops.stream_rmdir) hs_http_our_ops.stream_rmdir = hs_http_rmdir;
        memcpy(&hs_http_our_wrapper, http_own, sizeof(hs_http_our_wrapper));
        hs_http_our_wrapper.wops = &hs_http_our_ops;
        done += howdah_scheme_reregister(http_names, http_own, &hs_http_our_wrapper HOWDAH_TSC);
    }
    if (ftp_own->wops && ftp_own->wops->stream_opener) {
        memcpy(&hs_ftp_orig_ops, ftp_own->wops, sizeof(hs_ftp_orig_ops));
        memcpy(&hs_ftp_our_ops, ftp_own->wops, sizeof(hs_ftp_our_ops));
        hs_ftp_our_ops.stream_opener = hs_ftp_open;
        if (hs_ftp_orig_ops.url_stat) hs_ftp_our_ops.url_stat = hs_ftp_stat;
        if (hs_ftp_orig_ops.dir_opener) hs_ftp_our_ops.dir_opener = hs_ftp_dir;
        if (hs_ftp_orig_ops.unlink) hs_ftp_our_ops.unlink = hs_ftp_unlink;
        if (hs_ftp_orig_ops.rename) hs_ftp_our_ops.rename = hs_ftp_rename;
        if (hs_ftp_orig_ops.stream_mkdir) hs_ftp_our_ops.stream_mkdir = hs_ftp_mkdir;
        if (hs_ftp_orig_ops.stream_rmdir) hs_ftp_our_ops.stream_rmdir = hs_ftp_rmdir;
        memcpy(&hs_ftp_our_wrapper, ftp_own, sizeof(hs_ftp_our_wrapper));
        hs_ftp_our_wrapper.wops = &hs_ftp_our_ops;
        done += howdah_scheme_reregister(ftp_names, ftp_own, &hs_ftp_our_wrapper HOWDAH_TSC);
    }
    return done;
}
