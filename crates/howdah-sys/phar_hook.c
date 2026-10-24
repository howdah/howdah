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

/* 1 if the decision callback says BLOCK for this phar URL. Fail-open when no
 * callback or no URL. */
static int howdah_phar_blocked(HOWDAH_CP url) {
    if (!howdah_phar_decide || !url) {
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

/* Proxy the phar wrapper. Returns 1 if phar was found and proxied, 0 if phar is
 * not registered (honest no-op). Call once at first RINIT, after phar has registered. */
int howdah_install_phar_hook(howdah_sink_decide_t cb) {
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
