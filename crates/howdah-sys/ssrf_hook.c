/* Layer 3 SSRF egress hooks (productized from the SSRF spike; see the Layer-3
 * design §5.3). A function-table handler swap (same mechanism as sink_hook.c)
 * over the outbound-URL functions:
 *
 *   URL sinks (a scheme is REQUIRED): file_get_contents, fopen, get_headers
 *   socket openers (bare host[:port] ok): fsockopen, pfsockopen,
 *                                          stream_socket_client
 *   curl: curl_exec, with a per-request handle->URL map maintained by hooks on
 *         curl_init / curl_setopt / curl_setopt_array / curl_copy_handle /
 *         curl_reset / curl_close.
 *
 * Per call (two-phase; NO URL parsing lives in C):
 *   1. armed(ctx) == 0            -> chain (SSRF off: the zero-overhead path)
 *   2. howdah_ssrf_prepare(...)   -> Rust parses the target; 0 = not a network
 *                                    target (local path, unix://, ...) -> chain
 *   3. resolve host (getaddrinfo, once per distinct host per request, cached)
 *      into 17-byte records [family 4|6][16 addr bytes]; failure => 0 records
 *      (Rust still classifies a literal host, otherwise fails open)
 *   4. decide(...) == BLOCK       -> RETVAL_FALSE, do not call the original
 *
 * getaddrinfo also resolves decimal/octal/hex IP spellings, so C never decodes
 * them. Honest limits (documented, not hidden): the lookup has no timeout; PHP/
 * libcurl re-resolve at connect (DNS rebinding / TOCTOU); redirects are not
 * followed here; curl_multi_*, CURLOPT_RESOLVE/CONNECT_TO and non-string
 * CURLOPT_URL are unguarded; a curl handle with no known URL is unguarded; a
 * blocked curl_exec returns false with an empty curl_error().
 *
 * State (handle map, resolution cache) is bounded, in C statics, and cleared by
 * howdah_ssrf_request_reset() at RSHUTDOWN since FPM workers persist.
 * NTS only, like the rest of Howdah.
 */
#include "main/php.h"
#include "Zend/zend_API.h"

#include <string.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "howdah_sink.h"

/* Callbacks (see src/lib.rs). `ctx` is whatever howdah_ssrf_set_ctx supplied. */
typedef int (*howdah_ssrf_armed_t)(void *ctx);
typedef int (*howdah_ssrf_decide_t)(void *ctx, const char *scheme, size_t scheme_len,
                                    const char *host, size_t host_len, uint16_t port,
                                    const unsigned char *ips, size_t ips_count);

/* Provided by howdah-core (ffi.rs): the single source of truth for parsing. */
extern int howdah_ssrf_prepare(const unsigned char *input, size_t input_len,
                               int scheme_required, unsigned char *out_host,
                               size_t out_host_cap, size_t *out_host_len,
                               uint16_t *out_port);

/* Returns the action for an oversize (>cap) host: 0 allow / 1 log / 2 block. */
extern int howdah_sink_ssrf_oversize(void *ctx);

static howdah_ssrf_decide_t g_decide = NULL;
static howdah_ssrf_armed_t g_armed = NULL;
static void *g_ctx = NULL;

typedef void (*howdah_zif)(INTERNAL_FUNCTION_PARAMETERS);

/* ARG(n, var): the n-th call argument (dereferenced), or NULL if absent. */
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

/* ---- per-request resolution cache -------------------------------------- */
#define HOWDAH_HOST_MAX   256
#define HOWDAH_MAX_IPS    32
#define HOWDAH_REC        17
#define HOWDAH_CACHE_SLOTS 64

typedef struct {
    int used;
    size_t host_len;
    char host[HOWDAH_HOST_MAX];
    size_t count; /* 0 = lookup failed (also cached: never retry a slow failure) */
    unsigned char recs[HOWDAH_MAX_IPS * HOWDAH_REC];
} howdah_cache_ent;
static howdah_cache_ent g_cache[HOWDAH_CACHE_SLOTS];

static howdah_cache_ent *cache_find(const char *host, size_t len) {
    int i;
    for (i = 0; i < HOWDAH_CACHE_SLOTS; i++) {
        if (g_cache[i].used && g_cache[i].host_len == len
            && memcmp(g_cache[i].host, host, len) == 0)
            return &g_cache[i];
    }
    return NULL;
}

/* Resolve `host` (NUL-terminated, length hlen) into recs; returns the count
 * (0 on failure). */
static size_t resolve_host(const char *host, size_t hlen, unsigned char *recs) {
    struct addrinfo hints, *res = NULL, *a;
    size_t n = 0;
    if (memchr(host, '\0', hlen)) return 0; /* embedded NUL: do not truncate-resolve */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || !res) return 0;
    for (a = res; a && n < HOWDAH_MAX_IPS; a = a->ai_next) {
        unsigned char *r = recs + n * HOWDAH_REC;
        if (a->ai_family == AF_INET && a->ai_addr) {
            memset(r, 0, HOWDAH_REC);
            r[0] = 4;
            memcpy(r + 1, &((struct sockaddr_in *)a->ai_addr)->sin_addr, 4);
            n++;
        } else if (a->ai_family == AF_INET6 && a->ai_addr) {
            memset(r, 0, HOWDAH_REC);
            r[0] = 6;
            memcpy(r + 1, &((struct sockaddr_in6 *)a->ai_addr)->sin6_addr, 16);
            n++;
        }
    }
    freeaddrinfo(res);
    return n;
}

/* ---- core per-call check ------------------------------------------------ */
/* Returns 1 iff the call must be blocked. */
static int ssrf_should_block(const char *arg, size_t arglen, int scheme_required) {
    unsigned char hostbuf[HOWDAH_HOST_MAX + 1];
    unsigned char local[HOWDAH_MAX_IPS * HOWDAH_REC];
    const unsigned char *ips = NULL;
    size_t hlen = 0, count = 0, i;
    int prep;
    uint16_t port = 0;
    const char *scheme = "";
    size_t scheme_len = 0;
    howdah_cache_ent *ce;

    if (!g_decide || !g_armed) return 0;
    if (!g_armed(g_ctx)) return 0; /* SSRF off: zero overhead */
    prep = howdah_ssrf_prepare((const unsigned char *)arg, arglen, scheme_required,
                               hostbuf, HOWDAH_HOST_MAX, &hlen, &port);
    if (prep == 0) return 0; /* not a network target */
    /* Oversize host (could hide a zero-padded numeric IP): Rust decides. */
    if (prep == 2) return howdah_sink_ssrf_oversize(g_ctx) == HOWDAH_ACTION_BLOCK;
    if (hlen > HOWDAH_HOST_MAX) return 0;
    hostbuf[hlen] = '\0';

    /* Cosmetic scheme for the log: the short alnum run before "://". */
    for (i = 0; i < arglen && i < 16; i++) {
        unsigned char c = (unsigned char)arg[i];
        if (c == ':') {
            if (i > 0 && i + 2 < arglen && arg[i + 1] == '/' && arg[i + 2] == '/') {
                scheme = arg;
                scheme_len = i;
            }
            break;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
              || c == '+' || c == '-' || c == '.'))
            break;
    }

    ce = cache_find((const char *)hostbuf, hlen);
    if (ce) {
        ips = ce->recs;
        count = ce->count;
    } else {
        count = resolve_host((const char *)hostbuf, hlen, local);
        ips = local;
        for (i = 0; i < HOWDAH_CACHE_SLOTS; i++) {
            if (!g_cache[i].used) {
                g_cache[i].used = 1;
                g_cache[i].host_len = hlen;
                memcpy(g_cache[i].host, hostbuf, hlen);
                g_cache[i].count = count;
                memcpy(g_cache[i].recs, local, count * HOWDAH_REC);
                break;
            }
        }
        /* cache full: just don't cache (bounded, drop on overflow) */
    }

    return g_decide(g_ctx, scheme, scheme_len, (const char *)hostbuf, hlen, port,
                    count ? ips : NULL, count) == HOWDAH_ACTION_BLOCK;
}

/* ---- URL-first-arg sinks ------------------------------------------------- */
#define HOWDAH_DEFINE_URL_SINK(cname, scheme_required)                         \
    static howdah_zif howdah_orig_##cname = NULL;                              \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {            \
        zval *a;                                                               \
        HOWDAH_ARG(1, a);                                                      \
        if (HOWDAH_IS_STR(a)                                                   \
            && ssrf_should_block(Z_STRVAL_P(a), Z_STRLEN_P(a), (scheme_required))) { \
            RETVAL_FALSE;                                                      \
            return; /* neutralize: do not call the original */                 \
        }                                                                      \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                 \
    }

HOWDAH_DEFINE_URL_SINK(file_get_contents, 1)
HOWDAH_DEFINE_URL_SINK(fopen, 1)
HOWDAH_DEFINE_URL_SINK(get_headers, 1)
HOWDAH_DEFINE_URL_SINK(fsockopen, 0)
HOWDAH_DEFINE_URL_SINK(pfsockopen, 0)
HOWDAH_DEFINE_URL_SINK(stream_socket_client, 0)

/* ---- curl handle -> URL map ---------------------------------------------- */
#define HOWDAH_CURLOPT_URL 10002
#define HOWDAH_MAP_SLOTS 256
#define HOWDAH_URL_MAX 8192

static struct { long key; char *url; size_t len; } g_map[HOWDAH_MAP_SLOTS];

/* Handle key: resource id (PHP 5/7) / object handle (PHP 8). */
static int handle_key(zval *z, long *key) {
    if (!z) return 0;
#if PHP_VERSION_ID >= 80000
    if (Z_TYPE_P(z) == IS_OBJECT) { *key = (long)Z_OBJ_HANDLE_P(z); return 1; }
#elif PHP_VERSION_ID >= 70000
    if (Z_TYPE_P(z) == IS_RESOURCE) { *key = (long)Z_RES_HANDLE_P(z); return 1; }
#else
    if (Z_TYPE_P(z) == IS_RESOURCE) { *key = (long)Z_RESVAL_P(z); return 1; }
#endif
    return 0;
}

static void map_del(long key) {
    int i;
    for (i = 0; i < HOWDAH_MAP_SLOTS; i++) {
        if (g_map[i].url && g_map[i].key == key) {
            free(g_map[i].url);
            g_map[i].url = NULL;
            g_map[i].len = 0;
        }
    }
}

/* Set/replace the URL for `key`. Over-long URLs are not stored (entry cleared);
 * a full table drops the new entry. */
static void map_set(long key, const char *u, size_t len) {
    int i, free_i = -1;
    char *copy;
    map_del(key); /* clear first: an OOM or overflow must not leave a stale URL */
    if (len > HOWDAH_URL_MAX) return;
    copy = (char *)malloc(len + 1);
    if (!copy) return;
    memcpy(copy, u, len);
    copy[len] = '\0';
    for (i = 0; i < HOWDAH_MAP_SLOTS; i++) {
        if (g_map[i].url && g_map[i].key == key) {
            free(g_map[i].url);
            g_map[i].url = copy;
            g_map[i].len = len;
            return;
        }
        if (!g_map[i].url && free_i < 0) free_i = i;
    }
    if (free_i < 0) { free(copy); return; }
    g_map[free_i].key = key;
    g_map[free_i].url = copy;
    g_map[free_i].len = len;
}

static int map_get(long key, const char **u, size_t *len) {
    int i;
    for (i = 0; i < HOWDAH_MAP_SLOTS; i++) {
        if (g_map[i].url && g_map[i].key == key) {
            *u = g_map[i].url;
            *len = g_map[i].len;
            return 1;
        }
    }
    return 0;
}

static howdah_zif howdah_orig_curl_init = NULL, howdah_orig_curl_setopt = NULL,
                  howdah_orig_curl_setopt_array = NULL, howdah_orig_curl_copy_handle = NULL,
                  howdah_orig_curl_reset = NULL, howdah_orig_curl_close = NULL,
                  howdah_orig_curl_exec = NULL;

static void howdah_hook_curl_init(INTERNAL_FUNCTION_PARAMETERS) {
    zval *a;
    long k;
    HOWDAH_ARG(1, a);
    howdah_orig_curl_init(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (handle_key(return_value, &k)) {
        map_del(k); /* ids/handles are reused: never inherit a stale URL */
        if (HOWDAH_IS_STR(a)) map_set(k, Z_STRVAL_P(a), Z_STRLEN_P(a));
    }
}

static void howdah_hook_curl_setopt(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h, *o, *v;
    long k;
    HOWDAH_ARG(1, h);
    HOWDAH_ARG(2, o);
    HOWDAH_ARG(3, v);
    if (handle_key(h, &k) && o && Z_TYPE_P(o) == IS_LONG
        && Z_LVAL_P(o) == HOWDAH_CURLOPT_URL) {
        if (HOWDAH_IS_STR(v)) map_set(k, Z_STRVAL_P(v), Z_STRLEN_P(v));
        else map_del(k); /* non-string URL: unknown target (unguarded) */
    }
    howdah_orig_curl_setopt(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static void howdah_hook_curl_setopt_array(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h, *arr;
    long k;
    HOWDAH_ARG(1, h);
    HOWDAH_ARG(2, arr);
    if (handle_key(h, &k) && arr && Z_TYPE_P(arr) == IS_ARRAY) {
#if PHP_VERSION_ID >= 70000
        zval *v = zend_hash_index_find(Z_ARRVAL_P(arr), HOWDAH_CURLOPT_URL);
        if (v) {
            ZVAL_DEREF(v);
            if (Z_TYPE_P(v) == IS_STRING) map_set(k, Z_STRVAL_P(v), Z_STRLEN_P(v));
            else map_del(k);
        }
#else
        zval **pv;
        if (zend_hash_index_find(Z_ARRVAL_P(arr), HOWDAH_CURLOPT_URL, (void **)&pv) == SUCCESS) {
            if (Z_TYPE_PP(pv) == IS_STRING) map_set(k, Z_STRVAL_PP(pv), Z_STRLEN_PP(pv));
            else map_del(k);
        }
#endif
    }
    howdah_orig_curl_setopt_array(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static void howdah_hook_curl_copy_handle(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h;
    long src, dst;
    const char *u = NULL;
    size_t ulen = 0;
    int have = 0;
    HOWDAH_ARG(1, h);
    if (handle_key(h, &src)) have = map_get(src, &u, &ulen);
    howdah_orig_curl_copy_handle(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (handle_key(return_value, &dst)) {
        /* `u` points into the map; map_set copies before map_del could free it,
         * but a same-key reuse is impossible (src is still live). */
        map_del(dst);
        if (have) map_set(dst, u, ulen);
    }
}

static void howdah_hook_curl_reset(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h;
    long k;
    HOWDAH_ARG(1, h);
    if (handle_key(h, &k)) map_del(k);
    howdah_orig_curl_reset(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static void howdah_hook_curl_close(INTERNAL_FUNCTION_PARAMETERS) {
#if PHP_VERSION_ID < 80000
    zval *h;
    long k;
    HOWDAH_ARG(1, h);
    if (handle_key(h, &k)) map_del(k);
#endif
    /* PHP 8.0+: curl_close is a no-op and the handle stays usable, so keep the
     * entry (curl_init clears a reused handle key). */
    howdah_orig_curl_close(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static void howdah_hook_curl_exec(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h;
    long k;
    const char *u;
    size_t ulen;
    HOWDAH_ARG(1, h);
    /* No URL known for the handle: chain unguarded (documented gap). */
    if (handle_key(h, &k) && map_get(k, &u, &ulen)
        && ssrf_should_block(u, ulen, 0)) {
        RETVAL_FALSE;
        return;
    }
    howdah_orig_curl_exec(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ---- install / lifecycle ------------------------------------------------- */
#if PHP_VERSION_ID >= 70000
#define HOWDAH_SSRF_SWAP(cname, phpname)                                       \
    do {                                                                       \
        zend_function *_f = (zend_function *)zend_hash_str_find_ptr(           \
            CG(function_table), (phpname), sizeof(phpname) - 1);               \
        if (_f && _f->type == ZEND_INTERNAL_FUNCTION) {                        \
            howdah_orig_##cname = _f->internal_function.handler;               \
            _f->internal_function.handler = howdah_hook_##cname;               \
        }                                                                      \
    } while (0)
#else
#define HOWDAH_SSRF_SWAP(cname, phpname)                                       \
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

/* Install all SSRF hooks. Call once at MINIT, after the builtin modules (incl.
 * curl, when loaded) have registered their functions. Functions that are absent
 * (e.g. no curl extension) are simply skipped. */
void howdah_install_ssrf_hooks(howdah_ssrf_decide_t decide, howdah_ssrf_armed_t armed) {
    g_decide = decide;
    g_armed = armed;
    HOWDAH_SSRF_SWAP(file_get_contents, "file_get_contents");
    HOWDAH_SSRF_SWAP(fopen, "fopen");
    HOWDAH_SSRF_SWAP(get_headers, "get_headers");
    HOWDAH_SSRF_SWAP(fsockopen, "fsockopen");
    HOWDAH_SSRF_SWAP(pfsockopen, "pfsockopen");
    HOWDAH_SSRF_SWAP(stream_socket_client, "stream_socket_client");
    HOWDAH_SSRF_SWAP(curl_init, "curl_init");
    HOWDAH_SSRF_SWAP(curl_setopt, "curl_setopt");
    HOWDAH_SSRF_SWAP(curl_setopt_array, "curl_setopt_array");
    HOWDAH_SSRF_SWAP(curl_copy_handle, "curl_copy_handle");
    HOWDAH_SSRF_SWAP(curl_reset, "curl_reset");
    HOWDAH_SSRF_SWAP(curl_close, "curl_close");
    HOWDAH_SSRF_SWAP(curl_exec, "curl_exec");
}

/* Set the opaque ctx handed to the callbacks (the live per-request context). */
void howdah_ssrf_set_ctx(void *ctx) {
    g_ctx = ctx;
}

/* Clear all per-request state: the curl handle->URL map, the resolution cache
 * and the ctx. Call at RSHUTDOWN. */
void howdah_ssrf_request_reset(void) {
    int i;
    for (i = 0; i < HOWDAH_MAP_SLOTS; i++) {
        if (g_map[i].url) {
            free(g_map[i].url);
            g_map[i].url = NULL;
            g_map[i].len = 0;
        }
    }
    for (i = 0; i < HOWDAH_CACHE_SLOTS; i++) g_cache[i].used = 0;
    g_ctx = NULL;
}
