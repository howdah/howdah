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
 * T6 hardening, three independent opt-in knobs ([sinks.ssrf] rebind / scheme /
 * redirect, each off|detect|block; armed(ctx) returns a HOWDAH_SSRF_ARM_* mask):
 *
 *   scheme    Egress-scheme denial BEFORE any parsing/DNS. curl: only http(s)
 *             may leave (gopher/dict/file/ldap/tftp/... refused, and libcurl's
 *             ftp./dict./ldap.-prefix protocol guess). The stream URL sinks
 *             refuse the remote wrappers (ftp, ...). In `block` the curl handle
 *             also gets CURLOPT_PROTOCOLS=HTTP|HTTPS so libcurl itself refuses
 *             what a URL parser difference lets through, redirect hops included.
 *   rebind    Resolve-at-connect. We cannot see libcurl's connect() from PHP
 *             (no CURLOPT_OPENSOCKETFUNCTION/PREREQFUNCTION without the CURL*
 *             handle, which is a private php_curl field), so curl is done with
 *             what PHP exposes: in `block`, the validated IPv4 set is pinned
 *             with CURLOPT_RESOLVE (PHP 5.5+, libcurl 7.21.3+) so libcurl
 *             connects to exactly what was checked; after the transfer
 *             CURLINFO_PRIMARY_IP (the address actually connected, last hop) is
 *             judged again and the response is discarded if it is internal
 *             (this is the only guard on PHP 5.4, which has no CURLOPT_RESOLVE).
 *             Sockets (fsockopen/pfsockopen/stream_socket_client) and fopen(url)
 *             judge the connected PEER address of the returned stream, which is
 *             authoritative regardless of how the name was resolved.
 *   redirect  A curl 3xx to an internal target is not followed. A registered
 *             internal function (howdah_curl_header_guard, registered at MINIT
 *             when this or `scheme` is armed) is installed as the
 *             handle's CURLOPT_HEADERFUNCTION when CURLOPT_FOLLOWLOCATION is on
 *             and the script set no header callback of its own; it sees the
 *             Location header before libcurl follows it and aborts the transfer
 *             (a wrong return length -> CURLE_WRITE_ERROR) if the target is
 *             internal or its scheme is not http(s).
 *
 * getaddrinfo also resolves decimal/octal/hex IP spellings, so C never decodes
 * them. Honest limits (documented, not hidden): the lookup has no timeout; the
 * range check still resolves once here and PHP/libcurl resolve again unless the
 * pin applies (file_get_contents/get_headers have no peer to verify, and curl
 * redirect hops cannot be pinned: the final hop is verified after the fact);
 * stream-wrapper redirects are not re-checked; curl_multi_*, CURLOPT_CONNECT_TO
 * and non-string CURLOPT_URL are unguarded; a curl handle with no known URL is
 * unguarded; a script-set CURLOPT_HEADERFUNCTION means redirect hops are only
 * verified after the fact; a proxy (CURLOPT_PROXY or *_proxy in the
 * environment) disables the pin and the connect-time check (the connection goes
 * to the proxy); a blocked curl_exec returns false with an empty curl_error().
 *
 * State (handle map, resolution cache) is bounded, in C statics, and cleared by
 * howdah_ssrf_request_reset() at request teardown (RSHUTDOWN, and the bailout
 * path via clear_request_state) since FPM workers persist.
 * NTS only, like the rest of Howdah.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* RTLD_DEFAULT */
#endif
#include "main/php.h"
#include "main/php_network.h"
#include "main/php_streams.h"
#include "ext/standard/file.h"
#include "Zend/zend_API.h"
#include "Zend/zend_execute.h"
#include "Zend/zend_exceptions.h"

#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

#include "howdah_sink.h"

/* SSRF event kinds / armed-mask bits / scheme contexts. MUST mirror
 * HOWDAH_SSRF_* in howdah-core/src/ffi.rs. */
#define HOWDAH_SSRF_KIND_RANGE    0
#define HOWDAH_SSRF_KIND_REBIND   1
#define HOWDAH_SSRF_KIND_REDIRECT 2
#define HOWDAH_SSRF_ARM_RANGE     1
#define HOWDAH_SSRF_ARM_REBIND    2
#define HOWDAH_SSRF_ARM_SCHEME    4
#define HOWDAH_SSRF_ARM_REDIRECT  8
#define HOWDAH_SSRF_ARM_PIN       16 /* rebind=block: may set CURLOPT_RESOLVE */
#define HOWDAH_SSRF_ARM_PROTOCOLS 32 /* scheme=block: may set CURLOPT_PROTOCOLS */
#define HOWDAH_SSRF_VIA_STREAM    0
#define HOWDAH_SSRF_VIA_CURL      1

/* Callbacks (see src/lib.rs). `ctx` is always NULL (the ext uses module::CTX).
 * armed() returns a HOWDAH_SSRF_ARM_* mask (0 = nothing armed). */
typedef int (*howdah_ssrf_armed_t)(void *ctx);
typedef int (*howdah_ssrf_decide_t)(void *ctx, int kind, const char *scheme, size_t scheme_len,
                                    const char *host, size_t host_len, uint16_t port,
                                    const unsigned char *ips, size_t ips_count);

/* Provided by howdah-core (ffi.rs): the single source of truth for parsing.
 * scheme_required: 0 bare host ok (fsockopen, curl), 1 a scheme is required
 * (URL sinks), 2 a redirect Location value (absolute or scheme-relative `//`;
 * a plain relative reference is a skip). */
extern int howdah_ssrf_prepare(const unsigned char *input, size_t input_len,
                               int scheme_required, unsigned char *out_host,
                               size_t out_host_cap, size_t *out_host_len,
                               uint16_t *out_port);

/* Provided by howdah-core: build the CURLOPT_RESOLVE entry `host:port:ip[,ip]`
 * that pins the URL's hostname to the validated IPv4 records. 0 = nothing safe
 * to pin (literal-IP host, non-HTTP(S), IPv6-only, ...). */
extern size_t howdah_ssrf_pin_entry(const unsigned char *input, size_t input_len,
                                    const unsigned char *recs, size_t recs_count,
                                    int multi, unsigned char *out, size_t out_cap);

/* Returns the action for an oversize (>cap) host: 0 allow / 1 log / 2 block.
 * Provided by the ext glue (ssrf_filter.rs): it calls the core verdict for the
 * event `kind` (range mode, or a redirect hop's own mode) AND writes the
 * stashed log line. */
extern int howdah_ssrf_oversize_glue(void *ctx, int kind);

/* Egress-scheme verdict (0 allow / 1 log / 2 block) for `url`; `via` is
 * HOWDAH_SSRF_VIA_*. Provided by the ext glue; writes the stashed log line. */
extern int howdah_ssrf_scheme_glue(void *ctx, int via, const char *url, size_t url_len);

static howdah_ssrf_decide_t g_decide = NULL;
static howdah_ssrf_armed_t g_armed = NULL;
static void *g_ctx = NULL;

/* The armed mask, or 0 when the hooks were installed without a callback. */
static int ssrf_mask(void) { return g_armed ? g_armed(g_ctx) : 0; }

typedef void (*howdah_zif)(INTERNAL_FUNCTION_PARAMETERS);

/* The currently-executing PHP script path, for the Layer-4 origin. 5.x threads
 * TSRMLS and returns `char *`; 7/8 take no args and return `const char *`. A
 * local duplicate of sink_hook.c's helper so the egress / php-write paths here
 * need no cross-TU call. Spike-proven on 5.4/5.6/7.4/8.1/8.4. */
static const char *howdah_current_script(void) {
#if PHP_VERSION_ID >= 70000
    return zend_get_executed_filename();
#else
    TSRMLS_FETCH();
    return zend_get_executed_filename(TSRMLS_C);
#endif
}

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
    int truncated; /* getaddrinfo returned more than HOWDAH_MAX_IPS records */
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
 * (0 on failure). Sets `*truncated` when getaddrinfo returned MORE than
 * HOWDAH_MAX_IPS records, so the caller can treat the set as unverifiable: an
 * attacker DNS answer of 32 public addresses followed by an internal one would
 * otherwise classify clean while PHP's connect loop reaches the internal
 * address we never stored. */
static size_t resolve_host(const char *host, size_t hlen, unsigned char *recs, int *truncated) {
    struct addrinfo hints, *res = NULL, *a;
    size_t n = 0;
    *truncated = 0;
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
    if (a != NULL) *truncated = 1; /* stopped at the cap with records remaining */
    freeaddrinfo(res);
    return n;
}

/* ---- target parse + resolve --------------------------------------------- */
/* One outbound call's parsed (and optionally resolved) target. */
typedef struct {
    unsigned char host[HOWDAH_HOST_MAX + 1];
    size_t hlen;
    uint16_t port;
    size_t count; /* resolved records in `recs` (0: lookup failed, or not asked) */
    int truncated; /* resolution hit the cap with more records remaining */
    unsigned char recs[HOWDAH_MAX_IPS * HOWDAH_REC];
} howdah_target;

/* Parse `arg` with Rust (NO URL parsing in C) and, when `resolve`, resolve the
 * host through the per-request cache. Returns 0 (not a network target), 1
 * (host/port, and recs when resolved, are filled) or 2 (oversize host: could
 * hide a zero-padded numeric IP, so it is a verdict for the caller). */
static int ssrf_target(const char *arg, size_t arglen, int scheme_required, int resolve,
                       howdah_target *t) {
    howdah_cache_ent *ce;
    size_t hlen = 0, i;
    uint16_t port = 0;
    int prep;
    t->hlen = 0;
    t->port = 0;
    t->count = 0;
    t->truncated = 0;
    prep = howdah_ssrf_prepare((const unsigned char *)arg, arglen, scheme_required,
                               t->host, HOWDAH_HOST_MAX, &hlen, &port);
    if (prep != 1) return prep == 2 ? 2 : 0;
    if (hlen > HOWDAH_HOST_MAX) return 0;
    t->host[hlen] = '\0';
    t->hlen = hlen;
    t->port = port;
    if (!resolve) return 1;
    ce = cache_find((const char *)t->host, hlen);
    if (ce) {
        t->count = ce->count;
        t->truncated = ce->truncated;
        memcpy(t->recs, ce->recs, ce->count * HOWDAH_REC);
    } else {
        t->count = resolve_host((const char *)t->host, hlen, t->recs, &t->truncated);
        for (i = 0; i < HOWDAH_CACHE_SLOTS; i++) {
            if (!g_cache[i].used) {
                g_cache[i].used = 1;
                g_cache[i].host_len = hlen;
                memcpy(g_cache[i].host, t->host, hlen);
                g_cache[i].count = t->count;
                g_cache[i].truncated = t->truncated;
                memcpy(g_cache[i].recs, t->recs, t->count * HOWDAH_REC);
                break;
            }
        }
        /* cache full: just don't cache (bounded, drop on overflow) */
    }
    /* A truncated resolution is unverifiable: report it as the oversize/
     * suspicious verdict (2) so the range and redirect guards block it when
     * armed, rather than classifying only the first HOWDAH_MAX_IPS records. */
    if (t->truncated) return 2;
    return 1;
}

/* Cosmetic scheme for the log: the short alnum run before "://". */
static void ssrf_cosmetic_scheme(const char *arg, size_t arglen, const char **scheme,
                                 size_t *scheme_len) {
    size_t i;
    *scheme = "";
    *scheme_len = 0;
    for (i = 0; i < arglen && i < 16; i++) {
        unsigned char c = (unsigned char)arg[i];
        if (c == ':') {
            if (i > 0 && i + 2 < arglen && arg[i + 1] == '/' && arg[i + 2] == '/') {
                *scheme = arg;
                *scheme_len = i;
            }
            break;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
              || c == '+' || c == '-' || c == '.'))
            break;
    }
}

/* ---- core per-call check ------------------------------------------------ */
/* Returns 1 iff the call must be blocked. `origin`/`origin_len` are the calling
 * script path (Layer-4 egress "caller"); may be NULL/0 (the behavior glue then
 * sees an empty caller). */
static int ssrf_should_block(const char *arg, size_t arglen, int scheme_required,
                             const char *origin, size_t origin_len) {
    howdah_target t;
    const char *scheme = "";
    size_t scheme_len = 0;
    int prep, ssrf_on, egress_on;
    int ssrf_block = 0, beh_block = 0;

    /* Two independent gates. `ssrf_on` is the L3 reserved-range signal (the RANGE
     * bit of the armed mask; the other bits are the hardening knobs, which have
     * their own entry points): ONLY it may trigger the no-timeout resolve_host +
     * g_decide path. `egress_on` is the L4 behavior-egress facet, gated by its
     * own callback; it matches the host STRING and needs no resolution. */
    ssrf_on = (g_decide && (ssrf_mask() & HOWDAH_SSRF_ARM_RANGE));
    egress_on = (howdah_g_behavior_egress && howdah_g_behavior_armed
                 && howdah_g_behavior_armed(g_ctx, HOWDAH_BEHAVIOR_EGRESS));
    if (!ssrf_on && !egress_on) return 0; /* both facets off: zero overhead */

    prep = ssrf_target(arg, arglen, scheme_required, ssrf_on, &t);
    if (prep == 0) return 0; /* not a network target */
    /* Oversize host (could hide a zero-padded numeric IP): an SSRF-specific
     * decision. With no usable host string, the egress string match cannot run,
     * so this path is SSRF-only (fail-open for egress-only mode). */
    if (prep == 2) {
        /* Suspicious: an over-256 host (no usable string, t.hlen == 0) or a
         * truncated >32-record resolution (a usable host, t.hlen > 0, so the
         * Layer-4 egress string match can still run on it — F8 re-review). */
        int ov = ssrf_on && howdah_ssrf_oversize_glue(g_ctx, HOWDAH_SSRF_KIND_RANGE) == HOWDAH_ACTION_BLOCK;
        int eg = egress_on && t.hlen > 0
                 && howdah_g_behavior_egress(g_ctx, origin, origin_len,
                        (const char *)t.host, t.hlen) == HOWDAH_ACTION_BLOCK;
        return ov || eg;
    }

    if (ssrf_on) {
        ssrf_cosmetic_scheme(arg, arglen, &scheme, &scheme_len);
        /* SSRF verdict: no origin threaded into it (Ruling 4). */
        ssrf_block = g_decide(g_ctx, HOWDAH_SSRF_KIND_RANGE, scheme, scheme_len,
                              (const char *)t.host, t.hlen, t.port,
                              t.count ? t.recs : NULL, t.count)
                     == HOWDAH_ACTION_BLOCK;
    }

    if (egress_on) {
        /* Layer-4 egress (Ruling 4): a parallel behavior check on the same host
         * STRING, carrying the calling-script origin. No resolve_host needed; the
         * callback is caller-scoped (non-upload callers get None). */
        beh_block = howdah_g_behavior_egress(g_ctx, origin, origin_len,
                        (const char *)t.host, t.hlen) == HOWDAH_ACTION_BLOCK;
    }

    return ssrf_block || beh_block; /* block iff EITHER facet blocks */
}

/* ---- T6: scheme denial --------------------------------------------------- */
/* 1 iff the egress-scheme policy refuses `arg` (mode block). The core logs the
 * scheme CATEGORY only; in detect it logs and this returns 0. */
static int ssrf_scheme_blocked(const char *arg, size_t arglen, int via) {
    if (!(ssrf_mask() & HOWDAH_SSRF_ARM_SCHEME)) return 0;
    return howdah_ssrf_scheme_glue(g_ctx, via, arg, arglen) == HOWDAH_ACTION_BLOCK;
}

/* ---- T6: connect-time verification of a returned stream ------------------ */
/* Decode a sockaddr into a 17-byte record + host-order port. 0 = not IP. */
static int sockaddr_rec(const struct sockaddr *sa, socklen_t len, unsigned char *rec,
                        uint16_t *port) {
    memset(rec, 0, HOWDAH_REC);
    if (sa->sa_family == AF_INET && len >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        rec[0] = 4;
        memcpy(rec + 1, &s4->sin_addr, 4);
        *port = ntohs(s4->sin_port);
        return 1;
    }
    if (sa->sa_family == AF_INET6 && len >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        rec[0] = 6;
        memcpy(rec + 1, &s6->sin6_addr, 16);
        *port = ntohs(s6->sin6_port);
        return 1;
    }
    return 0;
}

/* fclose() through the function table (errors silenced, exception
 * cleared). */
static void howdah_php_fclose(zval *stream) {
    int saved;
#if PHP_VERSION_ID >= 70000
    zval fn, ret, params[1];
    ZVAL_STRING(&fn, "fclose");
    ZVAL_COPY_VALUE(&params[0], stream); /* shallow: the callee takes its own reference */
    ZVAL_UNDEF(&ret);
    saved = EG(error_reporting);
    EG(error_reporting) = 0;
    call_user_function(CG(function_table), NULL, &fn, &ret, 1, params);
    EG(error_reporting) = saved;
    if (EG(exception)) zend_clear_exception();
    zval_ptr_dtor(&ret);
    zval_ptr_dtor(&fn);
#else
    zval *fn, *params[1], ret;
    TSRMLS_FETCH();
    MAKE_STD_ZVAL(fn);
    ZVAL_STRING(fn, "fclose", 1);
    params[0] = stream;
    INIT_ZVAL(ret);
    saved = EG(error_reporting);
    EG(error_reporting) = 0;
    call_user_function(CG(function_table), NULL, fn, &ret, 1, params TSRMLS_CC);
    EG(error_reporting) = saved;
    zval_dtor(&ret);
    zval_ptr_dtor(&fn);
#endif
}

/* The function returned a stream in `rv` (= return_value) for the URL/host in
 * `arg`. Ask the stream for its connected PEER address (the one the kernel
 * actually used: authoritative however the name was resolved, so DNS rebinding
 * between our check and PHP's own lookup cannot hide) and judge it. If it must
 * be refused, close the stream the way fclose() does and make the call return
 * false. Fail-open: a non-socket stream, an unconnected (async) socket or any
 * lookup failure leaves the stream alone. For fsockopen/pfsockopen/
 * stream_socket_client nothing has been sent yet (the script has not had the
 * stream); for fopen(url) the http request has already gone out, so this stops
 * the script reading the response. */
static void ssrf_peer_guard(zval *rv, const char *arg, size_t arglen, int scheme_required,
                            const char *via) {
    php_stream *stream = NULL;
    void *addr = NULL;
    socklen_t addrlen = 0;
    howdah_target t;
    unsigned char rec[HOWDAH_REC];
    uint16_t pport = 0;
    int block = 0;
#if PHP_VERSION_ID < 70000
    zval *zv = rv;
    TSRMLS_FETCH();
#endif

    if (!g_decide || Z_TYPE_P(rv) != IS_RESOURCE) return;
    if (!(ssrf_mask() & HOWDAH_SSRF_ARM_REBIND)) return;
    if (ssrf_target(arg, arglen, scheme_required, 0, &t) != 1) return; /* unix://, local path */
#if PHP_VERSION_ID >= 70000
    php_stream_from_zval_no_verify(stream, rv);
#else
    php_stream_from_zval_no_verify(stream, &zv);
#endif
    if (!stream) return;
#if PHP_VERSION_ID >= 70000
    if (php_stream_xport_get_name(stream, 1, NULL, &addr, &addrlen) != 0 || !addr) return;
#else
    if (php_stream_xport_get_name(stream, 1, NULL, NULL, &addr, &addrlen TSRMLS_CC) != 0 || !addr)
        return;
#endif
    if (sockaddr_rec((const struct sockaddr *)addr, addrlen, rec, &pport)) {
        block = g_decide(g_ctx, HOWDAH_SSRF_KIND_REBIND, via, strlen(via),
                         (const char *)t.host, t.hlen, pport, rec, 1)
                == HOWDAH_ACTION_BLOCK;
    }
    efree(addr);
    if (block) {
        /* Close it exactly as the script's own fclose() would (the one close
         * path identical on 5.4-8.5, persistent streams included), then drop
         * our reference to the now-closed resource. */
        howdah_php_fclose(rv);
#if PHP_VERSION_ID >= 70000
        zval_ptr_dtor(rv);
#else
        zval_dtor(rv);
#endif
        ZVAL_BOOL(rv, 0);
    }
}

/* ---- URL-first-arg sinks ------------------------------------------------- */
/* URL sinks (a scheme is required): the stream egress-scheme policy first, then
 * the range check. */
#define HOWDAH_DEFINE_URL_SINK(cname, scheme_required)                         \
    static howdah_zif howdah_orig_##cname = NULL;                              \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {            \
        zval *a;                                                               \
        HOWDAH_ARG(1, a);                                                      \
        if (HOWDAH_IS_STR(a)) {                                                \
            const char *_org = howdah_current_script();                        \
            if (((scheme_required)                                             \
                 && ssrf_scheme_blocked(Z_STRVAL_P(a), Z_STRLEN_P(a),          \
                                        HOWDAH_SSRF_VIA_STREAM))               \
                || ssrf_should_block(Z_STRVAL_P(a), Z_STRLEN_P(a), (scheme_required), \
                                     _org, _org ? strlen(_org) : 0)) {         \
                RETVAL_FALSE;                                                  \
                return; /* neutralize: do not call the original */             \
            }                                                                  \
        }                                                                      \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                 \
    }

/* Socket openers (bare host[:port] ok): the range check before the connect, then
 * the connected-peer check on the returned stream (resolve-at-connect). */
#define HOWDAH_DEFINE_SOCK_SINK(cname)                                         \
    static howdah_zif howdah_orig_##cname = NULL;                              \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {            \
        zval *a;                                                               \
        HOWDAH_ARG(1, a);                                                      \
        if (HOWDAH_IS_STR(a)) {                                                \
            const char *_org = howdah_current_script();                        \
            if (ssrf_should_block(Z_STRVAL_P(a), Z_STRLEN_P(a), 0,             \
                                  _org, _org ? strlen(_org) : 0)) {            \
                RETVAL_FALSE;                                                  \
                return; /* neutralize: do not call the original */             \
            }                                                                  \
        }                                                                      \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                 \
        if (HOWDAH_IS_STR(a))                                                  \
            ssrf_peer_guard(return_value, Z_STRVAL_P(a), Z_STRLEN_P(a), 0,     \
                            "tcp-connect");                                    \
    }

HOWDAH_DEFINE_URL_SINK(get_headers, 1)
HOWDAH_DEFINE_SOCK_SINK(fsockopen)
HOWDAH_DEFINE_SOCK_SINK(pfsockopen)
HOWDAH_DEFINE_SOCK_SINK(stream_socket_client)

/* file_get_contents (T4): a URL sink for SSRF (scheme required) AND a file-open
 * sink for the wrapper/poison firewall. Bespoke (not HOWDAH_DEFINE_URL_SINK) so
 * it runs the firewall check after the SSRF verdict. Final action = max(ssrf,
 * firewall); BLOCK neutralizes (RETVAL_FALSE). */
static howdah_zif howdah_orig_file_get_contents = NULL;
static void howdah_hook_file_get_contents(INTERNAL_FUNCTION_PARAMETERS) {
    zval *a;
    int block = 0;
    HOWDAH_ARG(1, a);
    if (HOWDAH_IS_STR(a)) {
        const char *org = howdah_current_script();
        if (ssrf_scheme_blocked(Z_STRVAL_P(a), Z_STRLEN_P(a), HOWDAH_SSRF_VIA_STREAM)
            || ssrf_should_block(Z_STRVAL_P(a), Z_STRLEN_P(a), 1, org, org ? strlen(org) : 0)) {
            block = 1;
        }
        if (!block
            && howdah_file_firewall_check("file_get_contents", sizeof("file_get_contents") - 1,
                                          Z_STRVAL_P(a), Z_STRLEN_P(a), HOWDAH_FILE_OP_READ)) {
            block = 1;
        }
    }
    if (block) {
        RETVAL_FALSE;
        return;
    }
    howdah_orig_file_get_contents(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Set by howdah_install_behavior_hooks from its `swap` mask: the scoped
 * deny_php_writes tier is armed (fopen's write branch, and the generic-write
 * sinks, consult the php-write callback), and the delete guard is armed (rename's
 * SOURCE goes to the file-op hub). Config is process-static, so this is a pure
 * perf gate: the Rust side re-checks the config on every call. */
static int howdah_g_bhv_generic = 0;
static int howdah_g_bhv_rename_src = 0;

/* 1 iff a fopen mode string selects a write (any of w/a/x/c/+). Read-only ("r"
 * / "rb") yields 0. Scanned, never logged. */
static int howdah_mode_is_write(const char *mode, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        char c = mode[i];
        if (c == 'w' || c == 'a' || c == 'x' || c == 'c' || c == '+') {
            return 1;
        }
    }
    return 0;
}

/* fopen (Ruling 5): fopen is ALREADY swapped by howdah_install_ssrf_hooks, so it
 * gets a bespoke trampoline (NOT a second swap) that runs the SSRF egress check
 * THEN, when the Layer-4 php-write facet is armed, a php-write check. arg1 =
 * path/URL (also the SSRF target), arg2 = mode string. Final action = max(ssrf,
 * php-write); BLOCK neutralizes (RETVAL_FALSE). */
static howdah_zif howdah_orig_fopen = NULL;
static void howdah_hook_fopen(INTERNAL_FUNCTION_PARAMETERS) {
    zval *a;
    int block = 0;
    HOWDAH_ARG(1, a);
    if (HOWDAH_IS_STR(a)) {
        const char *org = howdah_current_script();
        size_t orglen = org ? strlen(org) : 0;
        if (ssrf_scheme_blocked(Z_STRVAL_P(a), Z_STRLEN_P(a), HOWDAH_SSRF_VIA_STREAM)
            || ssrf_should_block(Z_STRVAL_P(a), Z_STRLEN_P(a), 1, org, orglen)) {
            block = 1;
        }
        if (!block && howdah_g_behavior_php_write && howdah_g_bhv_generic) {
            zval *m;
            int is_write = HOWDAH_WRITE_READ;
            HOWDAH_ARG(2, m);
            if (HOWDAH_IS_STR(m)
                && howdah_mode_is_write(Z_STRVAL_P(m), Z_STRLEN_P(m))) {
                is_write = HOWDAH_WRITE_PLAIN;
            }
            if (howdah_g_behavior_php_write(NULL, org, orglen, Z_STRVAL_P(a),
                    Z_STRLEN_P(a), is_write) == HOWDAH_ACTION_BLOCK) {
                block = 1;
            }
        }
        /* T4 file-open firewall: wrapper scheme + poisonable local target. The
         * op class is read vs write, read off the mode string (arg2). Self-gates
         * on the decide callback, so this is a no-op when the firewall is off. */
        if (!block) {
            zval *m2;
            int op = HOWDAH_FILE_OP_READ;
            HOWDAH_ARG(2, m2);
            if (HOWDAH_IS_STR(m2) && howdah_mode_is_write(Z_STRVAL_P(m2), Z_STRLEN_P(m2))) {
                op = HOWDAH_FILE_OP_WRITE;
            }
            if (howdah_file_firewall_check("fopen", sizeof("fopen") - 1,
                                           Z_STRVAL_P(a), Z_STRLEN_P(a), op)) {
                block = 1;
            }
        }
    }
    if (block) {
        RETVAL_FALSE;
        return;
    }
    howdah_orig_fopen(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    /* T6 resolve-at-connect: fopen(url) returned a stream; judge the address it
     * actually connected to (a no-op for local files: no scheme, no socket). */
    if (HOWDAH_IS_STR(a))
        ssrf_peer_guard(return_value, Z_STRVAL_P(a), Z_STRLEN_P(a), 1, "stream-connect");
}

/* ---- Layer-4 write sinks ------------------------------------------------- */
/* These are NOT SSRF sinks: each writes a file to disk, so Layer-4 swaps them
 * (via howdah_install_behavior_hooks) to check the written target. `argn` is the
 * 1-based target argument; `wmode` the HOWDAH_WRITE_* class the Rust php_write
 * callback tiers on (UPLOAD for move_uploaded_file: the always-on upload-write
 * guard; PLAIN for the rest: the scoped deny_php_writes tier). Fail-open on a
 * NULL callback / non-string target. */
static int howdah_write_blocked(zval *t, int wmode) {
    const char *org;
    if (!howdah_g_behavior_php_write || !HOWDAH_IS_STR(t)) return 0;
    org = howdah_current_script();
    return howdah_g_behavior_php_write(NULL, org, org ? strlen(org) : 0,
               Z_STRVAL_P(t), Z_STRLEN_P(t), wmode) == HOWDAH_ACTION_BLOCK;
}

#define HOWDAH_DEFINE_PHP_WRITE_SINK(cname, argn, wmode)                       \
    static howdah_zif howdah_orig_##cname = NULL;                              \
    static void howdah_hook_##cname(INTERNAL_FUNCTION_PARAMETERS) {            \
        zval *t;                                                               \
        HOWDAH_ARG((argn), t);                                                 \
        if (howdah_write_blocked(t, (wmode))) {                                \
            RETVAL_FALSE;                                                      \
            return; /* neutralize: do not call the original */                 \
        }                                                                      \
        howdah_orig_##cname(INTERNAL_FUNCTION_PARAM_PASSTHRU);                 \
    }

HOWDAH_DEFINE_PHP_WRITE_SINK(file_put_contents, 1, HOWDAH_WRITE_PLAIN)
HOWDAH_DEFINE_PHP_WRITE_SINK(copy, 2, HOWDAH_WRITE_PLAIN)
HOWDAH_DEFINE_PHP_WRITE_SINK(move_uploaded_file, 2, HOWDAH_WRITE_UPLOAD)

/* rename has two operands that matter. Its SOURCE (arg1) is a delete in effect
 * (moving wp-config.php away resets the app): it goes to the file-op hub as
 * HOWDAH_FILE_OP_MOVE_SRC when the delete guard is armed. Its TARGET (arg2) is a
 * write: the scoped deny_php_writes tier. Either neutralizes the call. */
static howdah_zif howdah_orig_rename = NULL;
static void howdah_hook_rename(INTERNAL_FUNCTION_PARAMETERS) {
    zval *a;
    if (howdah_g_bhv_rename_src) {
        HOWDAH_ARG(1, a);
        if (HOWDAH_IS_STR(a)
            && howdah_file_firewall_check("rename", sizeof("rename") - 1,
                                          Z_STRVAL_P(a), Z_STRLEN_P(a),
                                          HOWDAH_FILE_OP_MOVE_SRC)) {
            RETVAL_FALSE;
            return;
        }
    }
    if (howdah_g_bhv_generic) {
        HOWDAH_ARG(2, a);
        if (howdah_write_blocked(a, HOWDAH_WRITE_PLAIN)) {
            RETVAL_FALSE;
            return;
        }
    }
    howdah_orig_rename(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ---- curl handle -> URL/option map ---------------------------------------- */
/* libcurl option / info numbers (stable ABI; PHP's CURLOPT_* are the same ints).
 * Spelled out so this file needs no libcurl headers. */
#define HOWDAH_CURLOPT_URL            10002
#define HOWDAH_CURLOPT_PROXY          10004
#define HOWDAH_CURLOPT_FOLLOWLOCATION 52
#define HOWDAH_CURLOPT_HEADERFUNCTION 20079
#define HOWDAH_CURLOPT_PROTOCOLS      181
#define HOWDAH_CURLOPT_RESOLVE        10203
#define HOWDAH_CURLOPT_CONNECT_TO     10243
#define HOWDAH_CURLINFO_EFFECTIVE_URL 1048577
#define HOWDAH_CURLINFO_PRIMARY_IP    1048608
#define HOWDAH_CURLPROTO_HTTP_HTTPS   3
#define HOWDAH_HDR_FN                 "howdah_curl_header_guard"

#define HOWDAH_MAP_SLOTS 256
#define HOWDAH_URL_MAX 8192

/* Per-handle option flags the hardening needs (tracked only for the few
 * options below; everything else about a handle is none of our business). */
#define HCF_FOLLOW          1  /* CURLOPT_FOLLOWLOCATION on */
#define HCF_USER_HDR        2  /* the script set its own CURLOPT_HEADERFUNCTION */
#define HCF_USER_RESOLVE    4  /* the script set CURLOPT_RESOLVE */
#define HCF_USER_CONNECT_TO 8  /* the script set CURLOPT_CONNECT_TO */
#define HCF_PROXY           16 /* the script set a CURLOPT_PROXY */

typedef struct {
    int used;
    long key;
    char *url;
    size_t len;
    unsigned flags;
    int overlong; /* URL exceeded HOWDAH_URL_MAX: the stored copy is truncated, so
                   * its parse is untrusted — the guard treats it as suspicious */
} howdah_cent;
static howdah_cent g_map[HOWDAH_MAP_SLOTS];

/* >0 while WE call a curl_* PHP function (pin, PROTOCOLS, header guard, getinfo):
 * the curl hooks then skip their tracking so our own options never read as the
 * script's. */
static int g_internal = 0;

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

static howdah_cent *map_find(long key) {
    int i;
    for (i = 0; i < HOWDAH_MAP_SLOTS; i++) {
        if (g_map[i].used && g_map[i].key == key) return &g_map[i];
    }
    return NULL;
}

/* Forget everything about `key` (handle ids are reused: never inherit state). */
static void map_del(long key) {
    howdah_cent *e = map_find(key);
    if (e) {
        free(e->url);
        memset(e, 0, sizeof *e);
    }
}

/* The entry for `key`, created if absent; NULL when the table is full. */
static howdah_cent *map_slot(long key) {
    int i;
    howdah_cent *e = map_find(key);
    if (e) return e;
    for (i = 0; i < HOWDAH_MAP_SLOTS; i++) {
        if (!g_map[i].used) {
            memset(&g_map[i], 0, sizeof g_map[i]);
            g_map[i].used = 1;
            g_map[i].key = key;
            return &g_map[i];
        }
    }
    return NULL;
}

/* Forget the URL only (a non-string URL: unknown target, unguarded); option
 * flags stay. */
static void map_unset_url(long key) {
    howdah_cent *e = map_find(key);
    if (e) {
        free(e->url);
        e->url = NULL;
        e->len = 0;
        e->overlong = 0; /* a non-string URL clears the over-long flag too */
    }
}

/* Set/replace the URL for `key`, keeping its option flags. An over-long URL is
 * TRUNCATED to its first HOWDAH_URL_MAX bytes, never dropped: a URL's authority
 * is at its front, so the host still reaches the classifier, and a URL long
 * enough to be cut mid-authority parses as oversize (suspicious) on the Rust
 * side. Dropping it instead would leave the handle untracked, and an attacker
 * who appends a long `#fragment` (which libcurl ignores but still connects
 * past) could then skip every curl guard. A full table drops the new entry. */
static void map_set(long key, const char *u, size_t len) {
    howdah_cent *e = map_slot(key);
    char *copy;
    size_t keep;
    if (!e) return;
    free(e->url); /* clear first: an OOM or overflow must not leave a stale URL */
    e->url = NULL;
    e->len = 0;
    /* Set before the malloc, so an over-long URL is flagged suspicious even if
     * the (truncated) copy cannot be stored. A later short URL on the same
     * handle clears it. */
    e->overlong = len > HOWDAH_URL_MAX;
    keep = len > HOWDAH_URL_MAX ? HOWDAH_URL_MAX : len;
    copy = (char *)malloc(keep + 1);
    if (!copy) return;
    memcpy(copy, u, keep);
    copy[keep] = '\0';
    e->url = copy;
    e->len = keep;
}

static void map_flag(long key, unsigned f, int on) {
    howdah_cent *e = map_slot(key);
    if (!e) return;
    if (on) e->flags |= f;
    else e->flags &= ~f;
}

/* Remember the script's setting of one of the options the hardening cares
 * about. `v` is the (dereferenced) value, or NULL. */
static void track_opt(long key, long opt, zval *v) {
    switch (opt) {
    case HOWDAH_CURLOPT_FOLLOWLOCATION:
        map_flag(key, HCF_FOLLOW, v && zend_is_true(v));
        break;
    case HOWDAH_CURLOPT_HEADERFUNCTION:
        /* Our own guard is not the script's callback. */
        map_flag(key, HCF_USER_HDR,
                 v && Z_TYPE_P(v) != IS_NULL
                     && !(HOWDAH_IS_STR(v) && Z_STRLEN_P(v) == sizeof(HOWDAH_HDR_FN) - 1
                          && memcmp(Z_STRVAL_P(v), HOWDAH_HDR_FN, sizeof(HOWDAH_HDR_FN) - 1) == 0));
        break;
    case HOWDAH_CURLOPT_RESOLVE:
        map_flag(key, HCF_USER_RESOLVE,
                 v && Z_TYPE_P(v) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL_P(v)) > 0);
        break;
    case HOWDAH_CURLOPT_CONNECT_TO:
        map_flag(key, HCF_USER_CONNECT_TO,
                 v && Z_TYPE_P(v) == IS_ARRAY && zend_hash_num_elements(Z_ARRVAL_P(v)) > 0);
        break;
    case HOWDAH_CURLOPT_PROXY:
        map_flag(key, HCF_PROXY, HOWDAH_IS_STR(v) && Z_STRLEN_P(v) > 0);
        break;
    default:
        break;
    }
}

static int is_tracked_opt(long opt) {
    return opt == HOWDAH_CURLOPT_FOLLOWLOCATION || opt == HOWDAH_CURLOPT_HEADERFUNCTION
        || opt == HOWDAH_CURLOPT_RESOLVE || opt == HOWDAH_CURLOPT_CONNECT_TO
        || opt == HOWDAH_CURLOPT_PROXY;
}

/* The value stored under integer key `idx` of a PHP array (dereferenced), or
 * NULL. */
static zval *arr_opt(zval *arr, long idx) {
#if PHP_VERSION_ID >= 70000
    zval *v = zend_hash_index_find(Z_ARRVAL_P(arr), idx);
    if (v) ZVAL_DEREF(v);
    return v;
#else
    zval **pv;
    return zend_hash_index_find(Z_ARRVAL_P(arr), idx, (void **)&pv) == SUCCESS ? *pv : NULL;
#endif
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
    if (!g_internal && handle_key(h, &k) && o && Z_TYPE_P(o) == IS_LONG) {
        if (Z_LVAL_P(o) == HOWDAH_CURLOPT_URL) {
            if (HOWDAH_IS_STR(v)) map_set(k, Z_STRVAL_P(v), Z_STRLEN_P(v));
            else map_unset_url(k); /* non-string URL: unknown target (unguarded) */
        } else if (is_tracked_opt(Z_LVAL_P(o))
                   && (ssrf_mask() & (HOWDAH_SSRF_ARM_REBIND | HOWDAH_SSRF_ARM_REDIRECT
                                      | HOWDAH_SSRF_ARM_SCHEME))) {
            track_opt(k, Z_LVAL_P(o), v);
        }
    }
    howdah_orig_curl_setopt(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static void howdah_hook_curl_setopt_array(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h, *arr;
    long k;
    HOWDAH_ARG(1, h);
    HOWDAH_ARG(2, arr);
    if (!g_internal && handle_key(h, &k) && arr && Z_TYPE_P(arr) == IS_ARRAY) {
        zval *v = arr_opt(arr, HOWDAH_CURLOPT_URL);
        if (v) {
            if (Z_TYPE_P(v) == IS_STRING) map_set(k, Z_STRVAL_P(v), Z_STRLEN_P(v));
            else map_unset_url(k);
        }
        if (ssrf_mask() & (HOWDAH_SSRF_ARM_REBIND | HOWDAH_SSRF_ARM_REDIRECT
                           | HOWDAH_SSRF_ARM_SCHEME)) {
            static const long opts[] = { HOWDAH_CURLOPT_FOLLOWLOCATION,
                                         HOWDAH_CURLOPT_HEADERFUNCTION, HOWDAH_CURLOPT_RESOLVE,
                                         HOWDAH_CURLOPT_CONNECT_TO, HOWDAH_CURLOPT_PROXY };
            size_t i;
            for (i = 0; i < sizeof opts / sizeof opts[0]; i++) {
                zval *ov = arr_opt(arr, opts[i]);
                if (ov) track_opt(k, opts[i], ov);
            }
        }
    }
    howdah_orig_curl_setopt_array(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

static void howdah_hook_curl_copy_handle(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h;
    long src, dst;
    howdah_cent *se = NULL;
    char *url = NULL;
    size_t ulen = 0;
    unsigned flags = 0;
    int have = 0, overlong = 0;
    HOWDAH_ARG(1, h);
    if (handle_key(h, &src) && (se = map_find(src)) != NULL) {
        have = 1;
        flags = se->flags;
        overlong = se->overlong;
        if (se->url) {
            url = (char *)malloc(se->len + 1);
            if (url) {
                memcpy(url, se->url, se->len);
                url[se->len] = '\0';
                ulen = se->len;
            }
        }
    }
    howdah_orig_curl_copy_handle(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (handle_key(return_value, &dst)) {
        map_del(dst);
        if (have) {
            howdah_cent *de;
            if (url) map_set(dst, url, ulen); /* resets the entry's overlong */
            de = map_slot(dst);
            if (de) {
                de->flags = flags;
                de->overlong = overlong; /* carry the source's over-long flag (map_set cleared it) */
            }
        }
    }
    free(url);
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

/* ---- calling curl_* from C ------------------------------------------------ */
/* The hardening changes a handle's options (CURLOPT_PROTOCOLS / _RESOLVE /
 * _HEADERFUNCTION) and reads it back (CURLINFO_*). The CURL* behind a PHP handle
 * is a private php_curl field whose layout differs per PHP version, so it goes
 * through PHP's own curl_setopt / curl_getinfo (call_user_function), the one
 * interface that is identical on 5.4-8.5. error_reporting is silenced for the
 * call and any exception it raised is cleared: a failed attempt must never
 * surface in the script. */

/* Call PHP function `fname` with (h, opt [, val]); the result lands in `ret`
 * (valid only when this returns 1). */
static int howdah_php_call(const char *fname, zval *h, long opt, zval *val, zval *ret) {
    int ok, saved;
#if PHP_VERSION_ID >= 70000
    zval fn, params[3];
    int n = val ? 3 : 2;
    ZVAL_STRING(&fn, fname);
    ZVAL_COPY_VALUE(&params[0], h); /* shallow: the callee takes its own reference */
    ZVAL_LONG(&params[1], opt);
    if (val) ZVAL_COPY_VALUE(&params[2], val);
    ZVAL_UNDEF(ret);
    saved = EG(error_reporting);
    EG(error_reporting) = 0;
    g_internal++;
    ok = call_user_function(CG(function_table), NULL, &fn, ret, n, params) == SUCCESS;
    g_internal--;
    EG(error_reporting) = saved;
    if (EG(exception)) {
        zend_clear_exception();
        ok = 0;
    }
    zval_ptr_dtor(&fn);
#else
    zval *fn, *p1, *params[3];
    int n = val ? 3 : 2;
    TSRMLS_FETCH();
    MAKE_STD_ZVAL(fn);
    ZVAL_STRING(fn, (char *)fname, 1);
    MAKE_STD_ZVAL(p1);
    ZVAL_LONG(p1, opt);
    params[0] = h;
    params[1] = p1;
    params[2] = val;
    INIT_ZVAL(*ret);
    saved = EG(error_reporting);
    EG(error_reporting) = 0;
    g_internal++;
    ok = call_user_function(CG(function_table), NULL, fn, ret, n, params TSRMLS_CC) == SUCCESS;
    g_internal--;
    EG(error_reporting) = saved;
    zval_ptr_dtor(&fn);
    zval_ptr_dtor(&p1);
#endif
    return ok;
}

/* curl_setopt($h, opt, value). kind: 0 long `lval`, 1 string `s`, 2 an array
 * holding the one string `s`. Returns 1 iff curl_setopt reported success. */
static int howdah_curl_setopt(zval *h, long opt, int kind, long lval, const char *s,
                              size_t slen) {
    zval ret;
    int ok;
#if PHP_VERSION_ID >= 70000
    zval val;
    if (kind == 0) {
        ZVAL_LONG(&val, lval);
    } else if (kind == 1) {
        ZVAL_STRINGL(&val, s, slen);
    } else {
        array_init(&val);
        add_next_index_stringl(&val, s, slen);
    }
    ok = howdah_php_call("curl_setopt", h, opt, &val, &ret);
    if (ok) ok = zend_is_true(&ret);
    zval_ptr_dtor(&ret); /* UNDEF when the call failed: a no-op */
    zval_ptr_dtor(&val);
#else
    zval *val;
    MAKE_STD_ZVAL(val);
    if (kind == 0) {
        ZVAL_LONG(val, lval);
    } else if (kind == 1) {
        ZVAL_STRINGL(val, (char *)s, slen, 1);
    } else {
        array_init(val);
        add_next_index_stringl(val, (char *)s, slen, 1);
    }
    ok = howdah_php_call("curl_setopt", h, opt, val, &ret);
    if (ok) ok = zend_is_true(&ret);
    zval_dtor(&ret);
    zval_ptr_dtor(&val);
#endif
    return ok;
}

/* curl_getinfo($h, opt) for a string-valued CURLINFO_*: copied NUL-terminated
 * into out[cap]. Returns 1 iff a string shorter than cap came back. */
static int howdah_curl_getinfo_str(zval *h, long opt, char *out, size_t cap, size_t *len) {
    zval ret;
    int got = 0;
    *len = 0;
    if (howdah_php_call("curl_getinfo", h, opt, NULL, &ret) && Z_TYPE(ret) == IS_STRING
        && (size_t)Z_STRLEN(ret) < cap) {
        memcpy(out, Z_STRVAL(ret), Z_STRLEN(ret));
        *len = (size_t)Z_STRLEN(ret);
        out[*len] = '\0';
        got = 1;
    }
#if PHP_VERSION_ID >= 70000
    zval_ptr_dtor(&ret);
#else
    zval_dtor(&ret);
#endif
    return got;
}

/* libcurl takes a comma list of addresses in one CURLOPT_RESOLVE entry since
 * 7.59.0; older versions take exactly one (a list would be ignored). Found once
 * through curl_version_info in the already-loaded libcurl; unknown = one. */
#if PHP_VERSION_ID >= 50500
struct howdah_curl_vi { int age; const char *version; unsigned int version_num; };
static int curl_pin_multi(void) {
    static int cached = -1;
    if (cached < 0) {
        typedef struct howdah_curl_vi *(*vi_fn)(int);
        vi_fn fn = (vi_fn)(uintptr_t)dlsym(RTLD_DEFAULT, "curl_version_info");
        struct howdah_curl_vi *d = fn ? fn(0) : NULL;
        cached = (d && d->version_num >= 0x073B00u) ? 1 : 0;
    }
    return cached;
}
#endif

/* A proxy (CURLOPT_PROXY, or libcurl's own *_proxy environment variables) means
 * the connection goes to the proxy, which resolves the target itself: neither
 * pinning nor the connected-peer check says anything about the target then. */
static int env_proxy(void) {
    static const char *const names[] = { "http_proxy", "https_proxy", "all_proxy",
                                         "HTTPS_PROXY", "ALL_PROXY", NULL };
    int i;
    for (i = 0; names[i]; i++) {
        const char *v = getenv(names[i]);
        if (v && *v) return 1;
    }
    return 0;
}

/* Before a guarded curl_exec: set what the armed knobs need on the handle.
 * Returns 1 iff the call must be refused (rebind=block: the host resolves to an
 * internal address). `u` is a private copy of the handle's URL. */
static int curl_prepare(zval *h, unsigned flags, int mask, const char *u, size_t ulen) {
    /* scheme=block: have libcurl itself refuse anything but http(s), redirect
     * hops included, whatever a URL parsing difference lets past the check. */
    if (mask & HOWDAH_SSRF_ARM_PROTOCOLS)
        howdah_curl_setopt(h, HOWDAH_CURLOPT_PROTOCOLS, 0, HOWDAH_CURLPROTO_HTTP_HTTPS, NULL, 0);

    /* rebind=block: judge the very set libcurl is about to connect to (a name
     * that resolves to an internal address is refused here, allow_hosts still
     * wins) and pin it so libcurl cannot re-resolve to something else. Skipped
     * when the script manages resolution itself (CURLOPT_RESOLVE / CONNECT_TO)
     * or uses a proxy: the after-the-fact check covers those. */
    if ((mask & HOWDAH_SSRF_ARM_PIN) && g_decide
        && !(flags & (HCF_USER_RESOLVE | HCF_USER_CONNECT_TO | HCF_PROXY)) && !env_proxy()) {
        howdah_target t;
        int pr = ssrf_target(u, ulen, 0, 1, &t);
        if (pr == 2) {
            /* Truncated/oversize resolution: an unverifiable set that cannot be
             * pinned; rebind=block refuses it rather than letting it connect
             * unpinned (F8 re-review). */
            if (howdah_ssrf_oversize_glue(g_ctx, HOWDAH_SSRF_KIND_REBIND) == HOWDAH_ACTION_BLOCK)
                return 1;
        } else if (pr == 1) {
            if (g_decide(g_ctx, HOWDAH_SSRF_KIND_REBIND, "curl-resolve", sizeof("curl-resolve") - 1,
                         (const char *)t.host, t.hlen, t.port, t.count ? t.recs : NULL, t.count)
                == HOWDAH_ACTION_BLOCK)
                return 1;
#if PHP_VERSION_ID >= 50500
            /* The pin itself needs CURLOPT_RESOLVE, which PHP 5.4 does not have. */
            if (t.count) {
                unsigned char entry[512];
                size_t n = howdah_ssrf_pin_entry((const unsigned char *)u, ulen, t.recs, t.count,
                                                 curl_pin_multi(), entry, sizeof entry);
                if (n) howdah_curl_setopt(h, HOWDAH_CURLOPT_RESOLVE, 2, 0, (const char *)entry, n);
            }
#endif
        }
    }

    /* redirect / scheme: when libcurl follows redirects and the script has no
     * header callback of its own, install the guard that sees each Location
     * before libcurl acts on it. */
    if ((mask & (HOWDAH_SSRF_ARM_REDIRECT | HOWDAH_SSRF_ARM_SCHEME)) && (flags & HCF_FOLLOW)
        && !(flags & HCF_USER_HDR))
        howdah_curl_setopt(h, HOWDAH_CURLOPT_HEADERFUNCTION, 1, 0, HOWDAH_HDR_FN,
                           sizeof(HOWDAH_HDR_FN) - 1);
    return 0;
}

/* After a successful guarded curl_exec: judge the address libcurl really
 * connected to (CURLINFO_PRIMARY_IP: the last hop's connection) against the
 * host of the final URL. If it is internal the response is discarded. This is
 * the whole of the resolve-at-connect guarantee on PHP 5.4 (no CURLOPT_RESOLVE)
 * and the backstop for redirect hops and script-managed resolution elsewhere.
 * The request has already been sent: discarding hides the response (no exfil of
 * the answer) but cannot un-send it, and a body streamed to CURLOPT_FILE /
 * WRITEFUNCTION or echoed (no RETURNTRANSFER) is already out. */
static void curl_postcheck(zval *h, zval *rv, unsigned flags) {
    char ipb[64], eff[HOWDAH_URL_MAX + 1];
    size_t iplen = 0, efflen = 0;
    unsigned char rec[HOWDAH_REC];
    struct in_addr a4;
    struct in6_addr a6;
    howdah_target t;
    int block;

    if (!g_decide || (flags & HCF_PROXY) || env_proxy()) return;
#if PHP_VERSION_ID >= 70000
    if (Z_TYPE_P(rv) == IS_FALSE) return;
#else
    if (Z_TYPE_P(rv) == IS_BOOL && !Z_BVAL_P(rv)) return;
#endif
    if (!howdah_curl_getinfo_str(h, HOWDAH_CURLINFO_PRIMARY_IP, ipb, sizeof ipb, &iplen) || !iplen)
        return;
    memset(rec, 0, sizeof rec);
    if (inet_pton(AF_INET, ipb, &a4) == 1) {
        rec[0] = 4;
        memcpy(rec + 1, &a4, 4);
    } else if (inet_pton(AF_INET6, ipb, &a6) == 1) {
        rec[0] = 6;
        memcpy(rec + 1, &a6, 16);
    } else {
        return;
    }
    t.hlen = 0;
    t.port = 0;
    if (!(howdah_curl_getinfo_str(h, HOWDAH_CURLINFO_EFFECTIVE_URL, eff, sizeof eff, &efflen)
          && ssrf_target(eff, efflen, 0, 0, &t) == 1)) {
        t.hlen = 0;
        t.port = 0;
    }
    block = g_decide(g_ctx, HOWDAH_SSRF_KIND_REBIND, "curl-connect", sizeof("curl-connect") - 1,
                     (const char *)t.host, t.hlen, t.port, rec, 1)
            == HOWDAH_ACTION_BLOCK;
    if (block) {
#if PHP_VERSION_ID >= 70000
        zval_ptr_dtor(rv);
#else
        zval_dtor(rv);
#endif
        ZVAL_BOOL(rv, 0);
    }
}

static void howdah_hook_curl_exec(INTERNAL_FUNCTION_PARAMETERS) {
    zval *h;
    long k;
    howdah_cent *e;
    unsigned flags = 0;
    int post = 0;
    HOWDAH_ARG(1, h);
    /* No URL known for the handle: chain unguarded (documented gap). */
    if (handle_key(h, &k) && (e = map_find(k)) != NULL && (e->url || e->overlong)) {
        const char *org = howdah_current_script();
        size_t orglen = org ? strlen(org) : 0;
        int mask = ssrf_mask();
        if (e->overlong) {
            /* Over-long URL (> HOWDAH_URL_MAX): a long userinfo can steer the
             * truncation so the stored text parses to an empty or wrong host, so
             * never infer the host from it. The scheme is at the front (the
             * stored prefix is still valid for the scheme check); the range
             * verdict is the oversize/suspicious one (F1 re-review). Everything
             * else the normal path does still runs, just without a trusted host. */
            flags = e->flags; /* so curl_postcheck sees HCF_PROXY etc. (re-review) */
            if (e->url && ssrf_scheme_blocked(e->url, e->len, HOWDAH_SSRF_VIA_CURL)) {
                RETVAL_FALSE;
                return;
            }
            if ((mask & HOWDAH_SSRF_ARM_RANGE) && g_decide
                && howdah_ssrf_oversize_glue(g_ctx, HOWDAH_SSRF_KIND_RANGE) == HOWDAH_ACTION_BLOCK) {
                RETVAL_FALSE;
                return;
            }
            /* Layer-4 egress: with no trusted host, judge an empty host — never
             * on allow_egress_hosts, so it fails closed rather than skipping the
             * allow-list for an over-long URL (F1 re-review). */
            if (howdah_g_behavior_egress && howdah_g_behavior_armed
                && howdah_g_behavior_armed(g_ctx, HOWDAH_BEHAVIOR_EGRESS)
                && howdah_g_behavior_egress(g_ctx, org, orglen, "", 0) == HOWDAH_ACTION_BLOCK) {
                RETVAL_FALSE;
                return;
            }
            /* scheme=block: have libcurl itself refuse non-http(s) (host-independent). */
            if (mask & HOWDAH_SSRF_ARM_PROTOCOLS)
                howdah_curl_setopt(h, HOWDAH_CURLOPT_PROTOCOLS, 0, HOWDAH_CURLPROTO_HTTP_HTTPS, NULL, 0);
            /* redirect/scheme: install the Location guard so a 3xx to an internal
             * target is still caught (F3 re-review). Can't pin without a trusted
             * host; the rebind post-check is the backstop. */
            if ((mask & (HOWDAH_SSRF_ARM_REDIRECT | HOWDAH_SSRF_ARM_SCHEME)) && (flags & HCF_FOLLOW)
                && !(flags & HCF_USER_HDR))
                howdah_curl_setopt(h, HOWDAH_CURLOPT_HEADERFUNCTION, 1, 0, HOWDAH_HDR_FN,
                                   sizeof(HOWDAH_HDR_FN) - 1);
            post = (mask & HOWDAH_SSRF_ARM_REBIND) != 0;
        } else {
            if (ssrf_scheme_blocked(e->url, e->len, HOWDAH_SSRF_VIA_CURL)
                || ssrf_should_block(e->url, e->len, 0, org, orglen)) {
                RETVAL_FALSE;
                return;
            }
            flags = e->flags;
            if (mask & (HOWDAH_SSRF_ARM_PROTOCOLS | HOWDAH_SSRF_ARM_PIN | HOWDAH_SSRF_ARM_REDIRECT
                        | HOWDAH_SSRF_ARM_SCHEME)) {
                /* Private copy: the calls below run PHP code paths that could, in
                 * theory, rewrite the map entry. */
                char ubuf[HOWDAH_URL_MAX + 1];
                size_t ulen = e->len;
                memcpy(ubuf, e->url, ulen);
                ubuf[ulen] = '\0';
                if (curl_prepare(h, flags, mask, ubuf, ulen)) {
                    RETVAL_FALSE;
                    return;
                }
            }
            post = (mask & HOWDAH_SSRF_ARM_REBIND) != 0;
        }
    }
    howdah_orig_curl_exec(INTERNAL_FUNCTION_PARAM_PASSTHRU);
    if (post) curl_postcheck(h, return_value, flags);
}

/* ---- curl redirect guard (the registered header callback) ----------------- */
/* HTTP status of the response whose headers are streaming through the guard
 * (0 = none seen yet). One synchronous curl_exec at a time. */
static int g_hdr_status = 0;

/* 1 iff the redirect hop to `loc` (a Location value) must be refused. */
static int hop_blocked(const char *loc, size_t len, int mask) {
    howdah_target t;
    const char *scheme;
    size_t scheme_len;
    int prep;
    /* A hop to gopher://, dict://, file://, ...: the scheme policy. */
    if ((mask & HOWDAH_SSRF_ARM_SCHEME)
        && howdah_ssrf_scheme_glue(g_ctx, HOWDAH_SSRF_VIA_CURL, loc, len) == HOWDAH_ACTION_BLOCK)
        return 1;
    if (!(mask & HOWDAH_SSRF_ARM_REDIRECT) || !g_decide) return 0;
    prep = ssrf_target(loc, len, 2, 1, &t);
    if (prep == 2)
        return howdah_ssrf_oversize_glue(g_ctx, HOWDAH_SSRF_KIND_REDIRECT) == HOWDAH_ACTION_BLOCK;
    if (prep != 1) return 0; /* relative reference: same host, not a new target */
    ssrf_cosmetic_scheme(loc, len, &scheme, &scheme_len);
    return g_decide(g_ctx, HOWDAH_SSRF_KIND_REDIRECT, scheme, scheme_len, (const char *)t.host,
                    t.hlen, t.port, t.count ? t.recs : NULL, t.count)
           == HOWDAH_ACTION_BLOCK;
}

/* The function installed as CURLOPT_HEADERFUNCTION. libcurl (through PHP)
 * calls it as ($ch, $header_line) for every response header line and treats a
 * return value other than the line length as a failure to write the header:
 * the transfer aborts with CURLE_WRITE_ERROR BEFORE the Location is followed.
 * It returns the length (pass) or 0 (abort); it keeps no state but the status
 * line of the current response so a `Location` on a non-3xx is ignored. */
static void howdah_curl_header_guard(INTERNAL_FUNCTION_PARAMETERS) {
    zval *line;
    const char *s, *v;
    size_t len, vlen;
    int mask;
#if PHP_VERSION_ID < 70000
    (void)return_value_ptr;
    (void)this_ptr;
    (void)return_value_used;
#endif
    HOWDAH_ARG(2, line);
    if (!HOWDAH_IS_STR(line)) {
        RETVAL_LONG(0);
        return;
    }
    s = Z_STRVAL_P(line);
    len = Z_STRLEN_P(line);
    RETVAL_LONG((long)len);
    mask = ssrf_mask();
    if (!(mask & (HOWDAH_SSRF_ARM_REDIRECT | HOWDAH_SSRF_ARM_SCHEME))) return;
    if (len >= 5 && strncasecmp(s, "HTTP/", 5) == 0) {
        /* "HTTP/1.1 302 Found" / "HTTP/2 302": the code after the first space. */
        size_t i = 5;
        int code = 0, digits = 0;
        while (i < len && s[i] != ' ') i++;
        while (i < len && s[i] == ' ') i++;
        while (i < len && digits < 3 && s[i] >= '0' && s[i] <= '9') {
            code = code * 10 + (s[i] - '0');
            digits++;
            i++;
        }
        g_hdr_status = digits == 3 ? code : 0;
        return;
    }
    if (len > 9 && strncasecmp(s, "location:", 9) == 0
        && (g_hdr_status == 0 || (g_hdr_status >= 300 && g_hdr_status < 400))) {
        v = s + 9;
        vlen = len - 9;
        while (vlen && (*v == ' ' || *v == '\t')) { v++; vlen--; }
        while (vlen && (v[vlen - 1] == '\r' || v[vlen - 1] == '\n' || v[vlen - 1] == ' '
                        || v[vlen - 1] == '\t')) vlen--;
        if (vlen > HOWDAH_URL_MAX) {
            /* Over-long Location: the scheme is at the front (checkable), but a
             * long userinfo could steer a truncation into a wrong/relative host
             * parse, so the redirect target is the suspicious verdict, not a
             * parse of the truncated text (F1 re-review). */
            if ((mask & HOWDAH_SSRF_ARM_SCHEME)
                && howdah_ssrf_scheme_glue(g_ctx, HOWDAH_SSRF_VIA_CURL, v, HOWDAH_URL_MAX) == HOWDAH_ACTION_BLOCK) {
                RETVAL_LONG(0);
                return;
            }
            if ((mask & HOWDAH_SSRF_ARM_REDIRECT) && g_decide
                && howdah_ssrf_oversize_glue(g_ctx, HOWDAH_SSRF_KIND_REDIRECT) == HOWDAH_ACTION_BLOCK)
                RETVAL_LONG(0);
            return;
        }
        if (vlen && hop_blocked(v, vlen, mask)) RETVAL_LONG(0); /* abort: do not follow */
    }
}

/* PHP 8 warns "Missing arginfo" for an internal function registered without
 * one, so spell out the ($ch, $header) signature. */
ZEND_BEGIN_ARG_INFO_EX(howdah_hdr_arginfo, 0, 0, 2)
    ZEND_ARG_INFO(0, ch)
    ZEND_ARG_INFO(0, header)
ZEND_END_ARG_INFO()

static const zend_function_entry howdah_hdr_fe[] = {
    { .fname = HOWDAH_HDR_FN, .handler = howdah_curl_header_guard, .arg_info = howdah_hdr_arginfo,
      .num_args = (sizeof(howdah_hdr_arginfo) / sizeof(howdah_hdr_arginfo[0])) - 1, .flags = 0 },
    { .fname = NULL }
};
static int g_hdr_registered = 0;


/* Register the redirect / scheme guard as a PHP-callable internal function: a
 * curl handle's CURLOPT_HEADERFUNCTION has to name something PHP can call. MUST
 * be called at MINIT, never later: a function registered at request time gets a
 * name interned in the request's own string table on PHP 7.x, which dangles in
 * the persistent function table once the request ends (the worker aborted at
 * shutdown, intermittently, on PHP 7.0). The caller registers only when the
 * redirect or scheme knob is armed, so a default install adds no function to
 * the namespace. Idempotent. */
void howdah_register_ssrf_guard_fn(void) {
#if PHP_VERSION_ID < 70000
    TSRMLS_FETCH();
#endif
    if (g_hdr_registered) return;
#if PHP_VERSION_ID < 70000
    zend_register_functions(NULL, howdah_hdr_fe, NULL, MODULE_PERSISTENT TSRMLS_CC);
#else
    zend_register_functions(NULL, howdah_hdr_fe, NULL, MODULE_PERSISTENT);
#endif
    g_hdr_registered = 1;
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

/* Install the Layer-4 behavior hooks. Sets the shared behavior callback pointers
 * (used by both sink_hook.c and here) AND function-table-swaps the write sinks
 * selected by `swap` (HOWDAH_BHV_SWAP_*): file_put_contents / copy (GENERIC),
 * move_uploaded_file (GENERIC or UPLOAD), rename (GENERIC or RENAME_SRC). fopen is
 * deliberately NOT swapped here — howdah_install_ssrf_hooks already swapped it,
 * and its bespoke trampoline's php-write branch goes live once these callbacks
 * are set and GENERIC is requested. Call once at first RINIT, after
 * howdah_install_ssrf_hooks, so fopen's original handler is this file's SSRF
 * trampoline (not re-captured). A NULL callback leaves that facet unguarded
 * (fail-open). Swapping only what an armed facet needs keeps a default install
 * (upload-write + delete guards) off the hot file_put_contents / copy paths. */
void howdah_install_behavior_hooks(howdah_behavior_armed_t armed,
                                   howdah_behavior_exec_dir_t exec_dir,
                                   howdah_behavior_binary_t binary,
                                   howdah_behavior_egress_t egress,
                                   howdah_behavior_php_write_t php_write,
                                   int swap) {
    howdah_g_behavior_armed = armed;
    howdah_g_behavior_exec_dir = exec_dir;
    howdah_g_behavior_binary = binary;
    howdah_g_behavior_egress = egress;
    howdah_g_behavior_php_write = php_write;
    howdah_g_bhv_generic = (swap & HOWDAH_BHV_SWAP_GENERIC) ? 1 : 0;
    howdah_g_bhv_rename_src = (swap & HOWDAH_BHV_SWAP_RENAME_SRC) ? 1 : 0;
    if (swap & HOWDAH_BHV_SWAP_GENERIC) {
        HOWDAH_SSRF_SWAP(file_put_contents, "file_put_contents");
        HOWDAH_SSRF_SWAP(copy, "copy");
    }
    if (swap & (HOWDAH_BHV_SWAP_GENERIC | HOWDAH_BHV_SWAP_UPLOAD)) {
        HOWDAH_SSRF_SWAP(move_uploaded_file, "move_uploaded_file");
    }
    if (swap & (HOWDAH_BHV_SWAP_GENERIC | HOWDAH_BHV_SWAP_RENAME_SRC)) {
        HOWDAH_SSRF_SWAP(rename, "rename");
    }
}

/* Clear all per-request state: the curl handle->URL map, the resolution cache
 * and the ctx. Call at request teardown (RSHUTDOWN, and the bailout path via
 * clear_request_state). */
void howdah_ssrf_request_reset(void) {
    int i;
    for (i = 0; i < HOWDAH_MAP_SLOTS; i++) {
        if (g_map[i].used) {
            free(g_map[i].url);
            memset(&g_map[i], 0, sizeof g_map[i]);
        }
    }
    g_internal = 0;
    g_hdr_status = 0;
    for (i = 0; i < HOWDAH_CACHE_SLOTS; i++) g_cache[i].used = 0;
    g_ctx = NULL;
}
