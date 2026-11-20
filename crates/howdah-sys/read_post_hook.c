/* The §4.1 raw-body hook: wrap `sapi_module.read_post`, the reader every PHP
 * body path (rfc1867 `fill_buffer`, the urlencoded reader) pulls bytes through.
 *
 * Gaps A and B happen before PHP fires any rfc1867 event for the part involved,
 * so the parsed-event callback cannot reach them. This shim chains the prior
 * reader, hands the bytes just read to the Rust decide callback (which feeds the
 * byte-stream scanner in howdah-core), and — once the scanner says Block —
 * returns 0 so PHP sees a clean end of body (`sapi_read_post_block` treats a
 * `<= 0` return as EOF and stops). The verdict is recorded in the core ctx and
 * delivered through the existing RINIT refusal; no longjmp here.
 *
 * `read_post`'s signature differs by generation (NTS; TSRMLS is empty):
 *   5.x : int    (char *buffer, unsigned int count)
 *   7.x+: size_t (char *buffer, size_t       count)
 * Installed from MINIT, restored at MSHUTDOWN; `g_stop` is reset per request by
 * the glue (`howdah_read_post_reset`). NTS only, like the rest of Howdah. */
#include "main/php.h"
#include "SAPI.h"
#include <stdint.h>
#include <string.h>

#if PHP_VERSION_ID >= 70000
typedef size_t howdah_rp_count_t;
typedef size_t howdah_rp_ret_t;
#else
typedef unsigned int howdah_rp_count_t;
typedef int howdah_rp_ret_t;
#endif

/* Rust decide: given the bytes just read, returns 1 to STOP the body (the
 * scanner decided Block) or 0 to continue. See crates/howdah-ext/src/post_scan.rs. */
typedef int (*howdah_read_post_decide_t)(const char *buf, size_t len);

static howdah_read_post_decide_t howdah_rp_decide = NULL;
static howdah_rp_ret_t (*howdah_rp_prev)(char *, howdah_rp_count_t) = NULL;
static int howdah_rp_installed = 0;
static int howdah_rp_stop = 0; /* latched on Block; reset per request */

static howdah_rp_ret_t howdah_read_post(char *buffer, howdah_rp_count_t count) {
    howdah_rp_ret_t n;
    if (howdah_rp_stop) {
        return 0; /* already blocked this request: signal EOF */
    }
    if (!howdah_rp_prev) {
        return 0;
    }
    n = howdah_rp_prev(buffer, count);
    if (n > 0 && howdah_rp_decide && howdah_rp_decide(buffer, (size_t) n)) {
        howdah_rp_stop = 1;
        return 0; /* clean end of body; PHP stops reading */
    }
    return n;
}

/* Save sapi_module.read_post and install ours. Call once at MINIT. Idempotent:
 * a second call that finds our own hook installed only refreshes the callback. */
void howdah_install_read_post_hook(howdah_read_post_decide_t cb) {
    if (howdah_rp_installed) {
        howdah_rp_decide = cb;
        return;
    }
    howdah_rp_decide = cb;
    howdah_rp_prev = sapi_module.read_post;
    sapi_module.read_post = howdah_read_post;
    howdah_rp_installed = 1;
}

/* Restore the saved reader. Only when OUR hook is still installed (do not
 * clobber a later-installed reader). Called from MSHUTDOWN. */
void howdah_uninstall_read_post_hook(void) {
    if (howdah_rp_installed && sapi_module.read_post == howdah_read_post) {
        sapi_module.read_post = howdah_rp_prev;
    }
    howdah_rp_prev = NULL;
    howdah_rp_decide = NULL;
    howdah_rp_installed = 0;
}

/* Clear the per-request stop latch. The glue calls this at request begin so a
 * block in one request does not wedge the persistent fpm/Apache worker's reads
 * for the next one. */
void howdah_read_post_reset(void) {
    howdah_rp_stop = 0;
}

/* PHP's effective, PARSED limits for this request (bytes). zend_ini_long would
 * misread the "128M" shorthand; PG(memory_limit)/SG(post_max_size) hold the
 * byte values PHP actually enforces. memory_limit = -1 when unlimited;
 * post_max_size = 0 when unlimited. */
int64_t howdah_memory_limit(void) {
    return (int64_t) PG(memory_limit);
}

int64_t howdah_post_max_size(void) {
    return (int64_t) SG(post_max_size);
}

/* The request's Content-Type as the SAPI recorded it (NUL-terminated, or NULL).
 * Used to extract the multipart boundary. Engine-owned; never freed. */
const char *howdah_request_content_type(void) {
    return SG(request_info).content_type;
}

/* 1 iff PHP resolved this request's body with its multipart/form-data reader,
 * i.e. SG(request_info).post_entry is the multipart entry: non-NULL with a NULL
 * post_reader (rfc1867 pulls read_post from its post_handler). urlencoded has a
 * non-NULL post_reader; php://input / PUT / enable_post_data_reading=0 have no
 * post_entry. Lets the glue arm the byte scanner ONLY for bodies PHP actually
 * parses as multipart — not every read_post consumer — matching where gaps A/B
 * exist. Stable across 5.x-8.x. */
int howdah_is_multipart_post(void) {
    const sapi_post_entry *pe = SG(request_info).post_entry;
    return (pe != NULL && pe->post_reader == NULL) ? 1 : 0;
}

/* CVE-2026-129289: drain the request body PHP leaves unread.
 *
 * `sapi_deactivate_module()` drains leftover body bytes with a
 * `sapi_read_post_block` loop, but only on the `else if (server_context)`
 * branch: it SKIPS the drain when the script opened `php://input`
 * (`SG(request_info).request_body` set). On a reused FastCGI connection
 * (nginx fastcgi_keep_conn, Apache enablereuse, LSAPI, HAProxy) the unread
 * bytes are then parsed as the NEXT FastCGI request, whose PARAMS the sender
 * chose. Our post_deactivate runs BEFORE PHP's deactivation, so we drain here,
 * mirroring SAPI.c's loop exactly.
 *
 * Gated on a FastCGI-family SAPI, a live server_context and `!post_read`.
 * Our scanner hook is neutralised for the drain: the stop latch is cleared (a
 * Block verdict latched it, and a latched hook returns 0 = nothing consumed)
 * and the decide callback is suspended (the request is over; nothing to scan
 * or latch). Never bails or longjmps. Returns the bytes drained (>= 0). */
int64_t howdah_drain_unread_body(void) {
    howdah_read_post_decide_t saved_decide;
    char dummy[SAPI_POST_BLOCK_SIZE];
    int64_t total = 0;
    long rounds = 0;
    const char *n = sapi_module.name;

#if PHP_VERSION_ID < 50600
    (void) n; (void) total; (void) rounds; (void) saved_decide; (void) dummy;
    return 0; /* PHP 5.4/5.5 lack sapi_read_post_block+SG(post_read) (5.6+) and predate the bug: harmless no-op */
#else
    if (!n || !SG(server_context) || SG(post_read)) {
        return 0;
    }
    if (strcmp(n, "fpm-fcgi") != 0 && strcmp(n, "cgi-fcgi") != 0 && strcmp(n, "litespeed") != 0) {
        return 0;
    }
    saved_decide = howdah_rp_decide;
    howdah_rp_decide = NULL;
    howdah_rp_stop = 0;
    for (;;) {
        long r = (long) sapi_read_post_block(dummy, SAPI_POST_BLOCK_SIZE);
        if (r <= 0) {
            break;
        }
        total += r;
        if (r < SAPI_POST_BLOCK_SIZE) {
            break;
        }
        if (++rounds > 4194304) { /* hard ceiling (32 GiB at 8 KiB): never spin forever */
            break;
        }
    }
    howdah_rp_decide = saved_decide;
    return total;
#endif
}

/* ---- FPM status-page injection (CVE-2026-129292) getters ----------------------
 * php-fpm's fpm_request_info() copies these three request fields into the
 * scoreboard BEFORE php_request_startup(), so no extension can prevent the
 * planting; Howdah only reads them at RINIT to log it. NUL-terminated or NULL,
 * engine-owned, never freed. The SG(request_info) members are stable 5.4-8.6. */
const char *howdah_req_auth_user(void) {
    return SG(request_info).auth_user;
}
const char *howdah_req_method(void) {
    return SG(request_info).request_method;
}
const char *howdah_req_script(void) {
    return SG(request_info).path_translated;
}
/* 1 iff the running SAPI is php-fpm ("fpm-fcgi"). */
int howdah_sapi_is_fpm(void) {
    return sapi_module.name && strcmp(sapi_module.name, "fpm-fcgi") == 0;
}
