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
