/* Layer 3 SOAP request guard (CVE-2026-129506, CVE-2026-15353).
 *
 * A class-method handler swap over SoapServer::handle, the same function-table
 * mechanism as legacy_hook.c / sink_hook.c but on a class's function_table
 * entry. The trampoline acquires the request XML BEFORE ext/soap parses it:
 *
 *   - the explicit $request string argument when handle($request) is called
 *     (SOAP parses it with soap_xmlParseMemory), else
 *   - SG(request_info).request_body (what handle() with no argument reads via
 *     soap_xmlParseFile("php://input")): rewind, read a capped copy, rewind so
 *     SOAP re-reads it unchanged. On PHP 7+ a gzip/deflate body is inflated
 *     through a zlib.inflate php_stream filter on a private temp stream (the
 *     original request_body is never touched), matching the Content-Encoding
 *     filter SOAP itself would append, else
 *   - on PHP 5.x, SG(request_info).raw_post_data as a fallback.
 *
 * The bytes go to the Rust glue (which asks the pure core classifier) and are
 * never logged. On BLOCK the glue has already delivered a clean 403, so the
 * trampoline returns WITHOUT calling the original handler: ext/soap's parser is
 * never reached and the worker survives (the disable_functions-style
 * neutralisation legacy_hook.c uses). On ALLOW/LOG it chains the original with
 * the arguments untouched.
 *
 * This is DEFENSIVE: Howdah refuses two malformed request shapes (a prolog DTD,
 * a malformed SOAP-ENC arraySize). It never triggers the underlying
 * use-after-free or heap over-read.
 *
 * Installed at first RINIT only when the guard is armed (ext/soap is a shared
 * extension often loaded after howdah, so MINIT would no-op) and only when the
 * handler is still PHP's own (guards a double-swap / another extension). NTS
 * only, like the rest of Howdah. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "main/php.h"
#include "main/SAPI.h"
#include "main/php_streams.h"
#include "Zend/zend_API.h"
#include "Zend/zend_execute.h"

#include <string.h>
#include <stddef.h>
#include <stdint.h>

#include "howdah_sink.h"

/* Rust glue decide: the raw request XML (scanned, never logged) and whether an
 * oversized body was capped to its prefix. 0 ALLOW / 1 LOG / 2 BLOCK. On BLOCK
 * the glue has already delivered a clean 403. */
typedef int (*howdah_soap_decide_t)(const char *xml, size_t xml_len, int truncated);

static howdah_soap_decide_t g_soap_decide = NULL;

typedef void (*howdah_zif)(INTERNAL_FUNCTION_PARAMETERS);
static howdah_zif howdah_orig_soap_handle = NULL;

/* The most XML Howdah scans from one SOAP request (a few MiB). A larger body is
 * scanned as its capped prefix, with the verdict's reason noting the cap. */
#define HOWDAH_SOAP_SCAN_CAP (4 * 1024 * 1024)
#define HOWDAH_SOAP_INIT_BUF 65536

/* ARG(n, var): the n-th call argument (dereferenced), or NULL if absent.
 * (Same accessor as legacy_hook.c / ssrf_hook.c.) */
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

/* Read a stream to EOF (or the cap) into a growing emalloc buffer. Sets *trunc
 * when the stream held more than the cap. Returns the buffer (caller efrees)
 * and its length via *out_len. */
static char *howdah_soap_read_all(php_stream *s, size_t *out_len, int *trunc) {
    size_t capacity = HOWDAH_SOAP_INIT_BUF;
    size_t total = 0;
    char *acc = (char *)emalloc(capacity);
    for (;;) {
        ssize_t r;
        if (total >= HOWDAH_SOAP_SCAN_CAP) {
            char probe[1];
            if (php_stream_read(s, probe, 1) > 0) {
                *trunc = 1;
            }
            break;
        }
        if (total == capacity) {
            size_t ncap = capacity * 2;
            if (ncap > HOWDAH_SOAP_SCAN_CAP) {
                ncap = HOWDAH_SOAP_SCAN_CAP;
            }
            acc = (char *)erealloc(acc, ncap);
            capacity = ncap;
        }
        r = php_stream_read(s, acc + total, capacity - total);
        if (r <= 0) {
            break;
        }
        total += (size_t)r;
    }
    *out_len = total;
    return acc;
}

#if PHP_VERSION_ID >= 70000
/* A gzip (1f 8b) or zlib (78 xx, header check) magic prefix. A valid SOAP XML
 * body never starts with these (it opens with '<', a BOM or whitespace), so
 * this never mistakes an uncompressed request for a compressed one. */
static int howdah_soap_looks_compressed(const char *b, size_t n) {
    unsigned char c0, c1;
    if (n < 2) {
        return 0;
    }
    c0 = (unsigned char)b[0];
    c1 = (unsigned char)b[1];
    if (c0 == 0x1f && c1 == 0x8b) {
        return 1; /* gzip */
    }
    if (c0 == 0x78 && ((((unsigned)c0 << 8) | c1) % 31) == 0) {
        return 1; /* zlib / deflate with header */
    }
    return 0;
}

/* Best-effort inflate of gzip/deflate bytes through a zlib.inflate php_stream
 * filter on a private temp stream (the request_body is never touched). window
 * 47 (= 15 + 32) auto-detects gzip and zlib framing, matching PHP's own
 * Content-Encoding handling. Returns a fresh emalloc buffer on success, else
 * NULL (the caller then scans the raw bytes; a benign body stays benign). */
static char *howdah_soap_inflate(const char *in, size_t in_len, size_t *out_len, int *trunc) {
    php_stream *tmp;
    php_stream_filter *filter;
    zval params;
    char *acc;
    size_t total = 0;

    tmp = php_stream_temp_new();
    if (!tmp) {
        return NULL;
    }
    php_stream_write(tmp, in, in_len);
    php_stream_rewind(tmp);

    array_init(&params);
    add_assoc_long(&params, "window", 47);
    filter = php_stream_filter_create("zlib.inflate", &params, 0);
    zval_ptr_dtor(&params);
    if (!filter) {
        php_stream_close(tmp);
        return NULL;
    }
    php_stream_filter_append(&tmp->readfilters, filter);

    acc = howdah_soap_read_all(tmp, &total, trunc);
    php_stream_close(tmp); /* also releases the appended filter */
    if (total == 0) {
        efree(acc);
        return NULL;
    }
    *out_len = total;
    return acc;
}
#endif

/* Acquire the no-argument request body: the bytes SoapServer::handle() reads
 * from "php://input" (backed by SG(request_info).request_body). Opening the
 * php://input wrapper populates and rewinds that buffer, and closing it leaves
 * it intact, so SOAP re-reads the same body afterwards — the repeatable
 * file_get_contents("php://input") pattern (php://input is re-readable since
 * 5.6, Howdah's SOAP floor). Reading request_body directly instead would miss a
 * body not yet buffered, since php://input is populated lazily on first open.
 *
 * *owned is always 1 on success (the caller efrees). Returns NULL (fail-open:
 * chain unguarded) when no body is reachable. */
static char *howdah_soap_read_body(size_t *out_len, int *trunc, int *owned) {
    php_stream *s;
    size_t raw_len = 0;
    char *raw;
    *owned = 0;
    *out_len = 0;
    *trunc = 0;
    s = php_stream_open_wrapper("php://input", "rb", 0, NULL);
    if (!s) {
        return NULL;
    }
    raw = howdah_soap_read_all(s, &raw_len, trunc);
    php_stream_close(s); /* request_body stays intact for SOAP's own open */
    *owned = 1;
#if PHP_VERSION_ID >= 70000
    if (howdah_soap_looks_compressed(raw, raw_len)) {
        size_t inf_len = 0;
        int inf_trunc = 0;
        char *inf = howdah_soap_inflate(raw, raw_len, &inf_len, &inf_trunc);
        if (inf) {
            efree(raw);
            raw = inf;
            raw_len = inf_len;
            if (inf_trunc) {
                *trunc = 1;
            }
        }
    }
#endif
    *out_len = raw_len;
    return raw;
}

static void howdah_hook_soap_handle(INTERNAL_FUNCTION_PARAMETERS) {
    zval *req = NULL;
    char *buf = NULL;
    size_t len = 0;
    int truncated = 0;
    int owned = 0;
    int act;

    if (!g_soap_decide || !howdah_orig_soap_handle) {
        if (howdah_orig_soap_handle) {
            howdah_orig_soap_handle(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        }
        return;
    }

    /* An explicit $request string argument: SOAP parses it directly. */
    HOWDAH_ARG(1, req);
    if (req && Z_TYPE_P(req) == IS_STRING) {
        len = Z_STRLEN_P(req);
        if (len > HOWDAH_SOAP_SCAN_CAP) {
            len = HOWDAH_SOAP_SCAN_CAP;
            truncated = 1;
        }
        act = g_soap_decide(Z_STRVAL_P(req), len, truncated);
        if (act == HOWDAH_ACTION_BLOCK) {
            return; /* clean 403 already delivered; do not call SOAP */
        }
        howdah_orig_soap_handle(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    /* No argument: read the request body (what handle() reads from php://input). */
    buf = howdah_soap_read_body(&len, &truncated, &owned);
    if (!buf) {
        howdah_orig_soap_handle(INTERNAL_FUNCTION_PARAM_PASSTHRU); /* fail-open */
        return;
    }
    act = g_soap_decide(buf, len, truncated);
    if (owned) {
        efree(buf);
    }
    if (act == HOWDAH_ACTION_BLOCK) {
        return; /* clean 403 already delivered; do not call SOAP */
    }
    howdah_orig_soap_handle(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* Swap SoapServer::handle's internal handler for our trampoline. Only when the
 * class exists, the method is an internal function, and the handler is still
 * PHP's own (not already ours / another ext). Returns 1 if ours is installed. */
#if PHP_VERSION_ID >= 70000
static int howdah_soap_swap(void) {
    zend_class_entry *ce = (zend_class_entry *)zend_hash_str_find_ptr(CG(class_table), "soapserver", 10);
    zend_function *f;
    if (!ce) {
        return 0;
    }
    if (howdah_orig_soap_handle) {
        return 1;
    }
    f = (zend_function *)zend_hash_str_find_ptr(&ce->function_table, "handle", 6);
    if (!f || f->type != ZEND_INTERNAL_FUNCTION) {
        return 0;
    }
    if (f->internal_function.handler == howdah_hook_soap_handle) {
        return 1;
    }
    howdah_orig_soap_handle = f->internal_function.handler;
    f->internal_function.handler = howdah_hook_soap_handle;
    return 1;
}
#else
static int howdah_soap_swap(void) {
    zend_class_entry **pce = NULL;
    zend_function *f = NULL;
    if (zend_hash_find(CG(class_table), "soapserver", sizeof("soapserver"), (void **)&pce) != SUCCESS
        || !pce || !*pce) {
        return 0;
    }
    if (howdah_orig_soap_handle) {
        return 1;
    }
    if (zend_hash_find(&(*pce)->function_table, "handle", sizeof("handle"), (void **)&f) != SUCCESS
        || !f || f->type != ZEND_INTERNAL_FUNCTION) {
        return 0;
    }
    if (f->internal_function.handler == howdah_hook_soap_handle) {
        return 1;
    }
    howdah_orig_soap_handle = f->internal_function.handler;
    f->internal_function.handler = howdah_hook_soap_handle;
    return 1;
}
#endif

/* Install the SoapServer::handle swap. Call once at first RINIT when the SOAP
 * guard is armed. Returns 1 if swapped (or already ours), 0 if the soapserver
 * class is absent (honest no-op: ext/soap not loaded, or PHP < 5.6). */
int howdah_install_soap_hook(howdah_soap_decide_t cb) {
    g_soap_decide = cb;
    return howdah_soap_swap();
}
