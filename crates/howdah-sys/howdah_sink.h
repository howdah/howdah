/* Shared sink ids / action codes for the PHP-extension C shims.
 * Hand-written. Values MUST mirror howdah-core/src/ffi.rs. */
#ifndef HOWDAH_SINK_H
#define HOWDAH_SINK_H

#define HOWDAH_SINK_COMMAND_EXEC 0
#define HOWDAH_SINK_INCLUDE      1
#define HOWDAH_SINK_EVAL         2
#define HOWDAH_SINK_UNSERIALIZE  3
#define HOWDAH_SINK_PHAR         4
#define HOWDAH_SINK_SSRF         5
/* Legacy-era sinks (1.5; see legacy_hook.c). */
#define HOWDAH_SINK_MAIL            6
#define HOWDAH_SINK_PREG_EVAL       7
#define HOWDAH_SINK_CREATE_FUNCTION 8
#define HOWDAH_SINK_ASSERT          9
#define HOWDAH_SINK_CALLBACK        10
#define HOWDAH_SINK_XML             11
#define HOWDAH_SINK_TLS             12

#define HOWDAH_ACTION_BLOCK      2
/* howdah_sink_check_xml only: neutralize by rewriting the options argument
 * (clear HOWDAH_XML_DANGEROUS_FLAGS) and running the original call. Mirrors
 * HOWDAH_STRIP in howdah-core/src/ffi.rs. */
#define HOWDAH_ACTION_STRIP      3

/* howdah_sink_check_xml capability bits and the LIBXML_* flags it strips (see
 * HOWDAH_XML_* in howdah-core/src/ffi.rs): NOENT 2 | DTDLOAD 4 | DTDATTR 8 |
 * DTDVALID 16. */
#define HOWDAH_XML_CAN_STRIP            1
#define HOWDAH_XML_ENGINE_IGNORES_FLAGS 2
#define HOWDAH_XML_DANGEROUS_FLAGS      30

/* Legacy sink install mask bits (howdah_install_legacy_hooks; mirrored as
 * HOWDAH_LEGACY_* in howdah-sys/src/lib.rs). */
#define HOWDAH_LEGACY_MAIL            1
#define HOWDAH_LEGACY_PREG_EVAL       2
#define HOWDAH_LEGACY_CREATE_FUNCTION 4
#define HOWDAH_LEGACY_ASSERT          8
#define HOWDAH_LEGACY_CALLBACK        16
#define HOWDAH_LEGACY_XML             32
#define HOWDAH_LEGACY_TLS             64

/* File-op classes for the file-op hub (howdah_sink_check_open_at): the T4 file-open
 * firewall plus the T5 delete / secret-read guards. Values MUST mirror
 * HOWDAH_FILE_OP_* in howdah-core/src/ffi.rs.
 *   READ     fopen (read mode) / file_get_contents / readfile / file
 *   WRITE    fopen (write mode)
 *   DELETE   unlink / rmdir                      (T5 delete guard)
 *   MOVE_SRC the SOURCE operand of rename        (T5 delete guard) */
#define HOWDAH_FILE_OP_READ     0
#define HOWDAH_FILE_OP_WRITE    1
#define HOWDAH_FILE_OP_DELETE   2
#define HOWDAH_FILE_OP_MOVE_SRC 3

/* `is_write_mode` codes for the Layer-4 php-write callback (howdah_behavior_php_
 * write_t). Mirror HOWDAH_WRITE_* in howdah-core/src/ffi.rs. UPLOAD is
 * move_uploaded_file (the always-on upload tier); PLAIN is every other write
 * sink (file_put_contents, write-mode fopen, rename, copy). */
#define HOWDAH_WRITE_READ   0
#define HOWDAH_WRITE_PLAIN  1
#define HOWDAH_WRITE_UPLOAD 2

/* howdah_install_file_hooks `ops` mask: which file-op sinks BESIDES the always-
 * swapped read sinks (readfile, file) to swap. Mirrored in howdah-sys/src/lib.rs. */
#define HOWDAH_FILE_HOOK_DELETE 1 /* unlink, rmdir (the delete guard is armed) */

/* ---- T4 file-open firewall glue (file_hook.c) ---------------------------
 * The decision callback the file-op trampolines invoke per intercepted call:
 * `name` is the guarded function, `target` its path/URL argument (scanned,
 * never logged), `op` a HOWDAH_FILE_OP_* code. Returns the action (0 ALLOW /
 * 1 LOG / 2 BLOCK). Mirrors the `howdah_sink_check_open_at` FFI. */
typedef int (*howdah_file_decide_t)(const char *name, size_t name_len,
                                    const char *target, size_t target_len, int op);

/* Install the file-op hub: set the shared decide callback and swap the sinks
 * file_hook.c owns: the read sinks (readfile, file) always, and per `ops`
 * (HOWDAH_FILE_HOOK_*) the delete sinks unlink / rmdir. The fopen /
 * file_get_contents trampolines live in ssrf_hook.c (already swapped there) and
 * call howdah_file_firewall_check directly; so does rename's SOURCE check. Call
 * once at first RINIT when the hub is armed. A NULL callback leaves the hub
 * disarmed (fail-open). */
void howdah_install_file_hooks(howdah_file_decide_t decide, int ops);

/* Shared file-open firewall check, exported for ssrf_hook.c's fopen /
 * file_get_contents trampolines (which are swapped there for SSRF/php-write).
 * Returns 1 iff the call must be neutralized (BLOCK). Fail-open (0) when the
 * firewall is disarmed (callback NULL) or `target` is NULL. Defined in
 * file_hook.c. */
int howdah_file_firewall_check(const char *name, size_t name_len,
                               const char *target, size_t target_len, int op);

/* Layer-4 behavior facets. Values MUST mirror HOWDAH_BEHAVIOR_* in
 * howdah-core/src/ffi.rs (and howdah_core.h). */
#define HOWDAH_BEHAVIOR_EXEC_DIR  0
#define HOWDAH_BEHAVIOR_BINARY    1
#define HOWDAH_BEHAVIOR_EGRESS    2
#define HOWDAH_BEHAVIOR_PHP_WRITE 3
#define HOWDAH_BEHAVIOR_UPLOAD_WRITE 4
#define HOWDAH_BEHAVIOR_DELETE       5
#define HOWDAH_BEHAVIOR_SECRET_READ  6

/* ---- Layer-4 behavior glue callbacks ------------------------------------
 * Set by howdah_install_behavior_hooks(); reachable from both sink_hook.c and
 * ssrf_hook.c. Defined once in sink_hook.c, extern-declared here. Each mirrors
 * the matching howdah_behavior_check_* FFI (see howdah_core.h) and returns the
 * action code (0 ALLOW / 1 LOG / 2 BLOCK). `ctx` is always NULL (the ext glue
 * uses its own thread-local CTX and also writes the log line). A NULL callback
 * leaves the chain unguarded (fail-open). */
typedef int (*howdah_behavior_armed_t)(void *ctx, int facet);
typedef int (*howdah_behavior_exec_dir_t)(void *ctx, const char *path, size_t path_len);
typedef int (*howdah_behavior_binary_t)(void *ctx, const char *caller, size_t caller_len,
                                        const char *prog, size_t prog_len);
typedef int (*howdah_behavior_egress_t)(void *ctx, const char *caller, size_t caller_len,
                                        const char *host, size_t host_len);
typedef int (*howdah_behavior_php_write_t)(void *ctx, const char *caller, size_t caller_len,
                                           const char *target, size_t target_len,
                                           int is_write_mode);

extern howdah_behavior_armed_t     howdah_g_behavior_armed;
extern howdah_behavior_exec_dir_t  howdah_g_behavior_exec_dir;
extern howdah_behavior_binary_t    howdah_g_behavior_binary;
extern howdah_behavior_egress_t    howdah_g_behavior_egress;
extern howdah_behavior_php_write_t howdah_g_behavior_php_write;

/* howdah_install_behavior_hooks `swap` mask: which write/rename sinks to swap.
 * Mirrored in howdah-sys/src/lib.rs. Purely a perf gate (the Rust side
 * re-checks the config on every call): a sink no armed facet needs is left
 * alone, so a default install pays nothing on file_put_contents / copy.
 *   GENERIC  the scoped deny_php_writes tier is armed: file_put_contents, copy,
 *            rename's target, fopen's write branch and move_uploaded_file all
 *            consult the php-write callback (PLAIN / UPLOAD).
 *   UPLOAD   the upload-write guard is armed: move_uploaded_file only.
 *   RENAME_SRC the delete guard is armed: rename's SOURCE goes to the file-op
 *            hub (needs howdah_install_file_hooks for the callback). */
#define HOWDAH_BHV_SWAP_GENERIC    1
#define HOWDAH_BHV_SWAP_UPLOAD     2
#define HOWDAH_BHV_SWAP_RENAME_SRC 4

/* Set the five behavior callbacks AND swap the write/rename sinks selected by
 * `swap` (HOWDAH_BHV_SWAP_*) onto their php-write trampolines: file_put_contents
 * / copy (GENERIC), move_uploaded_file (GENERIC or UPLOAD), rename (GENERIC or
 * RENAME_SRC). fopen is already swapped by the SSRF install, so its php-write
 * branch goes live as soon as the callbacks are set and GENERIC is requested.
 * Call once at first RINIT, after howdah_install_ssrf_hooks (same first-RINIT
 * install as the phar/ssrf hooks, for shared-extension load order). Implemented
 * in ssrf_hook.c. A NULL callback leaves that facet unguarded (fail-open). */
void howdah_install_behavior_hooks(howdah_behavior_armed_t armed,
                                   howdah_behavior_exec_dir_t exec_dir,
                                   howdah_behavior_binary_t binary,
                                   howdah_behavior_egress_t egress,
                                   howdah_behavior_php_write_t php_write,
                                   int swap);

#endif
