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

/* Legacy sink install mask bits (howdah_install_legacy_hooks; mirrored as
 * HOWDAH_LEGACY_* in howdah-sys/src/lib.rs). */
#define HOWDAH_LEGACY_MAIL            1
#define HOWDAH_LEGACY_PREG_EVAL       2
#define HOWDAH_LEGACY_CREATE_FUNCTION 4
#define HOWDAH_LEGACY_ASSERT          8
#define HOWDAH_LEGACY_CALLBACK        16
#define HOWDAH_LEGACY_XML             32
#define HOWDAH_LEGACY_TLS             64

/* Layer-4 behavior facets. Values MUST mirror HOWDAH_BEHAVIOR_* in
 * howdah-core/src/ffi.rs (and howdah_core.h). */
#define HOWDAH_BEHAVIOR_EXEC_DIR  0
#define HOWDAH_BEHAVIOR_BINARY    1
#define HOWDAH_BEHAVIOR_EGRESS    2
#define HOWDAH_BEHAVIOR_PHP_WRITE 3

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

/* Set the five behavior callbacks AND swap file_put_contents / move_uploaded_file
 * / rename onto their php-write trampolines (fopen is already swapped by the SSRF
 * install, so its php-write branch goes live as soon as the callbacks are set).
 * Call once at first RINIT, after howdah_install_ssrf_hooks (same first-RINIT
 * install as the phar/ssrf hooks, for shared-extension load order). Implemented
 * in ssrf_hook.c. A NULL callback leaves that facet unguarded (fail-open). */
void howdah_install_behavior_hooks(howdah_behavior_armed_t armed,
                                   howdah_behavior_exec_dir_t exec_dir,
                                   howdah_behavior_binary_t binary,
                                   howdah_behavior_egress_t egress,
                                   howdah_behavior_php_write_t php_write);

#endif
