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

#define HOWDAH_ACTION_BLOCK      2

#endif
