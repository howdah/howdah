/* Tiny C shim: exposes values that bindgen cannot evaluate because they are
 * built from token-pasting macros. ZEND_MODULE_BUILD_ID is a concatenation of
 * macro-expanded string literals ("API20180731,NTS" and the like); its exact
 * value is baked into the PHP binary and MUST match, or the extension is
 * refused at load. Compiling it from the real headers is the only reliable way
 * to get it right per generation. */
#include "main/php.h"

const char *howdah_sys_build_id(void) {
    return ZEND_MODULE_BUILD_ID;
}

/* Write one line to the SAPI error log (php_log_err: the CLI's stderr, FPM's
 * error log, Apache's ErrorLog). A function in PHP 5/7 and a macro in 8; both
 * take a char *. Safe at MINIT. */
void howdah_sys_log_err(const char *msg) {
    php_log_err((char *)msg);
}
