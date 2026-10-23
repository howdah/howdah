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
