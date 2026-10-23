/* Single bindgen entry point. Headers are found via `php-config --includes`. */
#include "main/php.h"
#include "main/rfc1867.h"
#include "main/SAPI.h"
/* PARSE_GET / PARSE_POST / PARSE_COOKIE / PARSE_SERVER for the input_filter
 * chain (not pulled in transitively by php.h). */
#include "main/php_variables.h"
/* php_info_print_table_* (phpinfo / `php --ri`) live here. */
#include "ext/standard/info.h"
