/* Single bindgen entry point. Headers are found via `php-config --includes`. */
#include "main/php.h"
#include "main/rfc1867.h"
#include "main/SAPI.h"
/* php_info_print_table_* (phpinfo / `php --ri`) live here. */
#include "ext/standard/info.h"
