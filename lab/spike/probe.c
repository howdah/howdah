/*
 * probe.c — throwaway spike extension for Howdah milestone 0.
 *
 * NOT part of the shipped Howdah extension. It exists only to prove, on
 * real PHP across versions, that chaining PHP's `php_rfc1867_callback`
 * lets an extension abort an abusive multipart/form-data upload before
 * PHP allocates per-part state, by counting MULTIPART_EVENT_FILE_START
 * events and returning FAILURE once a hardcoded threshold is exceeded.
 *
 * It saves whatever callback was already installed (e.g. by the
 * session extension's upload-progress feature) and chains to it so it
 * does not break other extensions that use the same single global hook.
 *
 * Build: phpize && ./configure && make (see lab/images/*.Dockerfile).
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "main/rfc1867.h"

#ifndef PROBE_THRESHOLD
#define PROBE_THRESHOLD 50
#endif

/* TSRMLS_DC/TSRMLS_CC still exist (as no-ops) through PHP 7.x but were
 * removed entirely from the headers in PHP 8.x. Define our own
 * version-gated equivalents instead of relying on upstream presence. */
#if PHP_VERSION_ID < 70000
#define PROBE_TSRMLS_DC TSRMLS_DC
#define PROBE_TSRMLS_CC TSRMLS_CC
#else
#define PROBE_TSRMLS_DC
#define PROBE_TSRMLS_CC
#endif

/* php_rfc1867_callback's return type is `int` through PHP 7.x and
 * `zend_result` from PHP 8.0 on. SUCCESS/FAILURE (0/-1) are defined
 * for both, so only the typedef needs to track the version. */
#if PHP_VERSION_ID >= 80000
typedef zend_result probe_ret_t;
#else
typedef int probe_ret_t;
#endif

/* zend_long didn't exist before PHP 7.0 (it was plain `long`). */
#if PHP_VERSION_ID < 70000
typedef long probe_long_t;
#else
typedef zend_long probe_long_t;
#endif

static probe_ret_t (*probe_orig_callback)(unsigned int event, void *event_data, void **extra PROBE_TSRMLS_DC) = NULL;

/* Exposed via a PHP function below so measure.sh can read them back
 * without parsing extension debug output. */
static unsigned long probe_file_start_count = 0;
static unsigned int  probe_last_event = 0;
static int           probe_aborted = 0;

static probe_ret_t probe_rfc1867_callback(unsigned int event, void *event_data, void **extra PROBE_TSRMLS_DC)
{
	probe_last_event = event;

	if (event == MULTIPART_EVENT_START) {
		probe_file_start_count = 0;
		probe_aborted = 0;
	} else if (event == MULTIPART_EVENT_FILE_START) {
		probe_file_start_count++;
		if (probe_file_start_count > PROBE_THRESHOLD) {
			probe_aborted = 1;
			return FAILURE;
		}
	}

	if (probe_orig_callback) {
		return probe_orig_callback(event, event_data, extra PROBE_TSRMLS_CC);
	}
	return SUCCESS;
}

PHP_FUNCTION(probe_file_start_count)
{
	RETURN_LONG((probe_long_t) probe_file_start_count);
}

PHP_FUNCTION(probe_last_event)
{
	RETURN_LONG((probe_long_t) probe_last_event);
}

PHP_FUNCTION(probe_aborted)
{
	RETURN_BOOL(probe_aborted);
}

#if PHP_VERSION_ID >= 70000
static const zend_function_entry probe_functions[] = {
	PHP_FE(probe_file_start_count, NULL)
	PHP_FE(probe_last_event, NULL)
	PHP_FE(probe_aborted, NULL)
	PHP_FE_END
};
#else
static const zend_function_entry probe_functions[] = {
	PHP_FE(probe_file_start_count, NULL)
	PHP_FE(probe_last_event, NULL)
	PHP_FE(probe_aborted, NULL)
	{NULL, NULL, NULL}
};
#endif

PHP_MINIT_FUNCTION(probe)
{
	probe_orig_callback = php_rfc1867_callback;
	php_rfc1867_callback = probe_rfc1867_callback;
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(probe)
{
	php_rfc1867_callback = probe_orig_callback;
	return SUCCESS;
}

zend_module_entry probe_module_entry = {
	STANDARD_MODULE_HEADER,
	"probe",
	probe_functions,
	PHP_MINIT(probe),
	PHP_MSHUTDOWN(probe),
	NULL,
	NULL,
	NULL,
	"0.1",
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PROBE
ZEND_GET_MODULE(probe)
#endif
