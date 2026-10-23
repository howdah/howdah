/*
 * input_probe.c — throwaway spike extension for the Howdah 1.0 Layer-1
 * input-hook spike.
 *
 * NOT part of the shipped Howdah extension. Benign hook probe, no attack
 * payload. It proves, on real PHP across versions, that:
 *   (a) sapi_module.input_filter can be chained (save prior, install ours,
 *       always call the prior and return ITS verdict) and then sees every
 *       GET/POST/COOKIE request variable, urlencoded and multipart;
 *   (b) SG(request_info).query_string and sapi_module.name are readable.
 *
 * Counters are exposed through PHP functions so a driver can read them back.
 *
 * Reset policy: counters are cleared in RSHUTDOWN, NOT RINIT. input_filter
 * can fire (POST during sapi_activate, GET/COOKIE during
 * php_hash_environment) BEFORE RINIT runs, so an RINIT reset would erase
 * the very counts being measured. input_probe_rinit_seen() records the
 * count observed at RINIT time to document that ordering.
 *
 * Build: phpize && ./configure --enable-input-probe && make
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "SAPI.h"

#if PHP_VERSION_ID < 70000
#define IP_TSRMLS_DC TSRMLS_DC
#define IP_TSRMLS_CC TSRMLS_CC
#else
#define IP_TSRMLS_DC
#define IP_TSRMLS_CC
#endif

#if PHP_VERSION_ID < 70000
typedef long ip_long_t;
typedef unsigned int ip_len_t;   /* val_len / *new_val_len */
#else
typedef zend_long ip_long_t;
typedef size_t ip_len_t;
#endif

/* `var` became `const char *` in PHP 8.1 (verified: 7.4 = char *, 8.1 = const
 * char *; 8.0 not measured, gated at 8.1 per the upstream change). */
#if PHP_VERSION_ID >= 80100
typedef const char *ip_var_t;
#else
typedef char *ip_var_t;
#endif

/* sapi_module_struct.input_filter:
 *   < 7.0 : unsigned int (*)(int arg, char *var, char **val, unsigned int val_len, unsigned int *new_val_len TSRMLS_DC)
 *   >= 7.0: unsigned int (*)(int arg, char *var, char **val, size_t val_len, size_t *new_val_len)
 * (return type stays unsigned int through 8.x) */
static unsigned int (*ip_orig_filter)(int arg, ip_var_t var, char **val, ip_len_t val_len, ip_len_t *new_val_len IP_TSRMLS_DC) = NULL;

static unsigned long ip_count = 0;
static unsigned long ip_by_arg[3] = {0, 0, 0}; /* PARSE_POST=0, GET=1, COOKIE=2 */
static int           ip_last_arg = -1;
static long          ip_last_name_len = -1;
static unsigned long ip_rinit_seen = 0;
static int           ip_chain_called = 0;

static unsigned int ip_input_filter(int arg, ip_var_t var, char **val, ip_len_t val_len, ip_len_t *new_val_len IP_TSRMLS_DC)
{
	ip_count++;
	if (arg >= 0 && arg <= 2) {
		ip_by_arg[arg]++;
	}
	ip_last_arg = arg;
	ip_last_name_len = var ? (long) strlen(var) : -1;

	if (ip_orig_filter) {
		ip_chain_called = 1;
		return ip_orig_filter(arg, var, val, val_len, new_val_len IP_TSRMLS_CC);
	}
	/* No prior filter: behave as "accept unchanged". */
	if (new_val_len) {
		*new_val_len = val_len;
	}
	return 1;
}

PHP_FUNCTION(input_probe_count)         { RETURN_LONG((ip_long_t) ip_count); }
PHP_FUNCTION(input_probe_last_arg)      { RETURN_LONG((ip_long_t) ip_last_arg); }
PHP_FUNCTION(input_probe_last_name_len) { RETURN_LONG((ip_long_t) ip_last_name_len); }
PHP_FUNCTION(input_probe_rinit_seen)    { RETURN_LONG((ip_long_t) ip_rinit_seen); }
PHP_FUNCTION(input_probe_chain_called)  { RETURN_BOOL(ip_chain_called); }

PHP_FUNCTION(input_probe_by_arg)
{
	/* "post,get,cookie" */
	char buf[96];
	int n = snprintf(buf, sizeof(buf), "%lu,%lu,%lu", ip_by_arg[0], ip_by_arg[1], ip_by_arg[2]);
#if PHP_VERSION_ID < 70000
	RETURN_STRINGL(buf, n, 1);
#else
	RETURN_STRINGL(buf, n);
#endif
}

PHP_FUNCTION(input_probe_query_string)
{
	const char *q = SG(request_info).query_string;
	if (!q) {
		RETURN_NULL();
	}
#if PHP_VERSION_ID < 70000
	RETURN_STRING((char *) q, 1);
#else
	RETURN_STRING(q);
#endif
}

PHP_FUNCTION(input_probe_sapi_name)
{
	const char *n = sapi_module.name;
	if (!n) {
		RETURN_NULL();
	}
#if PHP_VERSION_ID < 70000
	RETURN_STRING((char *) n, 1);
#else
	RETURN_STRING(n);
#endif
}

/* Extra raw request_info fields, to document what is reachable. */
PHP_FUNCTION(input_probe_request_info)
{
	char buf[256];
	int n = snprintf(buf, sizeof(buf), "method=%s content_length=%ld cookie=%s",
		SG(request_info).request_method ? SG(request_info).request_method : "(null)",
		(long) SG(request_info).content_length,
		SG(request_info).cookie_data ? SG(request_info).cookie_data : "(null)");
#if PHP_VERSION_ID < 70000
	RETURN_STRINGL(buf, n, 1);
#else
	RETURN_STRINGL(buf, n);
#endif
}

#if PHP_VERSION_ID >= 80000
ZEND_BEGIN_ARG_INFO_EX(ip_noargs, 0, 0, 0)
ZEND_END_ARG_INFO()
#define IP_FE(name) PHP_FE(name, ip_noargs)
#else
#define IP_FE(name) PHP_FE(name, NULL)
#endif

static const zend_function_entry input_probe_functions[] = {
	IP_FE(input_probe_count)
	IP_FE(input_probe_last_arg)
	IP_FE(input_probe_last_name_len)
	IP_FE(input_probe_rinit_seen)
	IP_FE(input_probe_chain_called)
	IP_FE(input_probe_by_arg)
	IP_FE(input_probe_query_string)
	IP_FE(input_probe_sapi_name)
	IP_FE(input_probe_request_info)
#if PHP_VERSION_ID >= 70000
	PHP_FE_END
#else
	{NULL, NULL, NULL}
#endif
};

PHP_MINIT_FUNCTION(input_probe)
{
	ip_orig_filter = sapi_module.input_filter;
	sapi_module.input_filter = ip_input_filter;
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(input_probe)
{
	sapi_module.input_filter = ip_orig_filter;
	return SUCCESS;
}

PHP_RINIT_FUNCTION(input_probe)
{
	ip_rinit_seen = ip_count; /* record, do NOT reset (see header comment) */
	return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(input_probe)
{
	ip_count = 0;
	ip_by_arg[0] = ip_by_arg[1] = ip_by_arg[2] = 0;
	ip_last_arg = -1;
	ip_last_name_len = -1;
	ip_rinit_seen = 0;
	ip_chain_called = 0;
	return SUCCESS;
}

zend_module_entry input_probe_module_entry = {
	STANDARD_MODULE_HEADER,
	"input_probe",
	input_probe_functions,
	PHP_MINIT(input_probe),
	PHP_MSHUTDOWN(input_probe),
	PHP_RINIT(input_probe),
	PHP_RSHUTDOWN(input_probe),
	NULL,
	"0.1",
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_INPUT_PROBE
ZEND_GET_MODULE(input_probe)
#endif
