// The config editor's schema table: every knob the page offers, with its
// type, default and the note shown next to it. The form, the TOML emitter
// (editor.js) and the reference text are all generated from this one table,
// so adding a config section is a table entry, not new UI code.
//
// Defaults here must equal the core's (test/schema.test.mjs checks them
// against the wasm validator and docs/config.md). Notes are taken from
// docs/config.md; nothing here may claim more than that file does.
//
// Exposed as window.HowdahConfigSchema and as CommonJS exports.
(function (root) {
  'use strict';

  var MODES = ['detect', 'block', 'off'];
  var MODE_OR_INHERIT = ['inherit', 'block', 'detect', 'off'];

  // php.ini directives. Read once per PHP process at startup; once
  // howdah.config names a readable file, that file's `mode` wins.
  // `suggested: true` marks a value that is a suggestion, not the extension's
  // registered default (both path directives default to empty).
  var INI = [
    { key: 'howdah.mode', type: 'enum', values: MODES, default: 'detect',
      note: 'block refuses offending requests, detect logs only, off disables everything. The shipped default is detect. Critical limits block even in detect. Once howdah.config names a readable file, the file’s mode is used and this value is ignored.' },
    { key: 'howdah.log', type: 'path', default: '/var/log/howdah/events.log', suggested: true,
      note: 'Where JSON event lines are written. The directory must exist and be writable by the PHP worker (a subdirectory of /var/log, not /var/log itself). It wins over [log] path in the TOML file. Empty, with no [log] table, means stderr, which php-fpm discards unless catch_workers_output = yes. Syslog and a per-event hook are set in a [log] table, which this page does not edit yet.' },
    { key: 'howdah.config', type: 'path', default: '/etc/howdah/howdah.toml', suggested: true,
      note: 'Path of the TOML file below. If the file is missing or cannot be read, Howdah uses howdah.mode and the built-in limits. If the file is present but malformed, Howdah falls back to its safe defaults (block mode, default limits) and keeps serving, and phpinfo still names the file: validate before deploying.' }
  ];

  var LIMITS = [
    { key: 'max_parts', group: 'multipart', type: 'int', min: 1, default: 2000,
      note: 'Parts in one multipart body. 2× stock PHP max_input_vars (1000); a memory-exhausting flood needs tens of thousands of parts.' },
    { key: 'max_files', group: 'multipart', type: 'int', min: 1, default: 200,
      note: 'File parts in one body. No legitimate form uploads hundreds of files at once.' },
    { key: 'max_part_headers', group: 'multipart', type: 'int', min: 1, default: 16,
      note: 'Header lines in any one part. Browsers send 1–3; best-effort lower bound (only Content-Disposition reaches the callback).' },
    { key: 'max_part_header_bytes', group: 'multipart', type: 'int', min: 1, default: 8192,
      note: 'Bytes (name + value) of any one part header; 8 KiB tolerates long UTF-8 filenames. Best-effort lower bound.' },
    { key: 'max_field_name_bytes', group: 'multipart', type: 'int', min: 1, default: 1024,
      note: 'Bytes of a form-field name. Field names are identifiers or array keys; 1 KiB is very generous.' },
    { key: 'max_filename_bytes', group: 'multipart', type: 'int', min: 1, default: 512,
      note: 'Bytes of an uploaded filename. Filesystems cap names near 255 bytes; 512 allows percent-encoded forms.' },
    { key: 'max_parse_memory_bytes', group: 'multipart', type: 'int', min: 1, default: 268435456,
      note: 'Total body bytes Howdah will process for one request (256 MiB). Keep it above your PHP post_max_size.' },
    { key: 'max_input_vars', group: 'input', type: 'int', min: 1, default: 2000,
      note: 'GET + POST + cookie variables in one request. 2× stock PHP max_input_vars: a real 1500-field form passes; a variable flood is dropped and logged.' },
    { key: 'max_input_nesting_depth', group: 'input', type: 'int', min: 1, default: 64,
      note: 'Array nesting of one name (a[b][c] = 2). Real forms nest a handful of levels.' },
    { key: 'max_input_key_bytes', group: 'input', type: 'int', min: 1, default: 1024,
      note: 'Bytes of any single variable name or array key. Standard severity: logs in detect, blocks in block.' },
    { key: 'max_request_headers', group: 'headers', type: 'int', min: 1, default: 200,
      note: 'Request headers in one request. Browsers send 10–30 and proxies add a few. Counting needs $_SERVER to be read (auto_globals_jit).' },
    { key: 'max_request_header_bytes', group: 'headers', type: 'int', min: 1, default: 16384,
      note: 'Bytes (name + value) of any one request header; 16 KiB tolerates large cookies and auth tokens.' }
  ];

  // Which layer each rule name belongs to (grouping in the [rules] section).
  var RULE_LAYER = {
    max_parts: 'multipart', max_files: 'multipart', max_part_headers: 'multipart',
    max_part_header_bytes: 'multipart', max_field_name_len: 'multipart', max_filename_len: 'multipart',
    parse_memory_budget: 'multipart', malformed_multipart: 'multipart', upload_progress_abuse: 'multipart',
    self_test: 'multipart',
    max_input_vars: 'input', max_input_nesting_depth: 'input', max_input_key_bytes: 'input',
    max_request_headers: 'headers', max_request_header_bytes: 'headers',
    sql_injection: 'inspect', path_traversal: 'inspect', command_injection: 'inspect',
    command_exec: 'sinks', include: 'sinks', eval: 'sinks', unserialize: 'sinks',
    phar: 'sinks', ssrf: 'sinks',
    upload_exec: 'behavior', unexpected_binary: 'behavior', unexpected_egress: 'behavior', php_write: 'behavior',
    // 1.5 legacy-era sinks: modes come from [sinks.<sink>] mode, as for the others.
    mail_injection: 'sinks', preg_eval: 'sinks', create_function: 'sinks', assert_string: 'sinks',
    dangerous_callback: 'sinks', xxe: 'sinks', tls_verify: 'sinks'
  };

  var RULE_NOTES = {
    critical: 'Critical: blocks even when the global mode is detect. Set to off to disable it entirely.',
    standard: 'Standard: logs in detect, blocks only in block mode.'
  };
  // The core accepts every rule name under [rules], but the extension reads
  // Layer 2 overrides only from [inspect.rule_modes] and sink modes only from
  // [sinks.<sink>] mode; a [rules] entry for those names has no effect.
  var NOOP_NOTE = 'Accepted by the core but has no effect: the extension does not read [rules] for this name. Use the Layer 2 per-class override ([inspect.rule_modes]), the sink’s own mode ([sinks.<sink>] mode), or the Layer 4 [behavior] mode instead.';

  // The [rules] keys are built from the core's catalog at runtime so the form
  // can never offer a rule the core rejects, or miss one it accepts.
  function rulesKeys(catalog) {
    return (catalog || []).map(function (r) {
      var layer = RULE_LAYER[r.name] || 'other';
      var noop = layer === 'inspect' || layer === 'sinks' || layer === 'behavior';
      return {
        key: r.name, type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
        severity: r.severity, layer: layer, noop: noop,
        note: noop ? NOOP_NOTE : (RULE_NOTES[r.severity] || '')
      };
    });
  }

  var INSPECT = [
    { key: 'enabled', type: 'bool', default: true, note: 'Master on/off for Layer 2 (input inspection).' },
    { key: 'mode', type: 'enum', values: MODES, default: 'detect',
      note: 'Independent of the global mode: a global block does not arm Layer 2. detect logs only (the default). block refuses the request before the script runs (see Enforcement timing in the configuration docs).' },
    { key: 'sqli', type: 'bool', default: true, note: 'Look for SQL-injection shapes.' },
    { key: 'traversal', type: 'bool', default: true, note: 'Look for path-traversal shapes.' },
    { key: 'cmdi', type: 'bool', default: true, note: 'Look for command-injection shapes.' },
    { key: 'limits.max_value_bytes', type: 'int', min: 1, default: 16384, note: 'Scan at most this many bytes of one value.' },
    { key: 'limits.max_total_bytes', type: 'int', min: 1, default: 2097152, note: 'Per-request aggregate scan budget; values past it are not scanned.' },
    { key: 'limits.max_values', type: 'int', min: 1, default: 2000, note: 'Per-request value count budget; values past it are not scanned.' },
    { key: 'rule_modes.sql_injection', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit', note: 'Per-class override of inspect.mode.' },
    { key: 'rule_modes.path_traversal', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit', note: 'Per-class override of inspect.mode.' },
    { key: 'rule_modes.command_injection', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit', note: 'Per-class override of inspect.mode.' }
  ];

  var SINKS = [
    { key: 'enabled', type: 'bool', default: true, note: 'Master on/off for Layer 3 (sink hardening).' },
    { key: 'mode', type: 'enum', values: MODES, default: 'detect',
      note: 'Independent of the global mode: a global block does not arm any sink. detect logs only (the default). Set a sink’s allowlist before arming block.' },
    { key: 'hook', type: 'enum', values: ['auto', 'opcode', 'compile'], default: 'auto',
      note: 'How include/require/eval are guarded on PHP 7.0+. auto (default): compile when only eval needs the hook, so a default install keeps OPcache JIT on; opcode when include has allow_paths or [behavior] deny_exec_dirs is set. opcode: a user opcode handler, full coverage (warm-opcache includes too) but PHP turns the JIT off while it is installed. compile: the compile-pointer swap PHP 5.x uses; JIT stays on, eval is fully covered, an include served from a warm opcache is not re-inspected. Nothing is installed when eval and include are off and deny_exec_dirs is unset.' },
    { key: 'command_exec.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'system, exec, shell_exec, passthru, popen, proc_open. Unset inherits sinks.mode. Only a string first argument is inspected (proc_open with an array command is not).' },
    { key: 'command_exec.allow', type: 'list', default: [],
      note: 'Commands that are fine, one per line. Anchored literal strings with an optional single trailing *. "/usr/bin/convert *" also allows anything appended after the space, so prefer exact commands. A bare * allows everything.' },
    { key: 'unserialize.mode', type: 'enum', values: MODES, default: 'off',
      note: 'Off by default (object unserialize is high-volume). detect logs classes not in allow_classes; block refuses them. Fill allow_classes from the detect log first.' },
    { key: 'unserialize.allow_classes', type: 'list', default: [], note: 'Class names that may be unserialized, one per line.' },
    { key: 'include.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'include/require. Active on PHP 5.x and 7.0+; on 5.x an include served from a warm opcache is not re-inspected. Inert until allow_paths is set.' },
    { key: 'include.allow_paths', type: 'list', default: [],
      note: 'Directories include/require may load from, one per line. Lexical prefixes: a symlink under an allowed directory is not resolved.' },
    { key: 'eval.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'eval. Active on PHP 5.x and 7.0+ (fully covered on both). There is no allowlist: in detect every eval() logs; in block every eval() is skipped.' },
    // 1.3: both opt-in (off); only an explicit mode here arms them.
    { key: 'phar.mode', type: 'enum', values: MODES, default: 'off',
      note: 'phar:// stream access (1.3). Off by default; a global or [sinks] block does not arm it. detect logs phar access outside allow_paths; block refuses it.' },
    { key: 'phar.allow_paths', type: 'list', default: [],
      note: 'Realpath prefixes under which .phar archives may be opened, one per line; matched component-wise up to and including the .phar segment. Empty means every phar access is a hit in detect.' },
    { key: 'ssrf.mode', type: 'enum', values: MODES, default: 'off',
      note: 'Outbound requests to hosts not in allow_hosts (1.3). Off by default; a global or [sinks] block does not arm it.' },
    { key: 'ssrf.allow_hosts', type: 'list', default: [],
      note: 'One per line: a hostname (exact, case-insensitive; no wildcards), a literal IP, or a CIDR such as 10.0.0.0/8 or fd00::/8 (full address required, so 10/8 is rejected). The core rejects wildcards and out-of-range prefixes.' },
    // 1.5 legacy-era sinks. Each mode inherits sinks.mode (detect = log only).
    { key: 'mail.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'mail(): a 5th argument carrying any sendmail option other than -f<address> / -r<address> (so -oi, -t and -O… are expected detect noise), or a 4th-argument header string with a line break not followed by a header (body injection). block refuses the call (returns false). Rule name: mail_injection. All PHP versions.' },
    { key: 'preg_eval.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'preg_replace / preg_filter with the /e modifier (the replacement is evaluated as code). PHP 5.x only; 7.0 removed the modifier, so nothing is installed on 7.0+. block returns null.' },
    { key: 'create_function.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'create_function() (PHP 5.x and 7.x; removed in 8.0, where nothing is installed). Every call is a hit, like eval. block returns false.' },
    { key: 'assert.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'assert() with a string argument, which PHP 5.x/7.x evaluate as code (needs assert.active / zend.assertions on). 8.0 stopped evaluating strings, so nothing is installed there. Rule name: assert_string. block returns false.' },
    { key: 'callback.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'A string callback naming system, exec, passthru, shell_exec, popen, proc_open, pcntl_exec, assert or create_function, passed to call_user_func(_array), array_map, array_filter, array_walk, usort/uasort/uksort, preg_replace_callback, register_shutdown_function or ob_start. Only the callback name is logged. Rule name: dangerous_callback. block returns false. Honest gap: on PHP 7.0+ a literal call_user_func(...) in the global namespace is compiled to its own opcode and is not seen (namespaced or dynamic calls are); PHP 5.x sees every form.' },
    { key: 'xml.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'An XML string passed to simplexml_load_string or DOMDocument::loadXML that declares an external entity (refused in block) or references an external DTD (the XHTML/SVG doctypes: detect only, never blocked, so an SVG sanitizer on DOMDocument::loadXML keeps working but logs xxe lines). The attempt shape; whether PHP fetches anything depends on LIBXML_NOENT / DTDLOAD. Not simplexml_load_file, DOMDocument::load, new SimpleXMLElement, XMLReader or ext/xml. Rule name: xxe.' },
    { key: 'xml.external_entities', type: 'enum', values: ['allow', 'deny'], default: 'allow',
      note: 'deny turns libxml’s external entity loader off for every request (ext/libxml’s php_libxml_disable_entity_loader, resolved at run time). Side effect on every PHP version: loading a document BY PATH through libxml (DOMDocument::load, simplexml_load_file, XMLReader::open) also fails; load the file yourself and parse the string. PHP 8 already needs LIBXML_NOENT to substitute external entities. No event is written for this toggle.' },
    { key: 'tls.mode', type: 'mode-or-inherit', values: MODE_OR_INHERIT, default: 'inherit',
      note: 'curl_setopt / curl_setopt_array turning CURLOPT_SSL_VERIFYPEER off or setting CURLOPT_SSL_VERIFYHOST to 0. Detect-only: block is logged as log and the call always proceeds. Only the option name is logged, never the URL. Rule name: tls_verify.' }
  ];

  // Top-level keys of the TOML file (before any [table]), besides `mode`.
  var TOP = [
    { key: 'on_invalid_config', type: 'enum', values: ['block', 'off'], default: 'block',
      note: 'Mode used if this file fails to parse. Scanned from the raw file, so it must stay on a top-level line.' },
    { key: 'exceptions_log', type: 'bool', default: false,
      note: 'Write every matched [[exceptions]] entry to the event log as action "excepted" (Layers 3 and 4: one line per excepted call; Layers 1 and 2: at most one per request). Off by default so adding an exception never adds log volume by itself; turn it on while tuning or when an auditor wants to see exceptions in use.' }
  ];

  // [[exceptions]]: the keys of one entry, in the order the emitter writes
  // them. `rule` and `reason` are required and at least one facet must be set;
  // the core enforces that (and which facets a layer accepts), this table only
  // names the columns.
  var EXCEPTION_FIELDS = [
    { key: 'rule', required: true, placeholder: 'sinks.command_exec',
      note: 'A rule id as spelled in the log (sql_injection, command_exec, php_write), a layer (limits, inspect, sinks, behavior) or layer.rule. Critical Layer 1 rules are refused.' },
    { key: 'script', placeholder: '/var/www/html/cron.php',
      note: 'The executing file as PHP reports it (__FILE__; symlinks resolved): absolute path or glob (* within a segment, ** across). Layers 3 and 4 only.' },
    { key: 'script_sha256', placeholder: '64 hex characters',
      note: 'SHA-256 of the executing file (sha256sum), files up to 4 MiB. Layers 3 and 4 only.' },
    { key: 'param', placeholder: 'content',
      note: 'Request variable name, exact, as submitted (jform[articletext]). Layer 2 only.' },
    { key: 'param_prefix', placeholder: 'jform[',
      note: 'Request variable name prefix. Layer 2 only; not together with param.' },
    { key: 'uri_prefix', placeholder: '/wp-admin/',
      note: 'Request path prefix (query string removed), raw bytes, must start with / and be more than "/". A request path with a . or .. segment, //, \\ or % never matches.' },
    { key: 'client_cidr', placeholder: '10.0.0.0/8',
      note: 'REMOTE_ADDR as the SAPI reports it: an IPv4/IPv6 CIDR or a bare address.' },
    { key: 'reason', required: true, placeholder: 'DECISION 2026-10-24 owner: why this is legitimate',
      note: 'Required. The audit record: date, owner, why.' }
  ];

  // Shipped application profiles (profiles/*.toml in the repository, served
  // at /profiles/<id>.toml). Starting points, loaded through the same path as
  // "Load existing", never applied on their own.
  var PROFILES = [
    { id: 'wordpress', title: 'WordPress' },
    { id: 'drupal7', title: 'Drupal 7' },
    { id: 'magento1', title: 'Magento 1 / OpenMage' },
    { id: 'magento2', title: 'Magento 2' },
    { id: 'joomla', title: 'Joomla 3 / 4' },
    { id: 'prestashop16', title: 'PrestaShop 1.6' }
  ];

  var SCHEMA = {
    ini: INI,
    top: TOP,
    exceptionFields: EXCEPTION_FIELDS,
    profiles: PROFILES,
    sections: [
      { id: 'limits', title: 'Limits', keys: LIMITS,
        groups: { multipart: 'Multipart body', input: 'Input shape', headers: 'Request headers' } },
      { id: 'rules', title: 'Per-rule mode', keys: [], rulesKeys: rulesKeys,
        groups: { multipart: 'Multipart', input: 'Input shape', headers: 'Request headers', inspect: 'Layer 2 names (no effect here)', sinks: 'Layer 3 names (no effect here)', behavior: 'Layer 4 names (no effect here)', other: 'Other' } },
      { id: 'inspect', title: 'Layer 2: input inspection', keys: INSPECT },
      { id: 'sinks', title: 'Layer 3: sink hardening', keys: SINKS, php7Only: ['include'] }
    ],
    presets: {
      defaults: { 'howdah.mode': 'detect' },
      enforcing: { 'howdah.mode': 'block' }
    }
  };

  // Bind the [rules] keys to the core's catalog (idempotent).
  function withCatalog(catalog) {
    SCHEMA.sections[1].keys = rulesKeys(catalog);
    return SCHEMA;
  }

  // Flat state: { 'howdah.mode': 'detect', 'limits.max_parts': 2000,
  // 'rules.max_parts': 'inherit', 'sinks.command_exec.allow': [], ... }
  function defaultState(catalog) {
    withCatalog(catalog);
    var state = {};
    INI.forEach(function (i) { state[i.key] = i.default; });
    TOP.forEach(function (t) { state[t.key] = t.default; });
    SCHEMA.sections.forEach(function (s) {
      s.keys.forEach(function (k) {
        state[s.id + '.' + k.key] = Array.isArray(k.default) ? k.default.slice() : k.default;
      });
    });
    // [[exceptions]]: an array of plain {rule, script, ..., reason} objects,
    // not a flat key; the emitter writes them after every table.
    state.exceptions = [];
    return state;
  }

  var api = {
    SCHEMA: SCHEMA, defaultState: defaultState, withCatalog: withCatalog, RULE_LAYER: RULE_LAYER, MODES: MODES,
    EXCEPTION_FIELDS: EXCEPTION_FIELDS, PROFILES: PROFILES
  };
  root.HowdahConfigSchema = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
