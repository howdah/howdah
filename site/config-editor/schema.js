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
    upload_exec: 'behavior', unexpected_binary: 'behavior', unexpected_egress: 'behavior', php_write: 'behavior'
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
      note: 'Independent of the global mode: a global block does not arm Layer 2. detect logs only (the default). block is enforced after the script has run (see Enforcement timing in the configuration docs).' },
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
      note: 'One per line: a hostname (exact, case-insensitive; no wildcards), a literal IP, or a CIDR such as 10.0.0.0/8 or fd00::/8 (full address required, so 10/8 is rejected). The core rejects wildcards and out-of-range prefixes.' }
  ];

  // Top-level keys of the TOML file (before any [table]), besides `mode`.
  var TOP = [
    { key: 'on_invalid_config', type: 'enum', values: ['block', 'off'], default: 'block',
      note: 'Mode used if this file fails to parse. Scanned from the raw file, so it must stay on a top-level line.' }
  ];

  var SCHEMA = {
    ini: INI,
    top: TOP,
    sections: [
      { id: 'limits', title: 'Limits', keys: LIMITS,
        groups: { multipart: 'Multipart body', input: 'Input shape', headers: 'Request headers' } },
      { id: 'rules', title: 'Per-rule mode', keys: [], rulesKeys: rulesKeys,
        groups: { multipart: 'Multipart', input: 'Input shape', headers: 'Request headers', inspect: 'Layer 2 names (no effect here)', sinks: 'Layer 3 names (no effect here)', other: 'Other' } },
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
    return state;
  }

  var api = { SCHEMA: SCHEMA, defaultState: defaultState, withCatalog: withCatalog, RULE_LAYER: RULE_LAYER, MODES: MODES };
  root.HowdahConfigSchema = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
