<?php
// Checks event lines against the schema-2 contract (docs/log-schema.md).
// Usage: php -n log_check.php <file> [syslog]
//   <file>   one event per line; with "syslog", each line is an RFC 3164
//            frame "<PRI>Mmm dd hh:mm:ss IDENT[PID]: {json}" and the frame is
//            checked too (IDENT and facility from $HOWDAH_IDENT/$HOWDAH_FAC).
// Prints "rule layer action" per event; exits 1 on the first violation.
// Runs with -n (no php.ini), so Howdah is never loaded into the checker.

$want = array('schema', 'version', 'ts', 'request_id', 'layer', 'rule', 'action',
              'client_ip', 'method', 'uri', 'reason');
sort($want);
$layer = array(
    'max_parts' => 1, 'max_files' => 1, 'max_part_headers' => 1, 'max_part_header_bytes' => 1,
    'max_field_name_len' => 1, 'max_filename_len' => 1, 'parse_memory_budget' => 1,
    'malformed_multipart' => 1, 'upload_progress_abuse' => 1, 'self_test' => 1,
    'max_input_vars' => 1, 'max_input_nesting_depth' => 1, 'max_input_key_bytes' => 1,
    'max_request_headers' => 1, 'max_request_header_bytes' => 1,
    'sql_injection' => 2, 'path_traversal' => 2, 'command_injection' => 2, 'cgi_arg_injection' => 2,
    'command_exec' => 3, 'include' => 3, 'eval' => 3, 'unserialize' => 3, 'phar' => 3, 'ssrf' => 3,
);
$sev = array('block' => 4, 'log' => 5, 'allow' => 6);

function bad($msg, $line) {
    fwrite(STDERR, "log_check: $msg\n  line: $line\n");
    exit(1);
}

$file = $argv[1];
$syslog = isset($argv[2]) && $argv[2] === 'syslog';
$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
if (!$lines) bad("no events in $file", '');

foreach ($lines as $line) {
    $json = $line;
    if ($syslog) {
        $ident = getenv('HOWDAH_IDENT');
        $fac = (int) getenv('HOWDAH_FAC');
        if (!preg_match('/^<(\d+)>([A-Z][a-z]{2} [ 0-9]\d \d\d:\d\d:\d\d) ([^\[ :]+)\[(\d+)\]: (\{.*\})$/', $line, $m)) {
            bad('not an RFC 3164 frame', $line);
        }
        if ($m[3] !== $ident) bad("ident {$m[3]} != $ident", $line);
        $json = $m[5];
        $pri = (int) $m[1];
    }
    $e = json_decode($json, true);
    if (!is_array($e)) bad('not JSON', $line);
    $keys = array_keys($e);
    sort($keys);
    if ($keys !== $want) bad('keys ' . implode(',', $keys), $line);
    if ($e['schema'] !== 2) bad('schema is not the integer 2', $line);
    if (!is_int($e['layer'])) bad('layer is not an integer', $line);
    if (!isset($layer[$e['rule']])) bad("unknown rule {$e['rule']}", $line);
    if ($e['layer'] !== $layer[$e['rule']]) bad("layer {$e['layer']} for {$e['rule']}", $line);
    if (!preg_match('/^[0-9]{13,}$/', $e['ts'])) bad('ts is not epoch-ms digits', $line);
    if (!preg_match('/^[0-9a-f]+$/', $e['request_id'])) bad('request_id', $line);
    if (!preg_match('/^[0-9]+\.[0-9]+\.[0-9]+/', $e['version'])) bad('version', $line);
    foreach (array('ts', 'request_id', 'rule', 'action', 'client_ip', 'method', 'uri', 'reason') as $k) {
        if (!is_string($e[$k])) bad("$k is not a string", $line);
    }
    if (strpos($e['uri'], '?') !== false) bad('uri carries a query string', $line);
    if ($syslog && $pri !== $fac * 8 + $sev[$e['action']]) bad("PRI $pri for facility $fac / {$e['action']}", $line);
    echo $e['rule'], ' ', $e['layer'], ' ', $e['action'], "\n";
}
