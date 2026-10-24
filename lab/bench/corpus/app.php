<?php
// Target app for lab/bench/corpus.sh (GoTestWAF payloads against Layer 2).
//
// 1. It touches every superglobal, so PHP registers each request variable
//    through Howdah's chained input_filter ($_SERVER is lazily built, and the
//    URL path is only inspected once it is).
// 2. It appends one marker line to the Howdah event log *while the script
//    runs*. Howdah writes its own Layer 1/2 line for this request at request
//    shutdown, i.e. after the marker and before the next request's marker.
//    Requests are strictly sequential (one GoTestWAF worker, one php-fpm
//    child), so bench.mjs can attribute every Howdah line to its request.
//    The marker records only where the payload was placed (inferred from
//    the request shape) and whether GoTestWAF tagged it as a test request,
//    never the payload itself.
// It always answers 200: Howdah stays in detect mode and the verdict is read
// from the log, not from the status code.
$n = count($_GET) + count($_POST) + count($_COOKIE) + count($_FILES) + count($_SERVER) + count($_REQUEST);

$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';
$ct = isset($_SERVER['CONTENT_TYPE']) ? strtolower($_SERVER['CONTENT_TYPE']) : '';
$len = isset($_SERVER['CONTENT_LENGTH']) ? (int) $_SERVER['CONTENT_LENGTH'] : 0;
$uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
$qpos = strpos($uri, '?');
$path = $qpos === false ? $uri : substr($uri, 0, $qpos);
$query = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';

if ($len > 0 || $ct !== '') {
    if (strpos($ct, 'json') !== false) {
        $channel = 'JSON body';
    } elseif (strpos($ct, 'multipart/form-data') !== false) {
        $channel = 'multipart form';
    } elseif (strpos($ct, 'application/x-www-form-urlencoded') !== false) {
        $channel = 'urlencoded form';
    } elseif (strpos($ct, 'xml') !== false || strpos($ct, 'soap') !== false) {
        $channel = 'XML/SOAP body';
    } else {
        $channel = 'other body';
    }
} elseif ($query !== '') {
    $channel = 'query string';
} elseif ($path !== '/' && $path !== '') {
    $channel = 'URL path';
} else {
    $channel = 'headers';
}

$log = ini_get('howdah.log');
if ($log) {
    file_put_contents(
        $log,
        json_encode(array('bench_marker' => array(
            'channel' => $channel,
            'method' => $method,
            // GoTestWAF's --addDebugHeader marks its test requests; its own
            // start-up probes do not carry the header and are not counted.
            'test' => isset($_SERVER['HTTP_X_GOTESTWAF_TEST']),
        ))) . "\n",
        FILE_APPEND | LOCK_EX
    );
}
echo "ok $n\n";
