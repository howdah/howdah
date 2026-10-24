<?php
// Probe used by lab/bench/server.sh before every measured cell. It proves which
// configuration the running SAPI really has, so a cell can never be
// mislabelled:
//  - the JSON answer says whether Howdah is loaded, OPcache is on and the JIT
//    is on;
//  - with ?check=1 it also touches one Layer 3 sink that is allowlisted in no
//    benchmark config (exec of `true` with an argument) and one phar:// path,
//    and the request carries a SQL-injection-shaped query value. server.sh
//    then reads the Howdah event log and checks that exactly the layers the
//    config enables logged something.
$checked = false;
if (isset($_GET['check'])) {
    $out = array();
    exec('true --howdah-bench-check', $out);
    @file_exists('phar:///tmp/howdah-bench-none.phar/x');
    $checked = true;
}
$s = function_exists('opcache_get_status') ? @opcache_get_status(false) : false;
$jit = null;
if (is_array($s) && isset($s['jit']) && is_array($s['jit']) && isset($s['jit']['on'])) {
    $jit = (bool) $s['jit']['on'];
}
echo json_encode(array(
    'php' => PHP_VERSION,
    'sapi' => PHP_SAPI,
    'howdah' => extension_loaded('howdah'),
    'opcache' => is_array($s) && !empty($s['opcache_enabled']),
    'jit' => $jit,
    'checked' => $checked,
)), "\n";
