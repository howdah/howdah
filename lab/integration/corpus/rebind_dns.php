<?php
// Lab-only DNS-rebinding resolver for sinks_fastfollow_container.sh (T6).
//
// Listens on 127.0.0.1:53/udp. For every name under .rebind.test the FIRST A
// query is answered with the decoy address (argv[1], default 203.0.113.7: a
// documentation-range "public" address nothing routes to) and EVERY LATER A
// query with 127.0.0.1. That is exactly the TOCTOU a rebinding attacker serves:
// the name passes a check-time lookup as public, then the connect-time lookup
// (PHP's / libcurl's own) lands on loopback. AAAA gets an empty NOERROR answer;
// any other name gets NXDOMAIN. TTL 0 so nothing caches it.
//
// No howdah in this process. Not part of the extension or the package.
$decoy = isset($argv[1]) ? $argv[1] : "203.0.113.7";
$s = stream_socket_server('udp://127.0.0.1:53', $en, $es, STREAM_SERVER_BIND);
if (!$s) { fwrite(STDERR, "bind failed: $es\n"); exit(1); }
$count = [];
while (true) {
    $pkt = stream_socket_recvfrom($s, 512, 0, $peer);
    if ($pkt === false || strlen($pkt) < 17) continue;
    $id = substr($pkt, 0, 2);
    $o = 12; $name = '';
    while ($o < strlen($pkt) && ($l = ord($pkt[$o])) > 0) { $name .= substr($pkt, $o + 1, $l) . '.'; $o += $l + 1; }
    $qend = $o + 1 + 4;
    $qtype = unpack('n', substr($pkt, $o + 1, 2))[1];
    $question = substr($pkt, 12, $qend - 12);
    $name = strtolower($name);
    $ours = substr($name, -13) === '.rebind.test.';
    $rcode = $ours ? 0 : 3;
    $ans = ''; $n = 0;
    if ($ours && $qtype === 1) {
        $count[$name] = (isset($count[$name]) ? $count[$name] : 0) + 1;
        $ip = $count[$name] === 1 ? $decoy : '127.0.0.1';
        $ans = "\xc0\x0c" . pack('nnNn', 1, 1, 0, 4) . pack('N', ip2long($ip));
        $n = 1;
        fwrite(STDERR, "dns A $name #{$count[$name]} -> $ip\n");
    }
    $resp = $id . chr(0x81) . chr(0x80 | $rcode) . pack('nnnn', 1, $n, 0, 0) . $question . $ans;
    stream_socket_sendto($s, $resp, 0, $peer);
}
