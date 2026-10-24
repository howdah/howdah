<?php
// A stand-in syslog daemon for the lab: binds a unix datagram socket (the
// path syslog(3) and Howdah write to, normally /dev/log) and appends every
// message it receives to a file, one per line. Usage:
//   php -n log_listener.php /dev/log /tmp/out.txt
$path = $argv[1];
$out = $argv[2];
@unlink($path);
$s = stream_socket_server("udg://$path", $errno, $errstr, STREAM_SERVER_BIND);
if (!$s) {
    fwrite(STDERR, "log_listener: cannot bind $path: $errstr\n");
    exit(1);
}
chmod($path, 0666);
while (true) {
    $m = stream_socket_recvfrom($s, 65536);
    if ($m === false || $m === '') {
        continue;
    }
    file_put_contents($out, rtrim($m, "\0\n") . "\n", FILE_APPEND);
}
