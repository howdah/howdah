<?php
// Lab-only HTTPS target for sinks_fastfollow_container.sh (T6): a self-signed
// certificate for CN=localhost generated on the fly, then a loop answering every
// request with "HTTPSSERVED". Usage: php https_server.php <port> <pem-path>.
// No howdah in this process. Not part of the extension or the package.
$port = isset($argv[1]) ? (int)$argv[1] : 18443;
$pem = isset($argv[2]) ? $argv[2] : "/tmp/howdah-https.pem";
$cfg = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA, 'digest_alg' => 'sha256'];
$k = openssl_pkey_new($cfg);
$csr = $k ? openssl_csr_new(['commonName' => 'localhost'], $k, $cfg) : false;
$x = $csr ? openssl_csr_sign($csr, null, $k, 2, $cfg) : false;
if (!$x) { fwrite(STDERR, "cert generation failed: " . openssl_error_string() . "\n"); exit(1); }
openssl_x509_export($x, $c);
openssl_pkey_export($k, $pk);
file_put_contents($pem, $c . $pk);
$ctx = stream_context_create(['ssl' => ['local_cert' => $pem, 'verify_peer' => false]]);
$srv = stream_socket_server("ssl://127.0.0.1:$port", $en, $es, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $ctx);
if (!$srv) { fwrite(STDERR, "listen failed: $es\n"); exit(1); }
while (true) {
    $cl = @stream_socket_accept($srv, 30);
    if (!$cl) continue;
    $buf = '';
    while (!feof($cl) && strpos($buf, "\r\n\r\n") === false && strlen($buf) < 8192) {
        $d = fread($cl, 2048);
        if ($d === false || $d === '') break;
        $buf .= $d;
    }
    $body = 'HTTPSSERVED';
    @fwrite($cl, "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
    @fclose($cl);
}
