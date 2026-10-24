<?php
// Benchmark app for the GET and POST workloads. It touches every request
// superglobal the way a real application does, so PHP (and Howdah's chained
// input_filter) materializes them, then prints a short body.
$n = count($_GET) + count($_POST) + count($_COOKIE) + count($_FILES) + count($_SERVER);
echo "ok $n\n";
