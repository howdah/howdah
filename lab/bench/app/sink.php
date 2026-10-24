<?php
// Benchmark app for the sink workload: one command execution and one include
// per request, the two Layer 3 sinks a typical legacy app reaches most often.
// Both are allowlisted in configs/l123.toml, so benign traffic logs nothing.
$n = count($_GET) + count($_SERVER);
system('true');
include __DIR__ . '/inc.php';
echo "ok $n " . BENCH_INC . "\n";
