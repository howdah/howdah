<?php
// Builds a BENIGN test phar whose metadata is an INERT tracer object.
// The tracer's __wakeup only echoes a marker; it carries no gadget and does
// nothing harmful. Usage: php -d phar.readonly=0 make_phar.php /path/t.phar
class Tracer { public $x = 1; function __wakeup() { echo "WOKE\n"; } }
$path = $argv[1];
@unlink($path);
$p = new Phar($path);
$p->addFromString('x', 'hi');
$p->setStub('<?php __HALT_COMPILER();');
$p->setMetadata(new Tracer);
unset($p);
echo "made\n";
