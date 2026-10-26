<?php
// PHP 8 only (named arguments are a parse error before 8.0, hence a separate
// file): the options argument is passed by name, out of positional order, so
// the argument slot between the document and the options is a filled default.
//   php xe_named.php <libxml flags>
libxml_use_internal_errors(true);
$s = simplexml_load_string(options: (int)$argv[1], data: getenv('XXE_DOC'));
$text = $s === false ? '' : (string)$s . $s->asXML();
$d = new DOMDocument();
$ok = $d->loadXML(options: (int)$argv[1], source: getenv('XXE_DOC'));
$text2 = $ok ? $d->saveXML() . $d->documentElement->textContent : '';
echo ($s !== false && $ok ? 'PARSED' : 'REFUSED'), ' ',
    (strpos($text . $text2, 'CANARY_SECRET_9731') !== false ? 'LEAK' : 'NOLEAK'), "\n";
