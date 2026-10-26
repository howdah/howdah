<?php
// One XML parse through one libxml entry point, for the XXE lab
// (lab/integration/legacy_sinks_container.sh).
//
//   php xe.php <entry> <libxml flags> [<env var holding the document>]
//
// Prints "<PARSED|REFUSED> <LEAK|NOLEAK>": did the parse succeed, and did the
// file the document's external entity names show up in what the parser built.
// Compatible with PHP 5.4 .. 8.5 (no short echo tags, no ::class, no ??).
$entry = $argv[1];
$flags = (int)$argv[2];
$doc = getenv(isset($argv[3]) ? $argv[3] : 'XXE_DOC');
libxml_use_internal_errors(true);
$text = '';
$parsed = false;
switch ($entry) {
    case 'simplexml_load_string':
        $s = simplexml_load_string($doc, null, $flags);
        $parsed = ($s !== false);
        if ($parsed) { $text = (string)$s . $s->asXML(); }
        break;
    case 'simplexml_load_string_var':
        // the flags travel in a variable the caller keeps using afterwards
        $opts = $flags;
        $alias = &$opts;
        $s = simplexml_load_string($doc, null, $opts);
        $parsed = ($s !== false);
        if ($parsed) { $text = (string)$s . $s->asXML(); }
        echo 'OPTS=', $opts, ' ';
        break;
    case 'simplexml_load_string_str':
        $s = simplexml_load_string($doc, null, (string)$flags);
        $parsed = ($s !== false);
        if ($parsed) { $text = (string)$s . $s->asXML(); }
        break;
    case 'domdocument':
        $d = new DOMDocument();
        $parsed = $d->loadXML($doc, $flags);
        if ($parsed) { $text = $d->saveXML() . ($d->documentElement ? $d->documentElement->textContent : ''); }
        break;
    case 'simplexmlelement':
        try {
            $s = new SimpleXMLElement($doc, $flags);
            $parsed = true;
            $text = (string)$s . $s->asXML();
        } catch (Exception $e) {
            $parsed = false;
        }
        break;
    case 'xmlreader':
        $r = new XMLReader();
        if ($r->XML($doc, null, $flags)) {
            $parsed = true;
            while ($r->read()) {
                if ($r->hasValue) { $text .= $r->value; }
            }
        }
        break;
    case 'dom84':
        $cls = 'Dom\\XMLDocument';
        try {
            $d = call_user_func(array($cls, 'createFromString'), $doc, $flags);
            $parsed = true;
            $text = $d->saveXml() . $d->documentElement->textContent;
        } catch (Exception $e) {
            $parsed = false;
        }
        break;
}
echo ($parsed ? 'PARSED' : 'REFUSED'), ' ', (strpos((string)$text, 'CANARY_SECRET_9731') !== false ? 'LEAK' : 'NOLEAK'), "\n";
