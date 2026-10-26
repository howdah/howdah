<?php
// The benign-corpus half of the XXE lab: documents applications legitimately
// parse (SAML, SVG, XHTML, RSS, plist, ODF, Office XML, DocBook-style internal
// entities, a bare DOCTYPE), each parsed through every XML entry point with a
// range of libxml flags. Prints one line per parse; the lab runs it with and
// without Howdah and requires identical output (zero behavioural change) and
// zero block events. PHP 5.4 .. 8.5 compatible.
libxml_use_internal_errors(true);
$docs = array(
    'plain'    => '<?xml version="1.0" encoding="UTF-8"?><r><a>1</a><b>SYSTEM PUBLIC</b></r>',
    'soap'     => '<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><m:Get xmlns:m="urn:x"><id>7</id></m:Get></soap:Body></soap:Envelope>',
    'saml'     => '<?xml version="1.0"?><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_a1" Version="2.0"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_b2"><saml:Issuer>https://idp.example.com</saml:Issuer></saml:Assertion></samlp:Response>',
    'ooxml'    => '<?xml version="1.0" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>hello</w:t></w:r></w:p></w:body></w:document>',
    'doctype'  => '<!DOCTYPE note><note><to>a</to></note>',
    'subset'   => '<?xml version="1.0"?><!DOCTYPE note [<!ELEMENT note (#PCDATA)>]><note>hi</note>',
    'entities' => '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY co "ACME"><!ENTITY addr "1 Main St, &co;"><!ENTITY sig "&co; - &addr;">]><d>&sig;</d>',
    'charents' => '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY nbsp "&#160;"><!ENTITY copy "&#169;">]><r>&nbsp;&copy;</r>',
    'xhtml'    => '<?xml version="1.0"?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd"><html xmlns="http://www.w3.org/1999/xhtml"><head><title>t</title></head><body><p>x</p></body></html>',
    'svg'      => '<?xml version="1.0"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="5" height="5"/></svg>',
    'rss'      => '<?xml version="1.0"?><!DOCTYPE rss PUBLIC "-//Netscape Communications//DTD RSS 0.91//EN" "http://my.netscape.com/publish/formats/rss-0.91.dtd"><rss version="0.91"><channel><title>t</title></channel></rss>',
    'plist'    => '<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>k</key><string>v</string></dict></plist>',
    'odf'      => '<?xml version="1.0"?><!DOCTYPE office:document PUBLIC "-//OpenOffice.org//DTD OfficeDocument1.0//EN" "office.dtd"><office:document xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"/>',
    'localdtd' => '<?xml version="1.0"?><!DOCTYPE r SYSTEM "r.dtd" [<!ENTITY x "internal">]><r>&x;</r>',
);
$flagsets = array(
    0,
    LIBXML_NOENT,
    LIBXML_NOENT | LIBXML_NOCDATA,
    LIBXML_NOENT | LIBXML_NONET,
    LIBXML_DTDLOAD | LIBXML_NONET,
    LIBXML_DTDATTR | LIBXML_NONET,
    LIBXML_DTDVALID | LIBXML_NONET,
    LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_NONET,
    LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR | LIBXML_NONET | LIBXML_NOBLANKS,
    LIBXML_NOBLANKS | LIBXML_NSCLEAN | LIBXML_COMPACT,
);
function h($s) { return $s === false || $s === null ? 'false' : md5($s); }
$n = 0;
foreach ($docs as $name => $x) {
    foreach ($flagsets as $f) {
        $tag = $name . '/' . $f . '/';
        $s = simplexml_load_string($x, null, $f);
        echo $tag, 'sx=', h($s ? $s->asXML() : false), "\n";
        $n++;
        try { $e = new SimpleXMLElement($x, $f); echo $tag, 'ctor=', h($e->asXML()), "\n"; }
        catch (Exception $ex) { echo $tag, "ctor=exception\n"; }
        $n++;
        if (class_exists('DOMDocument')) {
            $d = new DOMDocument();
            $r = $d->loadXML($x, $f);
            echo $tag, 'dom=', h($r ? $d->saveXML() : false), "\n";
            $n++;
        }
        if (class_exists('XMLReader')) {
            $rd = new XMLReader();
            $cnt = 0;
            if ($rd->XML($x, null, $f)) { while ($rd->read()) { $cnt++; } }
            echo $tag, 'xr=', $cnt, "\n";
            $n++;
        }
    }
}
echo "TOTAL=", $n, "\n";
