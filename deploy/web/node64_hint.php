<?php
/**
 * Node64 – kleiner Werbehinweis fuer Produktseiten (ohne DB, ohne Login, keine Ausgabe ausser dem Hinweis).
 *
 *   $node64_hint      = "Healthchecks auch lokal in deinem Heimnetz – mit Node64.";  // optional, sonst Standardtext
 *   $node64_hint_btn  = "More about Node64";       // optional, Text des Knopfs (Standard: "Mehr zu Node64")
 *   $node64_hint_href = "/node64.php?lang=en";     // optional, Ziel des Knopfs (Standard: /node64.php)
 *   include("node64_hint.php");                    // aus Unterordnern: include("../node64_hint.php");
 *
 * Text und Knopf werden escaped (kein HTML). Die Variablen werden danach geleert, damit ein weiterer Hinweis
 * auf derselben Seite wieder die Standardwerte bekommt. Link bewusst auf /node64.php: /node64 ist ein Ordner (latest.json).
 */
$n64h_text = (isset($node64_hint) AND is_string($node64_hint) AND trim($node64_hint) !== '') ? $node64_hint
	: 'Healthchecks, Reverse-Proxy, DNS-Filter, DynDNS und Honeypot lokal in deinem Heimnetz – verbunden mit deinem ipv64-Account: Node64.';
$n64h_btn = (isset($node64_hint_btn) AND is_string($node64_hint_btn) AND trim($node64_hint_btn) !== '') ? $node64_hint_btn : 'Mehr zu Node64';
$n64h_href = (isset($node64_hint_href) AND is_string($node64_hint_href) AND $node64_hint_href !== '') ? $node64_hint_href : '/node64.php';
if(!defined('NODE64_HINT_CSS')) {
	define('NODE64_HINT_CSS', true);
	echo '<style>.n64-dark{display:none!important}html[data-theme="dark"] .n64-light{display:none!important}html[data-theme="dark"] .n64-dark{display:inline!important}</style>';
}
?>
<div class="card mb-3 node64-hint" style="border-left:4px solid #f59c1a">
	<div class="card-body p-2 d-flex flex-wrap align-items-center" style="gap:.75rem">
		<img src="/img/node64/node64_icon.png" width="40" height="40" alt="" style="border-radius:8px">
		<div class="flex-grow-1" style="min-width:12rem">
			<img src="/img/node64/node64.svg" height="16" alt="Node64" class="n64-light"><img src="/img/node64/node64_dark.svg" height="16" alt="Node64" class="n64-dark">
			<div class="small mt-1"><?php echo htmlspecialchars($n64h_text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?></div>
		</div>
		<a class="btn btn-sm btn-outline-secondary" href="<?php echo htmlspecialchars($n64h_href, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?>"><?php echo htmlspecialchars($n64h_btn, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); ?> <i class="fa-solid fa-arrow-right"></i></a>
	</div>
</div>
<?php unset($node64_hint, $node64_hint_btn, $node64_hint_href, $n64h_text, $n64h_btn, $n64h_href); ?>
