<?php
// Test-Router fuer den PHP-Builtin-Server: bildet die Rewrite-Regel aus H3-HONEYPOT-VORHER-NACHHER.md nach. Nicht hochladen.
//   RewriteRule ^/?blocklists/live/([A-Za-z0-9]{32})/([A-Za-z0-9_.-]+)$ /blocklists/live.php?t=$1&f=$2 [L]
$p = (string)parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if(preg_match('#^/blocklists/live/([A-Za-z0-9]{32})/([A-Za-z0-9_.-]+)$#', $p, $m)) {
	$_GET['t'] = $m[1]; $_GET['f'] = $m[2];
	require $_SERVER['DOCUMENT_ROOT'] . '/blocklists/live.php';
	return true;
}
if(str_starts_with($p, '/blocklists/live/')) { http_response_code(404); echo "not found\n"; return true; } // Regel greift nicht: wie Apache 404
return false;
