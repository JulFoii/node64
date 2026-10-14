<?php
/**
 * Healthchecks 2.0: Versand-Bruecke fuer den hub. Der hub kann das interne SMS-Gateway und den
 * Mailversand nicht direkt erreichen; er schickt signierte Auftraege hierher, und diese Datei
 * nutzt die vorhandenen Funktionen send_mail(), send_sms(), send_firebase() aus dbconnect.php.
 *
 * Sicherheit: HMAC-SHA256 ueber den rohen Body mit dem Geheimnis aus HC2_BRIDGE_SECRET_FILE
 * (gleicher Inhalt wie /etc/ipv64-hub/bridge.secret auf den hubs), Zeitstempel max. 5 Minuten alt,
 * nur POST mit JSON. Antwort: {"ok":true} oder {"ok":false,"error":"..."}.
 */
include("dbconnect.php");
require_once __DIR__ . '/hc2_send_lib.php';  // hc2_deliver(): derselbe Versand wie fuer die API v2

const HC2_BRIDGE_SECRET_FILE = '/var/www/clients/client1/web58/private/hc2_bridge.secret';

header('Content-Type: application/json');
header('Cache-Control: no-store');

function bridge_out(bool $ok, string $error = '', int $code = 200): void {
	http_response_code($code);
	echo json_encode(array('ok' => $ok, 'error' => $error));
	exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') { bridge_out(false, 'method', 405); }
$secret = is_file(HC2_BRIDGE_SECRET_FILE) ? trim((string)file_get_contents(HC2_BRIDGE_SECRET_FILE)) : '';
if ($secret === '') { bridge_out(false, 'bridge not configured', 503); }
$raw = file_get_contents('php://input');
$sig = (string)($_SERVER['HTTP_X_HC2_SIGNATURE'] ?? '');
if ($raw === '' || strlen($raw) > 65536 || !hash_equals(hash_hmac('sha256', $raw, $secret), $sig)) { bridge_out(false, 'signature', 403); }
$req = json_decode($raw, true);
if (!is_array($req) || abs(time() - (int)($req['ts'] ?? 0)) > 300) { bridge_out(false, 'stale or invalid request', 400); }

$type = (string)($req['type'] ?? '');
$to = trim((string)($req['to'] ?? ''));
$subject = mb_substr((string)($req['subject'] ?? ''), 0, 200);
$text = (string)($req['text'] ?? '');
$html = (string)($req['html'] ?? '');
$updown = (string)($req['updown'] ?? '');
$userid = (int)($req['userid'] ?? 0);
if ($to === '' || $userid <= 0) { bridge_out(false, 'missing to/userid', 400); }

try {
	$err = hc2_deliver($pdo, $type, $to, $subject, $text, $html, $updown, $userid);
	if ($err === '') { bridge_out(true); }
	bridge_out(false, $err, in_array($err, array('invalid address', 'invalid number', 'unknown type'), true) ? 400 : 502);
} catch (Throwable $e) {
	error_log('hc2_send: ' . $e->getMessage());
	bridge_out(false, 'send failed', 500);
}
