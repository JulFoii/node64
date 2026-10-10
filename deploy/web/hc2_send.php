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

use PHPMailer\PHPMailer\PHPMailer;

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
if (!in_array($updown, array('', '0', '1'), true)) { $updown = ''; }

try {
	switch ($type) {
		case 'mail':
			if (!filter_var($to, FILTER_VALIDATE_EMAIL)) { bridge_out(false, 'invalid address', 400); }
			$mail = new PHPMailer();
			$body = $html !== '' ? $html : nl2br(htmlspecialchars($text));
			// send_mail() nimmt freien HTML-Text als Body, wenn er kein Schluesselwort/keine Check-ID ist
			$info = send_mail($pdo, $mail, '', '', $to, $subject !== '' ? $subject : 'IPv64.net Healthcheck', $body, $updown);
			$mail->smtpClose();
			bridge_out(true);
		case 'sms':
			if (!preg_match('/^[0-9]{6,20}$/', $to)) { bridge_out(false, 'invalid number', 400); }
			send_sms($pdo, json_encode(array('completenumber' => $to)), mb_substr($text, 0, 300), $updown, $userid);
			bridge_out(true);
		case 'app':
			send_firebase($pdo, json_encode(array('devicetoken' => $to)), mb_substr($text !== '' ? $text : $subject, 0, 200), $updown);
			bridge_out(true);
		default:
			bridge_out(false, 'unknown type', 400);
	}
} catch (Throwable $e) {
	error_log('hc2_send: ' . $e->getMessage());
	bridge_out(false, 'send failed', 500);
}
