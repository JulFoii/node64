<?php
/**
 * IPv64.net – Wochenbericht bzw. Newsletter abbestellen, ohne Anmeldung (Link in jeder Wochenbericht-Mail).
 *   GET  ?u=<id>&k=report|newsletter&t=<token>   Rueckfrage mit Knopf
 *   POST (gleiche Adresse)                         abbestellen; auch die Ein-Klick-Abmeldung der Mailprogramme
 *                                                  (RFC 8058: POST mit List-Unsubscribe=One-Click)
 * Der Token ist users.report_token (zufaellig, nur dafuer) – nicht der DynDNS-Update-Key.
 */
include(__DIR__ . '/dbconnect.php');

$uid = (int)($_GET['u'] ?? 0);
$kind = ($_GET['k'] ?? 'report') === 'newsletter' ? 'newsletter' : 'report';
$token = (string)($_GET['t'] ?? '');
$st = $pdo->prepare("SELECT id, report_token, weekly_report, newsletter FROM users WHERE id = :u");
$st->execute(array('u' => $uid));
$u = $st->fetch(PDO::FETCH_ASSOC);
$valid = $u && strlen((string)$u['report_token']) === 32 && hash_equals((string)$u['report_token'], $token);
$col = $kind === 'newsletter' ? 'newsletter' : 'weekly_report';
$done = false;
if ($valid && $_SERVER['REQUEST_METHOD'] === 'POST') {
	$pdo->prepare("UPDATE users SET $col = 0 WHERE id = :u")->execute(array('u' => $uid));
	if (function_exists('add_log')) { add_log($pdo, $uid, '0', 'Account', ($kind === 'newsletter' ? 'Newsletter' : 'Weekly report') . ' unsubscribed by link.'); }
	$done = true;
	if (stripos((string)($_POST['List-Unsubscribe'] ?? ''), 'One-Click') !== false) { http_response_code(200); echo 'OK'; exit; } // Mailprogramm
}
$what = $kind === 'newsletter' ? array('Newsletter', 'newsletter') : array('Wochenbericht', 'weekly report');
$h = function($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
header('Content-Type: text/html; charset=utf-8');
header('X-Robots-Tag: noindex');
?><!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title><?php echo $h($what[0]); ?> abbestellen – IPv64.net</title></head>
<body style="margin:0;background:#f1f1f1;font-family:Arial,Helvetica,sans-serif;color:#1d273b">
<div style="max-width:520px;margin:40px auto;background:#fff;border-radius:8px;padding:24px">
	<div style="font-size:18px;font-weight:bold;color:#17bebb;margin-bottom:16px">IPv64.net</div>
<?php if (!$valid) { ?>
	<p>Dieser Link ist ungültig oder abgelaufen. Den <?php echo $h($what[0]); ?> kannst du jederzeit in deinen <a href="/account.php?accountsettings#mail-prefs">Kontoeinstellungen</a> abschalten.</p>
	<p style="color:#667382;font-size:13px">This link is invalid. You can switch off the <?php echo $h($what[1]); ?> in your account settings at any time.</p>
<?php } elseif ($done || (int)$u[$col] === 0) { ?>
	<p><b><?php echo $h($what[0]); ?> abbestellt.</b> Du bekommst ihn nicht mehr. Wieder einschalten kannst du ihn in deinen <a href="/account.php?accountsettings#mail-prefs">Kontoeinstellungen</a>.</p>
	<p style="color:#667382;font-size:13px">You are unsubscribed from the <?php echo $h($what[1]); ?>. You can switch it on again in your account settings.</p>
<?php } else { ?>
	<p>Möchtest du den <b><?php echo $h($what[0]); ?></b> von IPv64.net abbestellen?</p>
	<form method="post"><button type="submit" style="background:#17bebb;color:#fff;border:0;border-radius:6px;padding:10px 18px;font-size:15px;cursor:pointer"><?php echo $h($what[0]); ?> abbestellen</button></form>
	<p style="color:#667382;font-size:13px;margin-top:16px">Unsubscribe from the <?php echo $h($what[1]); ?>? Use the button above.</p>
<?php } ?>
</div></body></html>
