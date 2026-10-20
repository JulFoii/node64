<?php
// Test-Stub fuer dbconnect.php (nur lokale Pruefung in hp3b-*, eigene Test-DB, Test-Passwort). Nicht hochladen.
// send_mail() schreibt nur in /w/mail.log (eine JSON-Zeile je Mail), PHPMailer ist ein leerer Platzhalter.
namespace PHPMailer\PHPMailer { class PHPMailer { public function smtpClose() {} } }
namespace {
if(getenv('HP3BTEST') !== '1') { exit; }
$pdo = new PDO('mysql:host=hp3b-db;dbname=ipv64', 'root', 'hp3btest', array(PDO::ATTR_PERSISTENT => true, PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES 'utf8'"));
date_default_timezone_set('Europe/Berlin');
function add_log($pdo, $userid, $subdomainid, $header, $content) {}
function send_mail(PDO $pdo, $mail, $frommail, $fromname, $empfaenger, $betreff, $msghtml, $updown, $hc2 = null) {
	file_put_contents('/w/mail.log', json_encode(array('to' => $empfaenger, 'subject' => $betreff, 'text' => $hc2['text'] ?? '', 'html' => $msghtml), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
	return true;
}
}
