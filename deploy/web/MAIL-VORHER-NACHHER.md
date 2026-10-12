# send_mail() für Healthchecks-2.0-Mails – Vorher/Nachher (dbconnect.php)

Zweck: Benachrichtigungs-Mails aus Healthchecks 2.0 (Störung, Entwarnung, Sammelmeldung, Bestätigungscode,
Test) bekommen ihren eigenen Betreff und ihr Design, einen sauberen Textteil und die Kennzeichnung als
automatische Mail. Fehlgeschlagene Mails werden als Fehler zurückgemeldet.

Alle bisherigen Aufrufe von `send_mail()` (Registrierung, Passwort, alte Healthchecks, Failover usw.) bleiben
unverändert: Der neue 9. Parameter `$hc2` ist optional, nur `hc2_send.php` übergibt ihn.
`hc2_send.php` erkennt den neuen Parameter selbst. Die Reihenfolge des Hochladens ist also egal.

Vier Stellen, alle in `function send_mail(...)`. Einrückung = Tabs.

## 1. Kopfzeile der Funktion

Vorher:
```php
function send_mail(PDO $pdo,$mail,$frommail,$fromname,$empfaenger,$betreff,$msghtml,$updown)
```

Nachher:
```php
function send_mail(PDO $pdo,$mail,$frommail,$fromname,$empfaenger,$betreff,$msghtml,$updown,$hc2 = null)
```

## 2. Betreff nicht ersetzen

Vorher:
```php
	if(strpos($msghtml, "Testnachricht") !== false)
	{
```

Nachher:
```php
	if(is_array($hc2))
	{
		// Healthchecks 2.0: Betreff kommt fertig vom hub
	}elseif(strpos($msghtml, "Testnachricht") !== false)
	{
```

## 3. Inhalt unverändert, eigener Textteil, automatische Mail

Vorher:
```php
	$mail->isHTML(true);
	if(strpos($msghtml, "health_limit") !== false)
	{
```

Nachher:
```php
	$mail->isHTML(true);
	if(is_array($hc2))
	{
		// Healthchecks 2.0: fertiges HTML mit eigenem Textteil, als automatische Nachricht gekennzeichnet
		$mail->Body = $msghtml;
		$mail->AltBody = (string)($hc2['text'] ?? '');
		$mail->addCustomHeader('Auto-Submitted', 'auto-generated');
		$mail->addCustomHeader('X-Auto-Response-Suppress', 'All');
	}elseif(strpos($msghtml, "health_limit") !== false)
	{
```

## 4. Ergebnis zurückgeben

Vorher:
```php
	if (!$mail->send()) {
		#echo 'Mailer Error: ' . $mail->ErrorInfo;
	} else {
		#echo 'Message sent!';
	}
	$mail->clearAddresses();
	$mail->msgHTML("");
	$mail->Subject = "";
	$mail->clearAllRecipients();
}
```

Nachher:
```php
	$sent = $mail->send();
	if (!$sent) {
		error_log('send_mail: ' . $mail->ErrorInfo);
	}
	$mail->clearAddresses();
	$mail->msgHTML("");
	$mail->AltBody = "";
	$mail->clearCustomHeaders();
	$mail->Subject = "";
	$mail->clearAllRecipients();
	return $sent;
}
```

Außerdem hochladen: `hc2_send.php` (aus deploy/web).

## Hinweis, nicht Teil der Änderung

`send_mail()` prüft das Zertifikat des Mailservers nicht (`verify_peer` = false). Hat der Mailserver ein
gültiges Zertifikat, sollte das später auf `true` gestellt werden.
