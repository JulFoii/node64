# dbconnect.php – Push über den hub (2026-10-12, ersetzt die vorige Fassung dieser Anleitung)

Auf der Live-Seite steht der hc2-Block am Ende von `dbconnect.php`. Die Weitergabe von Pushes an die
Nodes macht jetzt nur noch der hub: `hc2_push()` gibt den Push signiert an `/v1/portal/push`. Nur wenn
kein hub erreichbar ist, speichert PHP den Messpunkt selbst (ohne Weitergabe). Dadurch gibt es die Regeln
für die Weitergabe nur noch an einer Stelle.

## 1. Zwei Konstanten ergänzen

Im hc2-Block von `dbconnect.php` nach der Zeile mit `HC2_REDIS_PASS_FILE` einfügen (dieselben Werte wie
in `healthchecks2/hc2_lib.php`; die Schlüsseldatei `hc2_bridge.secret` gibt es dort schon):

```php
defined('HC2_BRIDGE_SECRET_FILE') || define('HC2_BRIDGE_SECRET_FILE', '/var/www/clients/client1/web58/private/hc2_bridge.secret'); // wie in hc2_lib.php
defined('HC2_HUBS')         || define('HC2_HUBS', 'https://hc-srv01.ipv64.net,https://hc-srv02.ipv64.net');
```

## 2. Funktion `hc2_push()` ersetzen und `hc2_push_hub()` dazunehmen

Vorher: die komplette Funktion `hc2_push()` von `/**` (Kommentar „Heartbeat eines Push-Checks der neuen
Welt“) bis zu ihrer schließenden `}`.

Nachher (beide Funktionen an dieselbe Stelle):

```php
/**
 * Heartbeat eines Push-Checks der neuen Welt (health.php). Liefert true, wenn der Token zu einem
 * hc2-Check gehoert; dann hat health.php nichts mehr zu tun. Alte Tokens (nicht in hc2_checks) -> false,
 * alte Logik laeuft unveraendert. Unbekannte Tokens werden hier NICHT verraten (false wie "alt").
 * Gespeichert und an die messenden Nodes weitergereicht wird beim hub (eine Stelle fuer alle Wege);
 * ist kein hub erreichbar, speichert PHP den Messpunkt selbst (ohne Weitergabe an Nodes).
 */
function hc2_push(string $token, array $get): bool {
	if ($token === '' || !preg_match('/^[A-Za-z0-9]{20,50}$/', $token)) { return false; }
	try {
		$db = HC2_DB; $pdo = hc2_pdo();
		$st = $pdo->prepare("SELECT token FROM `$db`.hc2_checks WHERE token = :t AND type = 'push' AND deleted_at IS NULL");
		$st->execute(array('t' => $token));
		$row = $st->fetch(PDO::FETCH_ASSOC);
		if (!$row) { return false; }
		$down = (isset($get['status']) && strtolower((string)$get['status']) === 'down') || isset($get['fail']);
		$msg = mb_substr((string)($get['msg'] ?? $get['message'] ?? ''), 0, 500);
		$from = (string)($_SERVER['REMOTE_ADDR'] ?? '');
		if (hc2_push_hub($row['token'], $down, $msg, $from)) { return true; }
		// kein hub erreichbar: selbst speichern (der checker bewertet ueber last_push_at)
		$details = json_encode(array('from' => $from, 'via' => 'health.php'));
		$pdo->prepare("INSERT IGNORE INTO `$db`.hc2_measurements (token, source, node_seq, time, status, latency_ms, reason, message, details, received_at)
			VALUES (:t, 'push', 0, UTC_TIMESTAMP(3), :s, 0, :r, :m, :d, UTC_TIMESTAMP(3))")
			->execute(array('t' => $row['token'], 's' => $down ? 0 : 1, 'r' => $down ? 'push_down' : '', 'm' => $msg, 'd' => $details));
		$pdo->prepare("UPDATE `$db`.hc2_checks SET last_push_at = UTC_TIMESTAMP(3) WHERE token = :t")->execute(array('t' => $row['token']));
		hc2_signal('hc2:push', $row['token'] . ($down ? ':down' : ':up'));
		return true;
	} catch (Throwable $e) {
		error_log('hc2_push: ' . $e->getMessage());
		return false;
	}
}

/** Push an den hub geben (signiert wie die Portal-Aufrufe); true = vom hub angenommen. Kurze Timeouts. */
function hc2_push_hub(string $token, bool $down, string $msg, string $from): bool {
	$secret = is_file(HC2_BRIDGE_SECRET_FILE) ? trim((string)file_get_contents(HC2_BRIDGE_SECRET_FILE)) : '';
	if ($secret === '' || !function_exists('curl_init')) { return false; }
	$raw = json_encode(array('ts' => time(), 'token' => $token, 'down' => $down, 'msg' => $msg, 'from' => $from), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	$sig = hash_hmac('sha256', $raw, $secret);
	foreach (explode(',', HC2_HUBS) as $hub) {
		$ch = curl_init(trim($hub) . '/v1/portal/push');
		curl_setopt_array($ch, array(CURLOPT_POST => true, CURLOPT_POSTFIELDS => $raw, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 4, CURLOPT_CONNECTTIMEOUT => 2,
			CURLOPT_HTTPHEADER => array('Content-Type: application/json', 'X-HC2-Signature: ' . $sig, 'User-Agent: ipv64-portal')));
		$res = curl_exec($ch); $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
		if ($res === false || $code >= 500) { continue; }
		$j = json_decode((string)$res, true);
		return is_array($j) && !empty($j['ok']);
	}
	return false;
}
```

## Prüfen

`https://ipv64.net/health.php?token=<Token eines lokalen Push-Checks>` aufrufen: In der Node erscheint
innerhalb von etwa einer Sekunde ein Messpunkt mit „via ipv64“ und der echten Absenderadresse; im
hub-Messpunkt steht `"via":"hub:fsn"` oder `"hub:nbg"`. Alte Tokens verhalten sich unverändert.
