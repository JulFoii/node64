# dbconnect.php – Online-Push an die Nodes weiterreichen (2026-10-12)

Auf der Live-Seite steht der hc2-Block am Ende von `dbconnect.php` (siehe PHASE1). Die Datei
`dbconnect_hc2.php` wird dort nicht geladen; deshalb gehören diese zwei Änderungen in `dbconnect.php`,
Funktion `hc2_push()`.

## 1. SELECT um Ausführungsort und Nodes erweitern

Vorher:
```php
		$st = $pdo->prepare("SELECT token, paused FROM `$db`.hc2_checks WHERE token = :t AND type = 'push' AND deleted_at IS NULL");
```

Nachher:
```php
		$st = $pdo->prepare("SELECT token, paused, execution, node_id, nodes FROM `$db`.hc2_checks WHERE token = :t AND type = 'push' AND deleted_at IS NULL");
```

## 2. Nach der Zeile mit `hc2_signal('hc2:push', ...)` einfügen

Vorher:
```php
		hc2_signal('hc2:push', $row['token'] . ($down ? ':down' : ':up'));
		return true;
```

Nachher:
```php
		hc2_signal('hc2:push', $row['token'] . ($down ? ':down' : ':up'));
		if ($row['execution'] !== 'online') {
			// lokal/hybrid: an alle messenden Nodes weiterreichen (Kommando "push"; Nodes verwerfen alles aelter als 2 min)
			$ids = array_values(array_unique(array_filter(explode(',', (string)$row['nodes']))));
			if (!$ids && !empty($row['node_id'])) { $ids = array($row['node_id']); }
			$args = json_encode(array('token' => $row['token'], 'down' => $down, 'msg' => $msg, 'from' => $_SERVER['REMOTE_ADDR'] ?? '', 'time' => gmdate('Y-m-d\TH:i:s\Z')), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
			foreach ($ids as $nid) {
				$pdo->prepare("INSERT INTO `$db`.hc2_commands (node_id, name, args, created_at) VALUES (:n, 'push', :a, UTC_TIMESTAMP(3))")->execute(array('n' => $nid, 'a' => $args));
				hc2_signal('hc2:node:' . $nid, 'command');
			}
		}
		return true;
```

## Prüfen

`https://ipv64.net/health.php?token=<Token eines lokalen Push-Checks>` aufrufen: In der Node erscheint
innerhalb von etwa einer Sekunde ein Messpunkt mit „via ipv64“. Alte Tokens verhalten sich unverändert.
