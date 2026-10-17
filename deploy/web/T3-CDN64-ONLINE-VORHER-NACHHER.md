# CDN64 online – Phase T3 einspielen (ipv64.net)

Steuerung von CDN64 online bei ipv64: neue Tabellen, API-v2-Endpunkte für Nodes und für die Server srv07/srv08.
Getestet in einer Testumgebung (MariaDB 10.5, PHP 8.3, api_v2.php mit dieser Datei) und im Durchstich mit einem
echten cdn64-edge und einer Test-Node (Tunnel, Weiterleitung, Traffic-Meldung, Sperre, Ausschalten).

## 1. SQL einspielen (Hauptdatenbank ipv64)

Datei `deploy/sql/cdn64_online.sql` – mehrfach ausführbar. Legt die Tabellen `cdn64o_*` an, ergänzt
`user_class.cdn_bandwidth` (Mbit/s, 0 = frei) und trägt srv07/srv08 mit dem SHA-256 ihres Server-Geheimnisses ein
(das Geheimnis selbst liegt nur auf dem jeweiligen Server in `/etc/cdn64-edge/config.yaml`).

Danach den Wert für Supporter setzen (Business und Company bleiben 0 = frei), z. B. 100 Mbit/s:

```sql
UPDATE user_class SET cdn_bandwidth = 100 WHERE id = 6;
```

## 2. Neue Datei in den Webroot

`deploy/web/api_v2_cdn64o.php` neben `api_v2.php` legen.

## 3. `api_v2.php`: Datei einbinden

VORHER (am Ende der Datei):

```php
// ===================================================================
//  Start
// ===================================================================
try {
	dispatch();
```

NACHHER (Zeile vor dem Start-Block; falls `api_v2_hc2.php` dort schon eingebunden ist, direkt darunter):

```php
require __DIR__ . '/api_v2_cdn64o.php';

// ===================================================================
//  Start
// ===================================================================
try {
	dispatch();
```

## 4. Altes CDN: gemeinsames Kontingent und keine Domain in beiden

Beide CDN teilen sich `user_class.cdn_domains`. Die neue API zählt das alte CDN schon mit; damit es auch umgekehrt
gilt, an zwei Stellen im alten CDN die neuen Namen mitzählen und Domains ablehnen, die schon in CDN64 online sind.

### 4a. `api_v2.php`, `route('POST', '/cdn', ...)`

VORHER:

```php
	$c = (int)q1("SELECT count(id) c FROM cdn_domains WHERE userid = :u", array('u' => uid()))['c'];
	if($c >= (int)$CLASS['cdn_domains']) { fail(403, 'limit_reached', 'CDN domain limit of your plan is reached.'); }
	if(q1("SELECT id FROM cdn_domains WHERE domainid = :d", array('d' => $d['id'])) !== null) { fail(409, 'cdn_exists', 'This domain is already in the CDN.'); }
```

NACHHER:

```php
	$c = (int)q1("SELECT count(id) c FROM cdn_domains WHERE userid = :u", array('u' => uid()))['c'];
	$c += (int)q1("SELECT count(id) c FROM cdn64o_hosts WHERE userid = :u", array('u' => uid()))['c'];
	if($c >= (int)$CLASS['cdn_domains']) { fail(403, 'limit_reached', 'CDN domain limit of your plan is reached.'); }
	if(q1("SELECT id FROM cdn_domains WHERE domainid = :d", array('d' => $d['id'])) !== null) { fail(409, 'cdn_exists', 'This domain is already in the CDN.'); }
	if(q1("SELECT id FROM cdn64o_hosts WHERE subdomain_id = :d LIMIT 1", array('d' => $d['id'])) !== null) { fail(409, 'cdn64o_active', 'This domain is in CDN64 online. Remove it there first.'); }
```

### 4b. `cdn.php`, Domain hinzufügen (`add_cdn`)

VORHER:

```php
			$statement = $pdo->prepare("SELECT count(id) FROM cdn_domains WHERE userid = :userid");
			$result = $statement->execute(array('userid' => $userid));
			$cdn_do = $statement->fetch();
			$statement = $pdo->prepare("SELECT id FROM cdn_domains WHERE domainid = :cdn_domain");
			$result = $statement->execute(array('cdn_domain' => $cdn_domain));
			$cdn = $statement->fetch();
```

NACHHER:

```php
			$statement = $pdo->prepare("SELECT (SELECT count(id) FROM cdn_domains WHERE userid = :userid) + (SELECT count(id) FROM cdn64o_hosts WHERE userid = :userid2) AS id");
			$result = $statement->execute(array('userid' => $userid, 'userid2' => $userid));
			$cdn_do = $statement->fetch();
			$statement = $pdo->prepare("SELECT id FROM cdn_domains WHERE domainid = :cdn_domain UNION SELECT id FROM cdn64o_hosts WHERE subdomain_id = :cdn_domain2 LIMIT 1");
			$result = $statement->execute(array('cdn_domain' => $cdn_domain, 'cdn_domain2' => $cdn_domain));
			$cdn = $statement->fetch();
```

(`$cdn_do["id"]` ist danach die Summe aus altem und neuem CDN; eine Domain mit Namen in CDN64 online gilt als
„already in use“.)

Hinweis: Im bisherigen Code fragt `SELECT count(id) ...` ohne Alias ab, `$cdn_do["id"]` ist dann leer – die
Grenze `cdn_domains` greift in `cdn.php` heute vermutlich gar nicht. Mit dem Alias `AS id` greift sie wieder.

## 5. Prüfen

```bash
curl -s -H "Authorization: Bearer <API-Key>" https://ipv64.net/api/v2/cdn64o
```

Erwartet: `quota` (Domains und Traffic, altes CDN mitgezählt), `edges` srv07/srv08, leere `tunnels`/`hosts`.
Die Server holen ihre Konfiguration danach selbst; auf srv07/srv08 zeigt `curl -s http://127.0.0.1/health` unter
`api` ein `last_ok` statt eines Fehlers.

## Was die Datei macht (Kurzfassung)

- **Nodes (API-Key):** `GET /cdn64o` (Kontingent, Server, Tunnels, Hosts), `POST /cdn64o/tunnels` (Node anmelden,
  Token nur einmal sichtbar), `POST /cdn64o/tunnels/{id}/token`, `DELETE /cdn64o/tunnels/{id}`,
  `POST /cdn64o/hosts` (Name einschalten), `GET|PATCH|DELETE /cdn64o/hosts/{id}`, `GET /cdn64o/hosts/{id}/events`.
- **Prüfungen beim Einschalten:** Klasse (`cdn_domains > 0`), gemeinsames Kontingent mit dem alten CDN, Traffic des
  Monats, Name gehört zu einer Domain des Accounts, Domain nicht im alten CDN, kein CNAME und kein DNS-Failover auf
  dem Namen, Name nur einmal.
- **DNS:** A/AAAA beider Server mit TTL 10 in `subdomain_records` mit `cdn_tmp = 3` (update.php und API lassen sie in
  Ruhe), vorhandene A/AAAA des Namens werden deaktiviert (DynDNS aktualisiert sie weiter im Hintergrund) und beim
  Ausschalten wieder aktiviert; Zuordnung nur in `cdn64o_records`. Scheitert PowerDNS, wird alles zurückgenommen.
- **Server (Server-Geheimnis):** `GET /cdn64o/edge/config` (alle 10 s, ETag/304), `POST /cdn64o/edge/report`
  (jede Minute Traffic je Host, verbundene Tunnels). Ist das Traffic-Kontingent des Monats erreicht, gehen alle
  Hosts des Accounts auf `blocked` (die Server weisen ab); im neuen Monat oder mit höherer Klasse wieder frei.
