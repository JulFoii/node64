# CDN64 online – Phase T5 einspielen (ipv64.net)

Modus 2 (TLS endet auf srv07/srv08): ipv64 setzt für die Server die TXT-Einträge der Let's-Encrypt-Prüfung und
hebt ihre Zertifikate verschlüsselt auf. Getestet in der Testumgebung (53 Prüfungen) und mit Go-Tests.

## 1. SQL (Hauptdatenbank ipv64)

Aus `deploy/sql/cdn64_online.sql` nur den neuen Block am Ende ausführen (die ganze Datei geht auch, sie ist mehrfach
ausführbar):

```sql
CREATE TABLE IF NOT EXISTS `cdn64o_certs` (
  `fqdn` varchar(253) NOT NULL,
  `blob` mediumtext NOT NULL,
  `not_after` datetime NOT NULL,
  `edge` varchar(32) NOT NULL DEFAULT '',
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`fqdn`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
```

## 2. Datei ersetzen

`deploy/web/api_v2_cdn64o.php` über die vorhandene Datei neben `api_v2.php` kopieren. `api_v2.php` bleibt unverändert.

## Was neu ist

- `C64O_MODES` = 1 und 2: Nodes können Namen in Modus 2 einschalten bzw. mit `PATCH /cdn64o/hosts/{id}` wechseln
  (DNS bleibt gleich).
- `POST /cdn64o/edge/acme-txt` (Server-Geheimnis): `{fqdn, value, delete}` – nur `_acme-challenge.<Name>` eines
  Modus-2-Hosts; legt bzw. löscht den TXT im Account des Hosts mit `add_record`/`del_record_name` (wie ACME-Clients
  über die API).
- `GET /cdn64o/edge/certs?fqdn=` und `PUT /cdn64o/edge/certs` (Server-Geheimnis): verschlüsseltes Zertifikat
  ablegen/holen (Schlüssel nur auf den Servern); ein älteres ersetzt nie ein neueres. Beim Ausschalten eines Namens
  wird sein Zertifikat gelöscht.
