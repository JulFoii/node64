# Phase 2 – Webseite: Versand-Brücke und Schlüssel

Der hub läuft auf beiden Servern und prüft Online-Checks. Für Benachrichtigungen über **ipv64-Mail, SMS und die App** braucht er die vorhandene Infrastruktur des Web-Servers (SMTP, internes SMS-Gateway, Firebase). Dafür gibt es eine kleine Brücke.

## 1. `hc2_send.php` in den Webroot

Datei `hc2_send.php` neben `health.php` ablegen. Sie nimmt nur signierte POST-Aufrufe des hub an (HMAC-SHA256, Zeitstempel ≤ 5 min) und ruft `send_mail()`, `send_sms()`, `send_firebase()` aus `dbconnect.php` auf. Für Besucher liefert sie nur `{"ok":false,"error":"method"}`.

## 2. Geheimnis der Brücke

Das Geheimnis liegt auf beiden hubs in `/etc/ipv64-hub/bridge.secret`. Es muss **identisch** nach

```
/var/www/clients/client1/web58/private/hc2_bridge.secret   (chmod 640, eine Zeile)
```

Ich kann es dir nicht in den Chat schreiben; hol es dir von hc-srv01: `cat /etc/ipv64-hub/bridge.secret` – oder sag Bescheid, dann lege ich es auf hc-srv01 unter `/root/hc2_bridge.secret` ab.

## 3. Schlüssel für Kanal-Geheimnisse – jetzt als Text

Der Schlüssel ist ab jetzt eine **Textdatei mit 64 Hex-Zeichen** (eine Zeile), damit er kopierbar ist. Ich habe ihn auf hc-srv01 erzeugt und auf beide hubs verteilt. Auf dem Web-Server:

```bash
# Inhalt von hc-srv01:/var/lib/ipv64-hub/secret.key (64 Hex-Zeichen) nach
/var/www/clients/client1/web58/private/hc2_secret.key      (ersetzt die alte, unlesbare Datei; chmod 640)
```

Die PHP-Funktionen `hc2_encrypt()`/`hc2_decrypt()` lesen beides (Hex-Text oder 32 Rohbytes). Dafür den hc2-Block in `dbconnect.php` einmal durch den aktuellen `dbconnect_hc2.php` ersetzen – oder nur die zwei Funktionen am Ende des Blocks (neu dazu: `hc2_key_bytes()`).

Noch ist nichts mit dem alten Schlüssel verschlüsselt (die neue Welt ist leer), ein Tausch ist also folgenlos.

## Prüfen

Nach Schritt 1+2 kann ich vom hub aus eine Testmail an die Adresse des Testaccounts schicken (`ipv64_mail`-Kanal) und eine Test-SMS, wenn du eine Nummer für den Testaccount hinterlegst.

## SMS-Limit

`user_class.sms_limit` gilt **pro Tag** (bestätigt). Der hub zählt in `hc2_sms_counter` je Account und Tag und verweigert darüber; `send_sms()` erhöht zusätzlich wie bisher `users.sms_count`.
