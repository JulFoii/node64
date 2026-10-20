#!/bin/bash
# Honeypot64 H6 (Teil ipv64: Passwortpruefung, Aenderungs-Feed, Fingerabdruecke): Pruefung in einer abgeschotteten
# Umgebung auf der Testbox (ssh agentbox). Eigene Container/Netz/Image mit Praefix hp6i-, Test-DB mit Test-Passwort; am
# Ende wird alles entfernt. Andere Container auf der Box werden nicht angefasst. Webroot wie live unter
# /var/www/clients/client1/web58/web (die Bewertung bindet dbconnect.php mit diesem Pfad ein).
# Prueft vorher, dass deploy/upload/web dieselben Dateien wie deploy/web enthaelt, und spielt deploy/upload/datenbank.sql ein.
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HP="$(cd "$HERE/../.." && pwd)"            # deploy/web/honeypot
WEB="$(cd "$HP/.." && pwd)"                # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"           # deploy/sql
UP="$(cd "$WEB/../upload" && pwd)"         # deploy/upload
BL="$WEB/blocklists"
API="${1:?Pfad zu api_v2.php}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Upload = Originale
for f in api_v2_honeypot.php api_v2_threat_passwords.php api_v2_threat_feed.php api_v2_openapi.json honeypot/hp_stats_lib.php honeypot/stats.php \
  honeypot/password.php bots/honeypot_cron.php bots/honeypot_lists.php bots/honeypot_passwords.php; do
  cmp -s "$WEB/$f" "$UP/web/$f" || { echo "deploy/upload/web/$f weicht von deploy/web ab"; exit 1; }
done
cmp -s "$BL/site/bots/blocklist/honeypot_score.php" "$UP/web/bots/blocklist/honeypot_score.php" || { echo "upload honeypot_score.php weicht ab"; exit 1; }
cmp -s "$SQL/honeypot_h6.sql" "$UP/datenbank.sql" || { echo "upload/datenbank.sql weicht von deploy/sql/honeypot_h6.sql ab"; exit 1; }

R="$STAGE/hp6i"; W="$R/web58/web"
mkdir -p "$W/honeypot" "$W/bots/blocklist" "$W/blocklists" "$R/tests" "$R/sql"
# echte api_v2.php mit den live vorhandenen require-Zeilen vor dem Start-Block (H2-H5), H6 nur ueber api_v2_honeypot.php
cat > "$STAGE/patch.py" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
n = "// ===================================================================\n//  Start\n"
p = s.rfind(n)
assert p >= 0, "Start-Block nicht gefunden"
sys.stdout.write(s[:p] + "require __DIR__ . '/api_v2_honeypot.php';\nrequire __DIR__ . '/api_v2_threat.php';\nrequire __DIR__ . '/api_v2_honeypot_stats.php';\nrequire __DIR__ . '/api_v2_threat_watch.php';\n\n" + s[p:])
PY
python "$STAGE/patch.py" "$API" > "$W/api_v2.php"
grep -q "api_v2_threat_watch.php" "$W/api_v2.php"
cp "$UP"/web/*.php "$UP/web/api_v2_openapi.json" "$W/"
cp "$WEB/api_v2_threat.php" "$WEB/api_v2_honeypot_stats.php" "$WEB/api_v2_threat_watch.php" "$W/"
cp "$UP"/web/honeypot/*.php "$W/honeypot/"
cp "$HP/hp_release_lib.php" "$HP/hp_limits_lib.php" "$W/honeypot/"
cp "$UP"/web/bots/*.php "$W/bots/"
cp "$WEB/bots/honeypot_lists_index.php" "$W/bots/"
cp "$UP/web/bots/blocklist/honeypot_score.php" "$W/bots/blocklist/"
cp "$HERE/dbconnect_stub.php" "$W/dbconnect.php"
cp "$HERE/header_stub.php" "$W/header.php"
cp "$HP/tests/footer_stub.php" "$W/footer.php"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$R/tests/"
cp "$SQL/honeypot.sql" "$SQL/honeypot_h3_scoring.sql" "$SQL/honeypot_h3_release.sql" "$SQL/honeypot_h4_stats.sql" "$SQL/honeypot_h5.sql" "$UP/datenbank.sql" "$R/sql/"

ssh agentbox 'rm -rf /tmp/hp6i'
scp -q -r "$R" agentbox:/tmp/

ssh agentbox 'bash -s' <<'REMOTE'
set -u
cleanup() {
  docker rm -f -v hp6i-php hp6i-db >/dev/null 2>&1 || true
  docker network rm hp6i-net >/dev/null 2>&1 || true
  docker rmi hp6i-php:latest >/dev/null 2>&1 || true
  rm -rf /tmp/hp6i
}
trap cleanup EXIT
docker network create hp6i-net >/dev/null
docker run -d --name hp6i-db --network hp6i-net -e MARIADB_ROOT_PASSWORD=hp6itest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t hp6i-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec hp6i-db mysql -uroot -php6itest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
M="docker exec -i hp6i-db mysql -uroot -php6itest ipv64"
$M < /tmp/hp6i/tests/setup.sql
for f in honeypot.sql honeypot_h3_scoring.sql honeypot_h3_release.sql honeypot_h4_stats.sql honeypot_h5.sql datenbank.sql datenbank.sql; do
  $M < /tmp/hp6i/sql/$f || echo "FEHLER beim Einspielen von $f"
done
echo "--- Tabellen"; docker exec hp6i-db mysql -uroot -php6itest ipv64 -N -e "SHOW TABLES LIKE 'hp\_%'" | tr '\n' ' '; echo
D=/var/www/clients/client1/web58
docker run -d --name hp6i-php --network hp6i-net -e HP6ITEST=1 -v /tmp/hp6i/web58:$D -v /tmp/hp6i/tests:/w/tests -w $D/web hp6i-php:latest \
  php -S 0.0.0.0:8080 -t $D/web >/dev/null
sleep 1
for f in $(cd /tmp/hp6i/web58/web && find . -name '*.php' | sort) /w/tests/run_tests.php; do
  case "$f" in /*) p="$f" ;; *) p="$D/web/${f#./}" ;; esac
  docker exec hp6i-php php -l "$p" | grep -v '^No syntax errors' || true
done
docker exec -e HP6ITEST=1 hp6i-php php /w/tests/run_tests.php http://127.0.0.1:8080 $D/web; rc=$?
echo "--- Server-Log (Warnungen/Fehler)"; docker logs hp6i-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | grep -v 'hp_list_changes_off\|hp_list_changes.*doesn' | head -30 || true
exit $rc
REMOTE
