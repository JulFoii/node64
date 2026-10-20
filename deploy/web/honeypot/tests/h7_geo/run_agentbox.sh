#!/bin/bash
# Honeypot64 "Herkunft der Angreifer" (Teil ipv64): Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz/Image mit Praefix hp7g-, Test-DB mit Test-Passwort; am Ende wird alles entfernt. Andere Container
# auf der Box werden nicht angefasst. Webroot wie live unter /var/www/clients/client1/web58/web (Generator und Bewertung
# binden dbconnect.php mit diesem Pfad ein).
# Prueft vorher, dass deploy/upload dieselben Dateien wie deploy/web bzw. deploy/sql enthaelt, und spielt deploy/upload/datenbank.sql ein.
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php> [--real]     (--real: zusaetzlich echte RIR-Daten, Groesse/Laufzeit)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HP="$(cd "$HERE/../.." && pwd)"            # deploy/web/honeypot
WEB="$(cd "$HP/.." && pwd)"                # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"           # deploy/sql
UP="$(cd "$WEB/../upload" && pwd)"         # deploy/upload
BL="$WEB/blocklists"
API="${1:?Pfad zu api_v2.php}"
REAL="${2:-}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Upload = Originale
for f in api_v2_openapi.json honeypot/hp_stats_lib.php honeypot/stats.php; do
  cmp -s "$WEB/$f" "$UP/web/$f" || { echo "deploy/upload/web/$f weicht von deploy/web ab"; exit 1; }
done
for f in create_blocklists_v2.php honeypot_score.php; do
  cmp -s "$BL/site/bots/blocklist/$f" "$UP/web/bots/blocklist/$f" || { echo "upload $f weicht ab"; exit 1; }
done
cmp -s "$SQL/honeypot_h7_geo.sql" "$UP/datenbank.sql" || { echo "upload/datenbank.sql weicht von deploy/sql/honeypot_h7_geo.sql ab"; exit 1; }
[ "$(cd "$UP" && find . -type f | wc -l)" = 7 ] || { echo "deploy/upload: unerwartete Dateien"; (cd "$UP" && find . -type f); exit 1; }
python -c "import json,sys; s=open(sys.argv[1],encoding='utf-8').read(); assert s==json.dumps(json.loads(s),indent=2,ensure_ascii=False)+'\n'" "$UP/web/api_v2_openapi.json"

R="$STAGE/hp7g"; W="$R/web58/web"
mkdir -p "$W/honeypot" "$W/bots/blocklist" "$W/blocklists/countries" "$R/web58/private" "$R/tests" "$R/sql"
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
cp "$UP/web/api_v2_openapi.json" "$W/"
cp "$WEB"/api_v2_honeypot.php "$WEB"/api_v2_threat.php "$WEB"/api_v2_honeypot_stats.php "$WEB"/api_v2_threat_watch.php "$WEB"/api_v2_threat_passwords.php "$WEB"/api_v2_threat_feed.php "$W/"
cp "$UP"/web/honeypot/*.php "$W/honeypot/"
cp "$HP/hp_release_lib.php" "$HP/hp_limits_lib.php" "$HP/ip.php" "$W/honeypot/"
cp "$WEB/bots/honeypot_cron.php" "$WEB/bots/honeypot_lists_index.php" "$W/bots/"
cp "$UP"/web/bots/blocklist/*.php "$W/bots/blocklist/"
cp "$BL/bots/read_countries_rir.php" "$W/bots/blocklist/"
cp "$HERE/dbconnect_stub.php" "$W/dbconnect.php"
cp "$HERE/header_stub.php" "$W/header.php"
cp "$HP/tests/footer_stub.php" "$W/footer.php"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$R/tests/"
cp "$SQL/honeypot.sql" "$SQL/honeypot_h3_scoring.sql" "$SQL/honeypot_h3_release.sql" "$SQL/honeypot_h4_stats.sql" "$SQL/honeypot_h5.sql" "$SQL/honeypot_h6.sql" "$UP/datenbank.sql" "$R/sql/"

ssh agentbox 'rm -rf /tmp/hp7g'
scp -q -r "$R" agentbox:/tmp/

ssh agentbox "REAL='$REAL' bash -s" <<'REMOTE'
set -u
cleanup() {
  docker rm -f -v hp7g-php hp7g-db >/dev/null 2>&1 || true
  docker network rm hp7g-net >/dev/null 2>&1 || true
  docker rmi hp7g-php:latest >/dev/null 2>&1 || true
  rm -rf /tmp/hp7g
}
trap cleanup EXIT
docker network create hp7g-net >/dev/null
docker run -d --name hp7g-db --network hp7g-net -e MARIADB_ROOT_PASSWORD=hp7gtest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t hp7g-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec hp7g-db mysql -uroot -php7gtest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
M="docker exec -i hp7g-db mysql -uroot -php7gtest ipv64"
$M < /tmp/hp7g/tests/setup.sql
for f in honeypot.sql honeypot_h3_scoring.sql honeypot_h3_release.sql honeypot_h4_stats.sql honeypot_h5.sql honeypot_h6.sql datenbank.sql datenbank.sql; do
  $M < /tmp/hp7g/sql/$f || echo "FEHLER beim Einspielen von $f"
done
chmod -R a+rwX /tmp/hp7g
D=/var/www/clients/client1/web58
docker run -d --name hp7g-php --network hp7g-net -e HP7GTEST=1 -v /tmp/hp7g/web58:$D -v /tmp/hp7g/tests:/w/tests -v /tmp/hp7g/sql:/w/sql -w $D/web hp7g-php:latest \
  php -S 0.0.0.0:8080 -t $D/web >/dev/null
sleep 1
for f in $(cd /tmp/hp7g/web58/web && find . -name '*.php' | sort) /w/tests/run_tests.php; do
  case "$f" in /*) p="$f" ;; *) p="$D/web/${f#./}" ;; esac
  docker exec hp7g-php php -l "$p" | grep -v '^No syntax errors' || true
done
docker exec -e HP7GTEST=1 hp7g-php php -d memory_limit=1024M /w/tests/run_tests.php http://127.0.0.1:8080 $D/web $REAL; rc=$?
echo "--- Server-Log (Warnungen/Fehler)"; docker logs hp7g-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -30 || true
exit $rc
REMOTE
