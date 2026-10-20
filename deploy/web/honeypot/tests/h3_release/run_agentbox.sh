#!/bin/bash
# Honeypot64 H3 (IP-Auskunft + Freigaben): Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz/Image mit Praefix hp3b-, Test-DB mit Test-Passwort; am Ende wird alles entfernt.
# Andere Container auf der Box werden nicht angefasst.
#   bash run_agentbox.sh <pfad/zu/ipv64net_webseite/api_v2.php>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
HP="$(cd "$HERE/../.." && pwd)"            # deploy/web/honeypot
WEB="$(cd "$HP/.." && pwd)"                # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"           # deploy/sql
API="${1:?Pfad zu api_v2.php}"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Webroot zusammenstellen: echte api_v2.php mit den require-Zeilen vor dem Start-Block (wie in den Einspiel-Anleitungen),
# Stubs fuer dbconnect/header/footer
mkdir -p "$STAGE/hp3b/web/honeypot" "$STAGE/hp3b/web/bots" "$STAGE/hp3b/tests" "$STAGE/hp3b/sql"
cat > "$STAGE/patch.py" <<'PY'
import sys
s = open(sys.argv[1], encoding="utf-8").read().replace("\r\n", "\n")
n = "// ===================================================================\n//  Start\n"
p = s.rfind(n)
assert p >= 0, "Start-Block nicht gefunden"
sys.stdout.write(s[:p] + "require __DIR__ . '/api_v2_honeypot.php';\nrequire __DIR__ . '/api_v2_threat.php';\n\n" + s[p:])
PY
python "$STAGE/patch.py" "$API" > "$STAGE/hp3b/web/api_v2.php"
grep -q "api_v2_threat.php" "$STAGE/hp3b/web/api_v2.php"
cp "$WEB/api_v2_honeypot.php" "$WEB/api_v2_threat.php" "$STAGE/hp3b/web/"
cp "$HP/ip.php" "$HP/admin.php" "$HP/hp_release_lib.php" "$STAGE/hp3b/web/honeypot/"
cp "$WEB/bots/honeypot_release.php" "$STAGE/hp3b/web/bots/"
cp "$HERE/dbconnect_stub.php" "$STAGE/hp3b/web/dbconnect.php"
cp "$HERE/header_stub.php" "$STAGE/hp3b/web/header.php"
cp "$HP/tests/footer_stub.php" "$STAGE/hp3b/web/footer.php"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$STAGE/hp3b/tests/"
cp "$SQL/honeypot.sql" "$SQL/honeypot_h3_release.sql" "$STAGE/hp3b/sql/"

ssh agentbox 'rm -rf /tmp/hp3b'
scp -q -r "$STAGE/hp3b" agentbox:/tmp/

ssh agentbox 'bash -s' <<'REMOTE'
set -u
cleanup() {
  docker rm -f -v hp3b-php hp3b-db >/dev/null 2>&1 || true
  docker network rm hp3b-net >/dev/null 2>&1 || true
  docker rmi hp3b-php:latest >/dev/null 2>&1 || true
  rm -rf /tmp/hp3b
}
trap cleanup EXIT
docker network create hp3b-net >/dev/null
docker run -d --name hp3b-db --network hp3b-net -e MARIADB_ROOT_PASSWORD=hp3btest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t hp3b-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec hp3b-db mysql -uroot -php3btest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
docker exec -i hp3b-db mysql -uroot -php3btest ipv64 < /tmp/hp3b/tests/setup.sql
docker exec -i hp3b-db mysql -uroot -php3btest ipv64 < /tmp/hp3b/sql/honeypot.sql
docker exec -i hp3b-db mysql -uroot -php3btest ipv64 < /tmp/hp3b/sql/honeypot_h3_release.sql
docker exec -i hp3b-db mysql -uroot -php3btest ipv64 < /tmp/hp3b/sql/honeypot_h3_release.sql   # mehrfach ausfuehrbar
echo "--- Tabellen"; docker exec hp3b-db mysql -uroot -php3btest ipv64 -N -e "SHOW TABLES LIKE 'hp\_%'" | tr '\n' ' '; echo
docker run -d --name hp3b-php --network hp3b-net -e HP3BTEST=1 -v /tmp/hp3b:/w -w /w/web hp3b-php:latest php -S 0.0.0.0:8080 -t /w/web >/dev/null
sleep 1
for f in /w/web/api_v2_threat.php /w/web/honeypot/ip.php /w/web/honeypot/admin.php /w/web/honeypot/hp_release_lib.php /w/web/bots/honeypot_release.php /w/tests/run_tests.php; do
  docker exec hp3b-php php -l "$f" | grep -v '^No syntax errors' || true
done
docker exec -e HP3BTEST=1 hp3b-php php /w/tests/run_tests.php http://127.0.0.1:8080 /w/web; rc=$?
echo "--- Server-Log (Warnungen/Fehler)"; docker logs hp3b-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -30 || true
exit $rc
REMOTE
