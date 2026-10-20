#!/bin/bash
# Honeypot64 H3 (Bewertung + Listen): Pruefung in einer abgeschotteten Umgebung auf der Testbox (ssh agentbox).
# Eigene Container/Netz/Image mit Praefix hp3a-, Test-DB mit Test-Passwort; am Ende wird alles entfernt.
# Andere Container auf der Box werden nicht angefasst. Der Webroot liegt im Container wie live unter
# /var/www/clients/client1/web58/web (die Skripte binden dbconnect.php mit diesem Pfad ein), private/ daneben.
#   bash run_agentbox.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WEB="$(cd "$HERE/../../.." && pwd)"          # deploy/web
SQL="$(cd "$WEB/../sql" && pwd)"             # deploy/sql
BL="$WEB/blocklists"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

R="$STAGE/hp3a"; W="$R/web58/web"
mkdir -p "$W/honeypot" "$W/bots/blocklist" "$W/blocklists/countries" "$R/web58/private" "$R/tests" "$R/sql"
cp "$BL/live.php" "$W/blocklists/"
cp "$BL/site/v64_blocklists.php" "$W/"
cp "$BL/site/bots/blocklist/honeypot_score.php" "$BL/site/bots/blocklist/create_blocklists_v2.php" "$W/bots/blocklist/"
cp "$WEB/honeypot/index.php" "$WEB/honeypot/token.php" "$W/honeypot/"
cp "$HERE/dbconnect_stub.php" "$W/dbconnect.php"
cp "$HERE/header_stub.php" "$W/header.php"
cp "$HERE/footer_stub.php" "$W/footer.php"
cp "$HERE/router.php" "$R/tests/"
cp "$HERE/run_tests.php" "$HERE/setup.sql" "$R/tests/"
cp "$SQL/honeypot.sql" "$SQL/honeypot_h3_scoring.sql" "$R/sql/"

ssh agentbox 'rm -rf /tmp/hp3a'
scp -q -r "$R" agentbox:/tmp/

ssh agentbox 'bash -s' <<'REMOTE'
set -u
cleanup() {
  docker rm -f -v hp3a-php hp3a-db >/dev/null 2>&1 || true
  docker network rm hp3a-net >/dev/null 2>&1 || true
  docker rmi hp3a-php:latest >/dev/null 2>&1 || true
  rm -rf /tmp/hp3a
}
trap cleanup EXIT
docker network create hp3a-net >/dev/null
docker run -d --name hp3a-db --network hp3a-net -e MARIADB_ROOT_PASSWORD=hp3atest -e MARIADB_DATABASE=ipv64 mariadb:10.5 >/dev/null
printf 'FROM php:8.3-cli\nRUN docker-php-ext-install pdo_mysql >/dev/null\n' | docker build -q -t hp3a-php:latest - >/dev/null
for i in $(seq 1 60); do docker exec hp3a-db mysql -uroot -php3atest -e 'SELECT 1' ipv64 >/dev/null 2>&1 && break; sleep 1; done
docker exec -i hp3a-db mysql -uroot -php3atest ipv64 < /tmp/hp3a/tests/setup.sql
docker exec -i hp3a-db mysql -uroot -php3atest ipv64 < /tmp/hp3a/sql/honeypot.sql
docker exec -i hp3a-db mysql -uroot -php3atest ipv64 < /tmp/hp3a/sql/honeypot_h3_scoring.sql
docker exec -i hp3a-db mysql -uroot -php3atest ipv64 < /tmp/hp3a/sql/honeypot_h3_scoring.sql   # mehrfach ausfuehrbar
echo "--- Tabellen"; docker exec hp3a-db mysql -uroot -php3atest ipv64 -N -e "SHOW TABLES LIKE 'hp\_%'" | tr '\n' ' '; echo
D=/var/www/clients/client1/web58
docker run -d --name hp3a-php --network hp3a-net -e HP3ATEST=1 -v /tmp/hp3a/web58:$D -v /tmp/hp3a/tests:/w/tests -w $D/web hp3a-php:latest \
  php -S 0.0.0.0:8080 -t $D/web /w/tests/router.php >/dev/null
sleep 1
for f in $D/web/blocklists/live.php $D/web/v64_blocklists.php $D/web/bots/blocklist/honeypot_score.php $D/web/bots/blocklist/create_blocklists_v2.php \
  $D/web/honeypot/index.php $D/web/honeypot/token.php /w/tests/run_tests.php /w/tests/router.php; do
  docker exec hp3a-php php -l "$f" | grep -v '^No syntax errors' || true
done
docker exec -e HP3ATEST=1 hp3a-php php /w/tests/run_tests.php http://127.0.0.1:8080 $D/web; rc=$?
echo "--- Server-Log (Warnungen/Fehler)"; docker logs hp3a-php 2>&1 | grep -iE 'error|warning|notice|deprecated' | head -20 || true
exit $rc
REMOTE
