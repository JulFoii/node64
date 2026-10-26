<?php
/**
 * DNS Failover mit den neuen Healthchecks (hc2): Monitore lesen ihren Zustand aus ipv64_hc.hc2_checks statt aus der
 * alten Tabelle healthchecks. Genutzt von dns_failover.php und bots/failover_checker.php.
 *
 * Schalter FAILOVER_HC2 (vor dem Einbinden definieren, sonst aus):
 *   false  nur die alten Healthchecks – Verhalten wie bisher
 *   true   neue Healthchecks zuerst, alte als Rueckfall, solange es sie gibt (gleicher Token, dns_failover_monitors bleibt)
 *
 * Die Zeilen haben das Format der alten Tabelle (healthtoken, healthname, status, last_update_time, type,
 * status_stabilize), damit die Aufrufer unveraendert bleiben. Status wie bisher: 0 neu, 1 online, 2 pausiert,
 * 3 Warnung, 4 offline, 5 stabilisiert sich. Der Failover zaehlt nur 1 und 4.
 */
defined('FAILOVER_HC2') || define('FAILOVER_HC2', false); // Umstieg auf die neuen Healthchecks: hier true setzen (gilt fuer Seite und Bot)

/** Zustand eines hc2-Checks als Status der alten Tabelle. */
function failover_hc2_status(string $state, int $paused): string {
	if ($paused) { return '2'; }
	switch ($state) {
		case 'up': return '1';
		case 'down': return '4';
		case 'degraded': case 'flapping': case 'dependent': return '3'; // weder online noch offline: loest nichts aus
		case 'stabilizing': return '5';
		case 'paused': return '2';
		default: return '0'; // pending, unbekannt
	}
}

/** Verbindung zur hc2-Datenbank (null = nicht eingeschaltet oder nicht erreichbar). */
function failover_hc2_pdo(): ?PDO {
	if (!FAILOVER_HC2) { return null; }
	if (!function_exists('hc2_pdo')) { @include_once(__DIR__ . '/dbconnect_hc2.php'); }
	if (!function_exists('hc2_pdo')) { return null; }
	try { return hc2_pdo(); } catch (Throwable $e) { return null; }
}

/**
 * Checks eines Nutzers im Format der alten Tabelle healthchecks; $token: nur dieser Check. Mit FAILOVER_HC2 kommen die
 * neuen Healthchecks zuerst, ein alter Check mit demselben Token wird dann nicht noch einmal geliefert.
 */
function failover_checks(PDO $pdo, int $userid, ?string $token = null): array {
	$out = array();
	if ($hc = failover_hc2_pdo()) {
		try {
			$db = HC2_DB;
			$sql = "SELECT token, name, type, state, paused, last_check_at FROM `$db`.hc2_checks WHERE userid = :u AND deleted_at IS NULL"
				. ($token !== null ? " AND token = :t" : "") . " ORDER BY name";
			$st = $hc->prepare($sql);
			$st->execute($token !== null ? array('u' => $userid, 't' => $token) : array('u' => $userid));
			foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
				$status = failover_hc2_status((string)$r['state'], (int)$r['paused']);
				// Name maskiert: dns_failover.php gibt ihn ungefiltert aus
				$out[$r['token']] = array('id' => 'hc2:' . $r['token'], 'healthtoken' => $r['token'], 'healthname' => htmlspecialchars((string)$r['name'], ENT_QUOTES), 'type' => $r['type'],
					'status' => $status, 'status_stabilize' => $status === '5' ? 1 : 0, 'hc2' => 1,
					// hc2 speichert UTC, die alten Seiten rechnen in Ortszeit
					'last_update_time' => $r['last_check_at'] ? date('Y-m-d H:i:s', strtotime($r['last_check_at'] . ' UTC')) : '');
			}
		} catch (Throwable $e) {
			// hc2 nicht lesbar: nur die alten Healthchecks
		}
	}
	$sql = "SELECT id, healthtoken, healthname, type, status, status_stabilize, last_update_time FROM healthchecks WHERE userid = :u"
		. ($token !== null ? " AND healthtoken = :t" : "");
	$st = $pdo->prepare($sql);
	$st->execute($token !== null ? array('u' => $userid, 't' => $token) : array('u' => $userid));
	foreach ($st->fetchAll(PDO::FETCH_ASSOC) as $r) {
		if (!isset($out[$r['healthtoken']])) { $r['hc2'] = 0; $r['status'] = (string)$r['status']; $out[$r['healthtoken']] = $r; }
	}
	return array_values($out);
}

/** Ein Check (null = gibt es nicht bzw. gehoert nicht diesem Nutzer). */
function failover_check(PDO $pdo, int $userid, string $token): ?array {
	if ($token === '') { return null; }
	$rows = failover_checks($pdo, $userid, $token);
	return $rows ? $rows[0] : null;
}
