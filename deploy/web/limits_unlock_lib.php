<?php
/**
 * Limits nach einem Account-Upgrade sofort wieder freigeben (auch nach einer Klassenaenderung von Hand in der
 * Datenbank: bots/limits_unlock.php prueft alle 5 Minuten ueber honeypot_cron.php). Geprueft wird immer gegen die
 * aktuelle Klasse; frei wird nur, was jetzt wieder unter dem Limit liegt.
 *
 * In account.php direkt nach dem Upgrade (nach add_log "Account Upgrade"):
 *     include_once __DIR__ . '/limits_unlock_lib.php'; ipv64_limits_unlock($pdo, (int)$userid);
 *
 * - CDN64 (neu): wegen Traffic gesperrte Namen wieder aktiv (die Server holen die Konfiguration alle 10 s).
 * - Cloud Router (VPN): wegen Traffic gedrosselte Gateways wie beim Monatswechsel freigeben (vpn_bot setzt es um).
 * - Healthchecks (alt): Hinweis-Merker zuruecksetzen; wegen des Limits pausierte Checks sind von Hand pausierten nicht
 *   zu unterscheiden und bleiben pausiert.
 * - Healthchecks 2.0: erledigen die hubs selbst (gesperrte Accounts lesen ihr Limit alle 30 s neu).
 * - CDN (alt): beim Limit abgeschaltete Proxys/Portmapper lassen sich nicht sicher wiederherstellen (vorheriger
 *   Zustand unbekannt) und bleiben aus.
 * Liefert, was freigegeben wurde (fuer Log/Ausgabe).
 */
function ipv64_limits_unlock(PDO $pdo, int $userid): array {
	$done = array();
	$one = function(string $sql, array $a) use ($pdo) { $st = $pdo->prepare($sql); $st->execute($a); return $st->fetch(PDO::FETCH_ASSOC) ?: array(); };
	$run = function(string $sql, array $a) use ($pdo) { $st = $pdo->prepare($sql); $st->execute($a); return $st->rowCount(); };
	$log = function(string $area, string $text) use ($pdo, $userid) { if(function_exists('add_log')) { add_log($pdo, $userid, '0', $area, $text); } };
	$class = $one("SELECT c.* FROM users u JOIN user_class c ON c.id = u.user_class WHERE u.id = :u", array('u' => $userid));
	if(!$class) { return $done; }
	$me = $one("SELECT * FROM users WHERE id = :u", array('u' => $userid));

	// CDN64: Traffic des Monats (altes und neues CDN zusammen, in MB) gegen das Klassenlimit, wie api_v2_cdn64o.php
	try {
		$limitMB = (int)($class['cdn_traffic'] ?? 0) * 1024;
		$t = $one("SELECT COALESCE(SUM(bytes_in + bytes_out), 0) b FROM cdn64o_traffic WHERE userid = :u AND day >= :d", array('u' => $userid, 'd' => date('Y-m-01')));
		$usedMB = (float)($me['cdn_traffic_input'] ?? 0) + (float)($me['cdn_traffic_output'] ?? 0) + (float)($t['b'] ?? 0) / 1048576;
		if($limitMB > 0 AND $usedMB < $limitMB) {
			$st = $pdo->prepare("SELECT id FROM cdn64o_hosts WHERE userid = :u AND status = 'blocked' AND blocked_reason = 'traffic'");
			$st->execute(array('u' => $userid));
			foreach($st->fetchAll(PDO::FETCH_ASSOC) as $h) {
				$run("UPDATE cdn64o_hosts SET status = 'active', blocked_reason = '' WHERE id = :h", array('h' => $h['id']));
				$run("INSERT INTO cdn64o_events (host_id, userid, kind, message) VALUES (:h, :u, 'unblocked', 'account upgrade: traffic available again')", array('h' => $h['id'], 'u' => $userid));
				$done['cdn64'] = ($done['cdn64'] ?? 0) + 1;
			}
			if(!empty($done['cdn64'])) { $log('CDN64', 'Account upgrade: ' . $done['cdn64'] . ' name(s) unblocked (traffic available again).'); }
		}
	} catch(Throwable $e) { $done['cdn64_error'] = $e->getMessage(); }

	// Cloud Router (VPN): wie der Monatswechsel (traffic_limit 2 = Drossel aufheben, vpn_bot setzt es um)
	try {
		if((int)($me['vpn_limit_reached'] ?? 0) === 1) {
			$usedGB = ((float)($me['vpn_traffic_input'] ?? 0) + (float)($me['vpn_traffic_output'] ?? 0)) / 1024 / 1024 / 1024;
			if($usedGB <= (float)($class['vpn_traffic'] ?? 0)) {
				$n = $run("UPDATE vpn_gateways SET traffic_limit = 2, actions = 'edit', status = 0 WHERE userid = :u AND traffic_limit = 1", array('u' => $userid));
				$run("UPDATE users SET vpn_limit_reached = 0 WHERE id = :u", array('u' => $userid));
				$done['vpn'] = $n;
				$log('Cloud Router', 'Account upgrade: VPN traffic limit lifted (' . $n . ' gateway(s)).');
			}
		}
	} catch(Throwable $e) { $done['vpn_error'] = $e->getMessage(); }

	// Healthchecks (alt): Hinweis-Merker, damit ein spaeteres Erreichen des neuen Limits wieder gemeldet wird
	try {
		$lim = (int)($class['healthcheck_update_limit'] ?? 0);
		if((int)($me['htu_info'] ?? 0) === 1 AND ($lim === 0 OR (int)($me['healthcheck_updates'] ?? 0) < $lim)) {
			$run("UPDATE users SET htu_info = 0 WHERE id = :u", array('u' => $userid));
			$done['healthchecks_info'] = 1;
		}
	} catch(Throwable $e) { $done['healthchecks_error'] = $e->getMessage(); }
	return $done;
}
