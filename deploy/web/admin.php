<?php
/**
 * IPv64.net – Admin: Nutzer verwalten (eine Seite, nur fuer Admins, users.admin = 1 aus der Datenbank).
 * Suche nach ID, E-Mail oder Domain; je Nutzer Profil, Statistik, Domains, Log; Klasse und Laufzeit, Sperren,
 * Freischalten, Sitzungen beenden, 2FA zuruecksetzen, Traffic zuruecksetzen (CDN alt/neu, Cloud Router), Domains
 * loeschen, Account loeschen, Login als Nutzer.
 * Alle Aktionen per POST mit CSRF-Token aus der Sitzung, im Admin-Protokoll (admin_audit) und neutral im Log des
 * Nutzers. Logik: admin_lib.php.
 */
include("header.php");
require_once __DIR__ . '/admin_lib.php';

header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

$admId = (isset($userid) AND (string)$userid !== '' AND (string)$userid !== '0') ? (int)$userid : 0;
echo '<p></p><div class="container-fluid" style="max-width:1400px">';
if(!adm_is_admin($pdo, $admId)) {
	echo '<div class="alert alert-danger">Kein Zugriff. Diese Seite ist nur für Admins.</div></div>';
	include("footer.php");
	exit;
}
adm_cleanup_links($pdo);
if(empty($_SESSION['adm_csrf'])) { $_SESSION['adm_csrf'] = bin2hex(random_bytes(16)); }
$csrf = (string)$_SESSION['adm_csrf'];
$self = 'admin';
$msg = array();
$ok = function($t) use (&$msg) { $msg[] = array('success', $t); };
$bad = function($t) use (&$msg) { $msg[] = array('danger', $t); };
$uid = (int)($_POST['uid'] ?? $_GET['uid'] ?? 0);
$q = trim((string)($_GET['q'] ?? ''));

// ---------------------------------------------------------------- Aktionen
if(($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
	$act = (string)($_POST['action'] ?? '');
	$target = $uid > 0 ? adm_user($pdo, $uid) : null;
	$protected = $target !== null && ((string)$target['admin'] === '1') && $uid !== $admId; // andere Admins: nur ansehen
	if(!hash_equals($csrf, (string)($_POST['csrf'] ?? ''))) {
		$bad('Sitzung abgelaufen, bitte Seite neu laden.');
	} elseif($target === null) {
		$bad('Nutzer nicht gefunden.');
	} elseif($protected && !in_array($act, array('class', 'reset_cdn_old', 'reset_cdn64', 'reset_vpn'), true)) {
		$bad('Andere Admins lassen sich hier nicht sperren, löschen oder übernehmen.');
	} else {
		$email = (string)$target['email'];
		switch($act) {
		case 'class':
			$class = (int)($_POST['user_class'] ?? 0);
			$until = (string)($_POST['valid_until'] ?? '');
			if(($m = (int)($_POST['extend'] ?? 0)) > 0) { $until = adm_extend_until($target['class_valid_until'], $m); }
			elseif($until !== '') { $until .= ' 23:59:59'; }
			$dl = ($_POST['domainlimit'] ?? '') === '' ? null : (int)$_POST['domainlimit'];
			if(adm_set_class($pdo, $uid, $class, $until, $dl)) {
				$cn = (string)(adm_one($pdo, "SELECT name FROM user_class WHERE id = :c", array('c' => $class))['name'] ?? $class);
				$d = 'Klasse ' . $cn . ' bis ' . date('d.m.Y', strtotime($until)) . ($dl !== null ? ', Domainlimit ' . $dl : '');
				adm_audit($pdo, $admId, $uid, 'class', $d);
				adm_userlog($pdo, $uid, 'Account-Klasse durch den Support gesetzt: ' . $d . '.');
				$ok('Gespeichert: ' . $d . '.');
			} else { $bad('Klasse oder Datum ungültig.'); }
			break;
		case 'block':
			$neutral = !empty($_POST['neutralize']);
			adm_set_status($pdo, $uid, 2);
			$n = $neutral ? adm_neutralize_dns($pdo, $uid) : 0;
			adm_audit($pdo, $admId, $uid, 'block', ($neutral ? $n . ' A/AAAA-Einträge entschärft; ' : '') . trim(mb_substr((string)($_POST['reason'] ?? ''), 0, 300)));
			adm_userlog($pdo, $uid, 'Account durch den Support gesperrt.');
			$ok('Account gesperrt und abgemeldet' . ($neutral ? ', ' . $n . ' DNS-Einträge entschärft' : '') . '.');
			break;
		case 'unblock':
		case 'activate':
			adm_set_status($pdo, $uid, 1);
			adm_audit($pdo, $admId, $uid, $act);
			adm_userlog($pdo, $uid, $act === 'unblock' ? 'Account durch den Support entsperrt.' : 'Account durch den Support freigeschaltet.');
			$ok($act === 'unblock' ? 'Account entsperrt.' : 'Account freigeschaltet.');
			break;
		case 'logout':
			adm_logout($pdo, $uid);
			adm_audit($pdo, $admId, $uid, 'logout');
			$ok('Sitzung des Nutzers beendet.');
			break;
		case 'reset_2fa':
			$n = adm_reset_2fa($pdo, $uid);
			adm_audit($pdo, $admId, $uid, 'reset_2fa', $n . ' Schlüssel');
			adm_userlog($pdo, $uid, 'Zwei-Faktor-Anmeldung durch den Support zurückgesetzt.');
			$ok('2FA zurückgesetzt (' . $n . ' Schlüssel entfernt).');
			break;
		case 'reset_cdn_old':
		case 'reset_cdn64':
		case 'reset_vpn':
			$tr = adm_traffic($pdo, $target);
			if($act === 'reset_vpn') {
				$n = adm_reset_vpn($pdo, $uid);
				adm_audit($pdo, $admId, $uid, $act, round($tr['vpn_gb'], 2) . ' GB' . ($tr['vpn_limited'] ? ', gedrosselt' : '') . ', ' . $n . ' Gateway(s) freigegeben');
				adm_userlog($pdo, $uid, 'Cloud-Router-Traffic des Monats durch den Support zurückgesetzt.');
				$ok('Cloud-Router-Traffic zurückgesetzt (' . round($tr['vpn_gb'], 2) . ' GB)' . ($n ? ', ' . $n . ' Gateway(s) freigegeben' : '') . '.');
			} else {
				$old = $act === 'reset_cdn_old';
				$was = $old ? $tr['cdn_old_gb'] : (float)$tr['cdn64_gb'];
				$n = $old ? adm_reset_cdn_old($pdo, $uid) : adm_reset_cdn64($pdo, $uid);
				adm_audit($pdo, $admId, $uid, $act, round($was, 2) . ' GB, ' . $n . ' CDN64-Name(n) entsperrt');
				adm_userlog($pdo, $uid, ($old ? 'CDN-Traffic (altes CDN)' : 'CDN64-Traffic') . ' des Monats durch den Support zurückgesetzt.');
				$ok(($old ? 'Traffic altes CDN' : 'Traffic CDN64') . ' zurückgesetzt (' . round($was, 2) . ' GB)' . ($n ? ', ' . $n . ' CDN64-Name(n) wieder aktiv' : '') . '.');
			}
			break;
		case 'delete_domain':
			$did = (int)($_POST['domain_id'] ?? 0);
			$dn = adm_one($pdo, "SELECT subdomainname, maindomain, owndomain FROM subdomains WHERE id = :d AND userid = :u", array('d' => $did, 'u' => $uid));
			if($dn !== null && adm_delete_domain($pdo, $uid, $did)) {
				$name = $dn['subdomainname'] . ((string)$dn['owndomain'] === '0' && $dn['maindomain'] !== '' ? '.' . $dn['maindomain'] : '');
				adm_audit($pdo, $admId, $uid, 'delete_domain', $name);
				adm_userlog($pdo, $uid, 'Domain ' . $name . ' durch den Support gelöscht.');
				$ok('Domain ' . $name . ' gelöscht.');
			} else { $bad('Domain nicht gefunden.'); }
			break;
		case 'delete_domains':
			$n = adm_delete_domains($pdo, $uid);
			adm_audit($pdo, $admId, $uid, 'delete_domains', $n . ' Domains');
			adm_userlog($pdo, $uid, 'Alle Domains durch den Support gelöscht.');
			$ok($n . ' Domains mit allen DNS-Einträgen gelöscht.');
			break;
		case 'delete_account':
			if(strtolower(trim((string)($_POST['confirm_email'] ?? ''))) !== strtolower($email)) {
				$bad('Zur Bestätigung bitte die E-Mail-Adresse des Nutzers genau eingeben.');
			} elseif($uid === $admId) {
				$bad('Den eigenen Account bitte unter „Account“ löschen.');
			} else {
				adm_delete_account($pdo, $uid);
				adm_audit($pdo, $admId, $uid, 'delete_account', $email);
				$ok('Account #' . $uid . ' (' . $email . ') mit allem gelöscht. Zahlungen bleiben für die Buchhaltung erhalten.');
				$uid = 0;
			}
			break;
		case 'login_as':
			if($uid === $admId) { $bad('Das ist dein eigener Account.'); break; }
			if(adm_login_as($pdo, $admId, $uid, (string)($_SESSION['session_id'] ?? ''))) {
				adm_audit($pdo, $admId, $uid, 'login_as');
				adm_userlog($pdo, $uid, 'Anmeldung durch den Support.');
				echo '<div class="alert alert-info">Angemeldet als ' . adm_h($email) . ' – zurück über „Zurück in den eigenen Account“ auf der Account-Seite.</div>';
				echo '<meta http-equiv="refresh" content="1; URL=https://ipv64.net/account"></div>';
				include("footer.php");
				exit;
			}
			$bad('Anmeldung als Nutzer nicht möglich (Sitzung oder Datenbank).');
			break;
		default:
			$bad('Unbekannte Aktion.');
		}
	}
}

$classes = adm_classes($pdo);
$user = $uid > 0 ? adm_user($pdo, $uid) : null;
$form = function(string $action, string $inner, string $cls = 'd-inline', string $confirm = '') use ($csrf, $uid, $self): string {
	$c = $confirm !== '' ? ' onsubmit="return confirm(\'' . adm_h(addslashes($confirm)) . '\')"' : '';
	return '<form method="post" action="' . $self . '?uid=' . $uid . '" class="' . $cls . '"' . $c . '><input type="hidden" name="csrf" value="' . adm_h($csrf) . '">'
		. '<input type="hidden" name="uid" value="' . $uid . '"><input type="hidden" name="action" value="' . adm_h($action) . '">' . $inner . '</form>';
};
$statusBadge = function($s): string {
	return array('0' => '<span class="badge badge-secondary">nicht freigeschaltet</span>', '1' => '<span class="badge badge-success">aktiv</span>',
		'2' => '<span class="badge badge-danger">gesperrt</span>')[(string)$s] ?? '<span class="badge badge-light">' . adm_h($s) . '</span>';
};
$fmt = function($t): string { return ($t === null || $t === '' || strpos((string)$t, '0000') === 0) ? '–' : date('d.m.Y H:i', strtotime((string)$t)); };
?>
<div class="d-flex flex-wrap align-items-center mb-3">
	<h3 class="mb-0 mr-3"><i class="fa-solid fa-user-shield"></i> Admin – Nutzer</h3>
	<form method="get" action="<?php echo $self; ?>" class="form-inline flex-grow-1">
		<input class="form-control mr-2 flex-grow-1" style="max-width:520px" name="q" value="<?php echo adm_h($q); ?>" placeholder="ID, E-Mail (auch Teil) oder Domain" autofocus>
		<button class="btn btn-primary" type="submit"><i class="fa-solid fa-magnifying-glass"></i> Suchen</button>
	</form>
</div>
<?php foreach($msg as $m) { echo '<div class="alert alert-' . $m[0] . '">' . adm_h($m[1]) . '</div>'; } ?>

<?php if($q !== '') { $res = adm_search($pdo, $q); ?>
<div class="card shadow mb-3"><div class="card-header"><?php echo count($res); ?> Treffer<?php echo count($res) >= ADM_SEARCH_LIMIT ? ' (gekürzt, genauer suchen)' : ''; ?></div>
<div class="table-responsive"><table class="table table-sm table-hover mb-0">
	<thead><tr><th>ID</th><th>E-Mail</th><th>Status</th><th>Klasse</th><th>gültig bis</th><th>Registriert</th><th>Letzter Login</th></tr></thead><tbody>
	<?php foreach($res as $r) { ?>
	<tr onclick="location.href='<?php echo $self; ?>?uid=<?php echo (int)$r['id']; ?>'" style="cursor:pointer">
		<td><?php echo (int)$r['id']; ?></td>
		<td><a href="<?php echo $self; ?>?uid=<?php echo (int)$r['id']; ?>"><?php echo adm_h($r['email']); ?></a><?php echo (string)$r['admin'] === '1' ? ' <span class="badge badge-dark">Admin</span>' : ''; ?><?php echo !empty($r['via_domain']) ? ' <span class="badge badge-info">über Domain</span>' : ''; ?></td>
		<td><?php echo $statusBadge($r['account_status']); ?></td>
		<td><?php echo adm_h($r['class_name'] ?? $r['user_class']); ?></td>
		<td><?php echo $fmt($r['class_valid_until']); ?></td>
		<td><?php echo $fmt($r['reg_date']); ?></td>
		<td><?php echo $fmt($r['last_login']); ?></td>
	</tr>
	<?php } if(!$res) { echo '<tr><td colspan="7" class="text-muted">Nichts gefunden.</td></tr>'; } ?>
	</tbody></table></div></div>
<?php } ?>

<?php if($user !== null) {
	$isAdmin = (string)$user['admin'] === '1';
	$self2 = $uid === $admId;
	$stats = adm_stats($pdo, $uid);
	$domains = adm_domains($pdo, $uid);
	$twofa = $stats['2FA-Schlüssel'] ?? 0;
	$traffic = adm_traffic($pdo, $user);
?>
<div class="row">
	<div class="col-xl-5">
		<div class="card shadow mb-3">
			<div class="card-header d-flex align-items-center"><strong>#<?php echo $uid; ?> · <?php echo adm_h($user['email']); ?></strong>
				<span class="ml-2"><?php echo $statusBadge($user['account_status']); ?><?php echo $isAdmin ? ' <span class="badge badge-dark">Admin</span>' : ''; ?><?php echo (string)$user['moderator'] === '1' ? ' <span class="badge badge-info">Moderator</span>' : ''; ?></span></div>
			<div class="card-body">
				<dl class="row mb-0 small">
					<dt class="col-5">Klasse</dt><dd class="col-7"><span class="badge badge-warning"><?php echo adm_h($user['class_name'] ?? $user['user_class']); ?></span> bis <?php echo $fmt($user['class_valid_until']); ?><?php echo strtotime((string)$user['class_valid_until']) < time() && (int)$user['user_class'] > 1 ? ' <span class="badge badge-danger">abgelaufen</span>' : ''; ?></dd>
					<dt class="col-5">Registriert</dt><dd class="col-7"><?php echo $fmt($user['reg_date']); ?></dd>
					<dt class="col-5">Letzter Login</dt><dd class="col-7"><?php echo $fmt($user['last_login']); ?><?php echo (string)$user['sessionid'] !== '' ? ' <span class="badge badge-success">angemeldet</span>' : ''; ?></dd>
					<dt class="col-5">2FA</dt><dd class="col-7"><?php echo $twofa ? '<span class="badge badge-success">aktiv (' . (int)$twofa . ')</span>' : '<span class="badge badge-light">aus</span>'; ?></dd>
					<dt class="col-5">Domainlimit</dt><dd class="col-7"><?php echo (int)$user['domainlimit']; ?></dd>
					<dt class="col-5">Updates DynDNS / API / Health</dt><dd class="col-7"><?php echo (int)$user['dyndns_updates']; ?> / <?php echo (int)$user['api_updates']; ?> / <?php echo (int)$user['healthcheck_updates']; ?></dd>
					<dt class="col-5">SMS / Meldungen</dt><dd class="col-7"><?php echo (int)$user['sms_count']; ?> / <?php echo (int)$user['notification_count']; ?></dd>
					<dt class="col-5">Traffic VPN / CDN</dt><dd class="col-7"><?php echo round($traffic['vpn_gb'], 2); ?> GB / <?php echo round($traffic['cdn_old_gb'] + (float)$traffic['cdn64_gb'], 2); ?> GB</dd>
					<dt class="col-5">Guthaben</dt><dd class="col-7"><?php echo adm_h($user['guthaben']); ?><?php echo $user['partner_id'] !== '' ? ' · Partner ' . adm_h($user['partner_id']) : ''; ?></dd>
					<dt class="col-5">Newsletter</dt><dd class="col-7"><?php echo (string)$user['newsletter'] === '1' ? 'ja' : 'nein'; ?></dd>
				</dl>
			</div>
		</div>

		<div class="card shadow mb-3">
			<div class="card-header"><i class="fa-solid fa-crown"></i> Klasse und Laufzeit</div>
			<div class="card-body">
				<?php
				$sel = '<select class="custom-select custom-select-sm" name="user_class">';
				foreach($classes as $c) { $sel .= '<option value="' . (int)$c['id'] . '"' . ((int)$c['id'] === (int)$user['user_class'] ? ' selected' : '') . '>' . adm_h($c['name']) . '</option>'; }
				$sel .= '</select>';
				$until = strpos((string)$user['class_valid_until'], '0000') === 0 ? '' : date('Y-m-d', strtotime((string)$user['class_valid_until']));
				echo $form('class', '<div class="form-row">'
					. '<div class="col-md-4 mb-2"><label class="small mb-0">Klasse</label>' . $sel . '</div>'
					. '<div class="col-md-4 mb-2"><label class="small mb-0">gültig bis</label><input type="date" class="form-control form-control-sm" name="valid_until" value="' . adm_h($until) . '"></div>'
					. '<div class="col-md-4 mb-2"><label class="small mb-0">Domainlimit</label><input type="number" min="0" class="form-control form-control-sm" name="domainlimit" value="' . (int)$user['domainlimit'] . '"></div></div>'
					. '<button class="btn btn-sm btn-primary mr-1" type="submit">Speichern</button>'
					. '<span class="small text-muted ml-2 mr-1">oder verlängern:</span>'
					. '<button class="btn btn-sm btn-outline-primary mr-1" type="submit" name="extend" value="1">+1 Monat</button>'
					. '<button class="btn btn-sm btn-outline-primary mr-1" type="submit" name="extend" value="3">+3 Monate</button>'
					. '<button class="btn btn-sm btn-outline-primary" type="submit" name="extend" value="12">+12 Monate</button>'
					. '<div class="small text-muted mt-1">Verlängern rechnet ab dem bisherigen Ende (oder ab heute, falls schon abgelaufen) mit der gewählten Klasse.</div>', 'd-block');
				?>
			</div>
		</div>

		<div class="card shadow mb-3">
			<div class="card-header"><i class="fa-solid fa-gauge-high"></i> Traffic (laufender Monat)</div>
			<div class="card-body">
				<?php
				$gb = function($v) { return $v === null ? '–' : number_format((float)$v, 2, ',', '.') . ' GB'; };
				$trow = function(string $label, string $usage, string $badge, string $act, string $confirm) use ($form) {
					return '<div class="d-flex align-items-center justify-content-between border-bottom py-2"><div class="small"><b>' . $label . '</b><br>' . $usage . $badge . '</div>'
						. $form($act, '<button class="btn btn-sm btn-outline-warning" type="submit"><i class="fa-solid fa-rotate-left"></i> Zurücksetzen</button>', 'd-inline ml-2', $confirm) . '</div>';
				};
				$cdnSum = $traffic['cdn_old_gb'] + (float)$traffic['cdn64_gb'];
				echo $trow('CDN (alt)', $gb($traffic['cdn_old_gb']), '', 'reset_cdn_old', 'Traffic des alten CDN für diesen Monat auf 0 setzen?');
				echo $trow('CDN64 (neu)', $gb($traffic['cdn64_gb']), $traffic['cdn64_blocked'] ? ' <span class="badge badge-danger">' . (int)$traffic['cdn64_blocked'] . ' Name(n) gesperrt</span>' : '', 'reset_cdn64', 'Traffic von CDN64 für diesen Monat auf 0 setzen? Wegen Traffic gesperrte Namen werden wieder aktiv.');
				echo '<div class="small text-muted pt-1 pb-2">Limit beide CDNs zusammen: ' . $gb($cdnSum) . ' von ' . (int)$traffic['cdn_limit_gb'] . ' GB' . ($traffic['cdn_limit_gb'] > 0 && $cdnSum >= $traffic['cdn_limit_gb'] ? ' <span class="badge badge-danger">erreicht</span>' : '') . '</div>';
				echo $trow('Cloud Router (VPN)', $gb($traffic['vpn_gb']) . ' von ' . (int)$traffic['vpn_limit_gb'] . ' GB', $traffic['vpn_limited'] ? ' <span class="badge badge-danger">gedrosselt</span>' : '', 'reset_vpn', 'Cloud-Router-Traffic für diesen Monat auf 0 setzen? Gedrosselte Gateways werden wieder freigegeben.');
				?>
				<div class="small text-muted mt-2">Wie der Monatswechsel, nur für diesen Nutzer. Beim alten CDN bleiben wegen des Limits abgeschaltete Proxys und Portmapper aus – der Nutzer schaltet sie selbst wieder ein. CDN64-Namen und Cloud-Router-Gateways werden sofort freigegeben.</div>
			</div>
		</div>

		<?php if(!$isAdmin || $self2) { ?>
		<div class="card shadow mb-3">
			<div class="card-header"><i class="fa-solid fa-screwdriver-wrench"></i> Aktionen</div>
			<div class="card-body">
				<div class="mb-2">
				<?php if(!$self2) { echo $form('login_as', '<button class="btn btn-sm btn-info mr-1" type="submit"><i class="fa-solid fa-user-secret"></i> Als Nutzer anmelden</button>', 'd-inline', 'Als ' . $user['email'] . ' anmelden? Eine eigene Sitzung des Nutzers endet dabei. Zurück über „Zurück in den eigenen Account“ auf der Account-Seite.'); } ?>
				<?php if((string)$user['account_status'] === '0') { echo $form('activate', '<button class="btn btn-sm btn-success mr-1" type="submit">Freischalten</button>'); } ?>
				<?php if((string)$user['account_status'] === '2') { echo $form('unblock', '<button class="btn btn-sm btn-success mr-1" type="submit">Entsperren</button>', 'd-inline', 'Account entsperren?'); } ?>
				<?php echo $form('logout', '<button class="btn btn-sm btn-outline-secondary mr-1" type="submit">Sitzung beenden</button>'); ?>
				<?php if($twofa) { echo $form('reset_2fa', '<button class="btn btn-sm btn-outline-warning" type="submit">2FA zurücksetzen</button>', 'd-inline', '2FA-Schlüssel des Nutzers entfernen? Er meldet sich danach nur mit Passwort an.'); } ?>
				</div>
				<?php if((string)$user['account_status'] !== '2' && !$self2) { echo $form('block',
					'<div class="input-group input-group-sm mb-1"><input class="form-control" name="reason" maxlength="300" placeholder="Grund (nur im Admin-Protokoll)">'
					. '<div class="input-group-append"><button class="btn btn-warning" type="submit"><i class="fa-solid fa-ban"></i> Sperren</button></div></div>'
					. '<div class="custom-control custom-checkbox small"><input type="checkbox" class="custom-control-input" id="neutralize" name="neutralize" value="1">'
					. '<label class="custom-control-label" for="neutralize">zusätzlich alle A/AAAA-Einträge entschärfen (wie der Abuse-Bot: 1.1.1.1 bzw. Cloudflare)</label></div>',
					'd-block mb-3', 'Account sperren? Der Nutzer wird abgemeldet und kann sich nicht mehr anmelden.'); } ?>
				<?php if(!$self2) { ?>
				<hr>
				<?php echo $form('delete_domains', '<button class="btn btn-sm btn-outline-danger mb-2" type="submit"' . ($domains ? '' : ' disabled') . '><i class="fa-solid fa-globe"></i> Alle ' . count($domains) . ' Domains löschen</button>', 'd-block', 'Alle Domains von ' . $user['email'] . ' mit allen DNS-Einträgen löschen? Das lässt sich nicht rückgängig machen.'); ?>
				<?php echo $form('delete_account',
					'<div class="input-group input-group-sm"><input class="form-control" name="confirm_email" autocomplete="off" placeholder="E-Mail des Nutzers zur Bestätigung">'
					. '<div class="input-group-append"><button class="btn btn-danger" type="submit"><i class="fa-solid fa-skull-crossbones"></i> Account löschen</button></div></div>'
					. '<div class="small text-muted mt-1">Löscht den Account mit allem (Domains, DNS, Checks, Nodes, CDN, Cloud Router, DNS64, Honeypot, Logs) – wie „Account löschen“ des Nutzers. Zahlungen bleiben erhalten.</div>',
					'd-block', 'Account ' . $user['email'] . ' endgültig mit allem löschen?'); ?>
				<?php } ?>
			</div>
		</div>
		<?php } else { ?>
		<div class="alert alert-secondary small">Anderer Admin: nur Klasse/Laufzeit änderbar, keine Sperre, kein Löschen, keine Anmeldung als.</div>
		<?php } ?>
	</div>

	<div class="col-xl-7">
		<div class="card shadow mb-3">
			<div class="card-header"><i class="fa-solid fa-chart-simple"></i> Statistik</div>
			<div class="card-body"><div class="row small">
				<?php foreach($stats as $k => $v) { echo '<div class="col-6 col-md-4 mb-1"><span class="text-muted">' . adm_h($k) . '</span> <strong class="float-right mr-3">' . (int)$v . '</strong></div>'; } ?>
			</div></div>
		</div>

		<div class="card shadow mb-3">
			<div class="card-header"><i class="fa-solid fa-globe"></i> Domains (<?php echo count($domains); ?>)</div>
			<div class="table-responsive" style="max-height:340px;overflow:auto"><table class="table table-sm mb-0 small">
				<thead><tr><th>Name</th><th>Einträge</th><th>Updates</th><th>Letztes Update</th><th>Seit</th><th></th></tr></thead><tbody>
				<?php foreach($domains as $d) {
					$name = $d['subdomainname'] . ((string)$d['owndomain'] === '0' && $d['maindomain'] !== '' ? '.' . $d['maindomain'] : ''); ?>
				<tr><td class="text-monospace"><?php echo adm_h($name); ?><?php echo (string)$d['owndomain'] !== '0' ? ' <span class="badge badge-light">eigene</span>' : ''; ?><?php echo (string)$d['deactivated'] === '1' ? ' <span class="badge badge-secondary">aus</span>' : ''; ?></td>
					<td><?php echo (int)$d['records']; ?></td><td><?php echo (int)$d['update_count']; ?></td><td><?php echo $fmt($d['last_update']); ?></td><td><?php echo $fmt($d['reg_date']); ?></td>
					<td class="text-right"><?php if(!$isAdmin || $self2) { echo $form('delete_domain', '<input type="hidden" name="domain_id" value="' . (int)$d['id'] . '"><button class="btn btn-sm btn-link text-danger p-0" type="submit" title="Löschen"><i class="fa-solid fa-trash"></i></button>', 'd-inline', 'Domain ' . $name . ' mit allen Einträgen löschen?'); } ?></td></tr>
				<?php } if(!$domains) { echo '<tr><td colspan="6" class="text-muted">Keine Domains.</td></tr>'; } ?>
				</tbody></table></div>
		</div>

		<div class="row">
			<div class="col-lg-6">
				<div class="card shadow mb-3"><div class="card-header"><i class="fa-solid fa-receipt"></i> Letzte Zahlungen</div>
					<ul class="list-group list-group-flush small">
					<?php $pays = adm_payments($pdo, $uid); foreach($pays as $p) { echo '<li class="list-group-item py-1">' . $fmt($p['payment_time']) . ' · <span class="text-muted">' . adm_h(mb_substr((string)$p['payment_info'], 0, 80)) . '</span></li>'; }
					if(!$pays) { echo '<li class="list-group-item py-1 text-muted">Keine.</li>'; } ?>
					</ul></div>
			</div>
			<div class="col-lg-6">
				<div class="card shadow mb-3"><div class="card-header"><i class="fa-solid fa-clipboard-list"></i> Admin-Protokoll zu diesem Nutzer</div>
					<ul class="list-group list-group-flush small" style="max-height:220px;overflow:auto">
					<?php $al = adm_audit_list($pdo, $uid, 30); foreach($al as $a) { echo '<li class="list-group-item py-1">' . $fmt($a['created_at'] . ' UTC') . ' · <strong>' . adm_h($a['action']) . '</strong> · ' . adm_h($a['admin_email'] ?? $a['admin_id']) . ($a['details'] !== '' ? '<div class="text-muted">' . adm_h($a['details']) . '</div>' : '') . '</li>'; }
					if(!$al) { echo '<li class="list-group-item py-1 text-muted">Noch nichts.</li>'; } ?>
					</ul></div>
			</div>
		</div>

		<div class="card shadow mb-3"><div class="card-header"><i class="fa-solid fa-list"></i> Letzte Log-Einträge des Nutzers</div>
			<div class="table-responsive" style="max-height:300px;overflow:auto"><table class="table table-sm mb-0 small"><tbody>
			<?php $logs = adm_logs($pdo, $uid, 25); foreach($logs as $l) { echo '<tr><td class="text-nowrap">' . $fmt($l['zeit']) . '</td><td>' . adm_h($l['header']) . '</td><td class="text-muted">' . adm_h(mb_substr((string)$l['content'], 0, 200)) . '</td></tr>'; }
			if(!$logs) { echo '<tr><td class="text-muted">Keine Einträge.</td></tr>'; } ?>
			</tbody></table></div></div>
	</div>
</div>
<?php } elseif($q === '') { ?>
<div class="card shadow mb-3"><div class="card-header"><i class="fa-solid fa-clipboard-list"></i> Admin-Protokoll (letzte Aktionen)</div>
	<div class="table-responsive"><table class="table table-sm mb-0 small"><thead><tr><th>Zeit</th><th>Admin</th><th>Aktion</th><th>Nutzer</th><th>Details</th></tr></thead><tbody>
	<?php $al = adm_audit_list($pdo, 0, 50); foreach($al as $a) {
		echo '<tr><td class="text-nowrap">' . $fmt($a['created_at'] . ' UTC') . '</td><td>' . adm_h($a['admin_email'] ?? $a['admin_id']) . '</td><td><strong>' . adm_h($a['action']) . '</strong></td>'
			. '<td><a href="' . $self . '?uid=' . (int)$a['target_id'] . '">#' . (int)$a['target_id'] . '</a> ' . adm_h($a['target_email'] ?? '(gelöscht)') . '</td><td class="text-muted">' . adm_h($a['details']) . '</td></tr>'; }
	if(!$al) { echo '<tr><td colspan="5" class="text-muted">Noch keine Aktionen (oder Tabelle admin_audit fehlt – SQL aus dem Upload einspielen).</td></tr>'; } ?>
	</tbody></table></div></div>
<?php } ?>
</div>
<?php include("footer.php"); ?>
