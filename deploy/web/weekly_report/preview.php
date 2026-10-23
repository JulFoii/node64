<?php
/**
 * IPv64.net – Wochenbericht: Vorschau und Testmail (nur Admins, users.admin = 1).
 *   ?u=<id>&lang=de|en   Bericht dieses Accounts ansehen (Standard: der eigene)
 *   POST send=1          denselben Bericht als Testmail an die eigene Adresse schicken
 * Zeigt dazu die Verteilung ueber die Woche und den Stand dieser Woche.
 */
include('../header.php');
require_once __DIR__ . '/lib.php';
$h = function($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
if (!isset($account) || (string)($account['admin'] ?? '0') !== '1') {
	echo '<div class="container"><div class="alert alert-warning mt-3">Nur für Admins.</div></div>';
	include('../footer.php');
	exit;
}
if (empty($_SESSION['wr_csrf'])) { $_SESSION['wr_csrf'] = bin2hex(random_bytes(16)); }
$now = time();
$uid = (int)($_GET['u'] ?? $account['id']);
$d = wr_collect($pdo, $uid, $now);
if ($d !== null && in_array($_GET['lang'] ?? '', array('de', 'en'), true)) { $d['lang'] = $_GET['lang']; }
$msg = '';
if ($d !== null && ($_POST['send'] ?? '') === '1') {
	if (!hash_equals($_SESSION['wr_csrf'], (string)($_POST['csrf'] ?? ''))) { $msg = '<div class="alert alert-danger">Sitzung abgelaufen.</div>'; }
	else {
		$err = wr_send($pdo, $d, (string)$account['email']);
		$msg = $err === '' ? '<div class="alert alert-success">Testmail an ' . $h($account['email']) . ' geschickt.</div>' : '<div class="alert alert-danger">Nicht gesendet: ' . $h($err) . '</div>';
	}
}
$m = $d !== null ? wr_render($d, wr_token($pdo, $uid)) : null;
// Verteilung und Stand dieser Woche
$per = array_fill(0, 7, 0); $on = 0;
foreach ($pdo->query("SELECT id FROM users WHERE weekly_report = 1 AND account_status = '1'")->fetchAll(PDO::FETCH_COLUMN) as $id) { $per[intdiv(wr_slot((int)$id), WR_HOURS)]++; $on++; }
$week = wr_week($now); $done = array(0, 0, 0);
$st = $pdo->prepare("SELECT ok, COUNT(*) FROM weekly_report_log WHERE week = :w GROUP BY ok"); $st->execute(array('w' => $week));
foreach ($st->fetchAll(PDO::FETCH_NUM) as $r) { $done[(int)$r[0]] = (int)$r[1]; }
$slot = wr_slot($uid); $days = array('Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So');
?>
<div class="container-fluid">
	<h4 class="mt-3"><i class="fa-solid fa-envelope-open-text"></i> Wochenbericht – Vorschau</h4>
	<?php echo $msg; ?>
	<div class="row">
		<div class="col-lg-4 pb-3">
			<div class="card shadow-sm"><div class="card-header p-2">Account und Testmail</div><div class="card-body small">
				<form method="get" class="form-inline mb-2">
					<label class="mr-2">User-ID</label><input class="form-control form-control-sm mr-2" style="width:7rem" type="number" name="u" value="<?php echo (int)$uid; ?>">
					<select class="custom-select custom-select-sm mr-2" name="lang"><option value="">Sprache des Accounts</option><option value="de"<?php echo ($_GET['lang'] ?? '') === 'de' ? ' selected' : ''; ?>>Deutsch</option><option value="en"<?php echo ($_GET['lang'] ?? '') === 'en' ? ' selected' : ''; ?>>English</option></select>
					<button class="btn btn-sm btn-outline-primary">Anzeigen</button>
				</form>
				<?php if ($d === null) { ?><div class="alert alert-warning">Account unbekannt oder gesperrt.</div><?php } else { ?>
				<p class="mb-1">Termin: <b><?php echo $days[intdiv($slot, WR_HOURS)] . ', ' . (WR_FIRST_HOUR + $slot % WR_HOURS); ?> Uhr</b> · Wochenbericht
					<?php $st = $pdo->prepare("SELECT weekly_report FROM users WHERE id = :u"); $st->execute(array('u' => $uid)); echo (int)$st->fetchColumn() === 1 ? '<span class="badge badge-success">an</span>' : '<span class="badge badge-secondary">aus</span>'; ?></p>
				<?php if (!wr_has_content($d)) { ?><p class="text-warning mb-1">Ohne Dienste – dieser Account bekäme keine Mail.</p><?php } ?>
				<?php if ($d['errors']) { echo '<p class="text-danger mb-1">' . $h(implode('; ', $d['errors'])) . '</p>'; } ?>
				<p class="mb-2">Betreff: <b><?php echo $h($m['subject']); ?></b></p>
				<form method="post"><input type="hidden" name="csrf" value="<?php echo $h($_SESSION['wr_csrf']); ?>"><input type="hidden" name="send" value="1">
					<button class="btn btn-sm btn-primary"><i class="fa-solid fa-paper-plane"></i> Testmail an <?php echo $h($account['email']); ?></button></form>
				<?php } ?>
				<hr>
				<p class="mb-1">Eingeschaltet: <b><?php echo $on; ?></b> Accounts · je Tag (Mo–So): <?php echo implode(' · ', $per); ?></p>
				<p class="mb-0">Woche <?php echo $h($week); ?>: <?php echo $done[1]; ?> gesendet, <?php echo $done[2]; ?> ohne Dienste, <?php echo $done[0]; ?> Fehler</p>
			</div></div>
			<?php if ($m) { ?><div class="card shadow-sm mt-3"><div class="card-header p-2">Textteil</div><div class="card-body p-2"><pre class="small mb-0" style="white-space:pre-wrap"><?php echo $h($m['text']); ?></pre></div></div><?php } ?>
		</div>
		<div class="col-lg-8 pb-3">
			<?php if ($m) { ?><div class="card shadow-sm"><div class="card-header p-2">HTML-Teil</div>
				<iframe title="Vorschau" sandbox="" style="width:100%;height:1400px;border:0" srcdoc="<?php echo $h($m['html']); ?>"></iframe></div><?php } ?>
		</div>
	</div>
</div>
<?php include('../footer.php'); ?>
