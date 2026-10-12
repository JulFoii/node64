<?php
/** Healthchecks 2.0 – Störungen des Accounts (offen und vergangen). */
ob_start(); // header.php gibt HTML aus; hc2_redirect()/hc2_json() verwerfen es
include("../header.php");
require_once(__DIR__ . '/hc2_lib.php');
hc2_require_login();
$uid = (int)$userid; $pdo = hc2_pdo(); $nodes = hc2_nodes($uid);
$names = array(); foreach (hc2_checks($uid) as $c) { $names[$c['token']] = $c['name']; }
$days = (int)($_GET['days'] ?? 30); if (!in_array($days, array(7, 30, 90, 365), true)) { $days = 30; }
$open = (string)($_GET['open'] ?? '') === '1';
$st = $pdo->prepare("SELECT * FROM hc2_incidents WHERE userid = :u AND (started_at >= UTC_TIMESTAMP() - INTERVAL $days DAY OR ended_at IS NULL)" . ($open ? " AND ended_at IS NULL" : "") . " ORDER BY ended_at IS NULL DESC, started_at DESC LIMIT 500");
$st->execute(array('u' => $uid)); $list = $st->fetchAll(PDO::FETCH_ASSOC);
$sumDown = 0; $openCount = 0;
foreach ($list as $i) { if (!$i['ended_at']) { $openCount++; } $sumDown += max(0, strtotime(($i['ended_at'] ?: gmdate('Y-m-d H:i:s')) . ' UTC') - strtotime($i['started_at'] . ' UTC')); }
?>
<p></p>
<div class="container">
	<?php echo hc2_subnav('incidents'); ?>
	<div class="card shadow-sm mb-3">
		<div class="card-header p-2 d-flex flex-wrap align-items-center" style="gap:.5rem"><span><i class="fa-solid fa-triangle-exclamation"></i> Störungen</span>
			<span class="badge badge-<?php echo $openCount ? 'danger' : 'success'; ?>"><?php echo $openCount; ?> offen</span><span class="badge badge-light"><?php echo count($list); ?> in <?php echo $days; ?> Tagen · gesamt <?php echo hc2_dur($sumDown); ?></span>
			<form method="get" class="form-inline ml-auto" style="gap:.3rem"><select class="custom-select custom-select-sm" name="days" onchange="this.form.submit()"><?php foreach (array(7, 30, 90, 365) as $d) { echo '<option value="' . $d . '"' . ($days === $d ? ' selected' : '') . '>' . $d . ' Tage</option>'; } ?></select><div class="custom-control custom-checkbox"><input class="custom-control-input" type="checkbox" id="open" name="open" value="1"<?php echo $open ? ' checked' : ''; ?> onchange="this.form.submit()"><label class="custom-control-label" for="open">nur offene</label></div></form></div>
		<div class="table-responsive"><table class="table table-sm table-hover mb-0">
			<thead><tr><th>Check</th><th>Beginn</th><th>Ende</th><th>Dauer</th><th>Grund</th><th>Messstellen</th></tr></thead><tbody>
			<?php if (!$list) { echo '<tr><td colspan="6" class="text-muted p-3">Keine Störungen im Zeitraum.</td></tr>'; } ?>
			<?php foreach ($list as $i) { $dur = max(0, strtotime(($i['ended_at'] ?: gmdate('Y-m-d H:i:s')) . ' UTC') - strtotime($i['started_at'] . ' UTC')); ?>
			<tr><td><a href="<?php echo HC2_BASE; ?>/check.php?token=<?php echo hc2_h($i['token']); ?>"><?php echo hc2_h($names[$i['token']] ?? ($i['token'] . ' (gelöscht)')); ?></a></td>
				<td class="small text-nowrap"><?php echo hc2_dt($i['started_at']); ?></td><td class="small text-nowrap"><?php echo $i['ended_at'] ? hc2_dt($i['ended_at']) : '<span class="badge badge-danger">offen</span>'; ?></td>
				<td class="small text-nowrap"><?php echo hc2_dur($dur); ?></td><td class="small"><?php echo hc2_h(hc2_reason_text($i['reason'])); echo $i['message'] ? ' – ' . hc2_h(mb_substr($i['message'], 0, 120)) : ''; ?></td>
				<td class="small"><?php $sl = array(); foreach (explode(',', (string)$i['sources']) as $s) { if ($s !== '') { $sl[] = hc2_source_label($s, $nodes); } } echo hc2_h(implode(', ', $sl)); ?></td></tr>
			<?php } ?>
			</tbody></table></div>
	</div>
</div>
<?php include("../footer.php"); ?>
