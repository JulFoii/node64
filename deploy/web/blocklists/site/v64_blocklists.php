<?php 
include("header.php");

?>

 <div class="jumbotron jumbotron-fluid d-none d-xl-block p-3">
	<div class="container">
	  <h1 class="display-3"><img src="https://ipv64.net/img/logo_64.png" height="80" alt="IPv64 Logo" class="mb-3">
	   IPv64 Blocklists - First Level Protection <i class="fa-solid fa-shield-halved text-success"></i></h1>
	  <p class="lead">The <strong>IPv64.net blocklists</strong> make use of the already known and <strong>well-established blocklists</strong> and prepare them for the 
	  further operation of your systems. IPv64 processes the lists and you can easily integrate them into your infrastructure
	  immediately and always up-to-date. </p>

	</div>
  </div>
	<div class="container">
		<div class="row">
		
	  <div class="col-7">
		<div class="card shadow-sm">
		  <div class="card-header">
			<i class="fa-solid fa-microchip text-info"></i>
			IPv64.net Blocklists - Collections</strong>
		  </div>
		  <div class="card-body p-0">
			<table class="table table-striped" style="table-layout: fixed;over-flow: break-word;">
			  <thead>
				<tr>
				  <th scope="col" width="3%"></th>
				  <th scope="col">Source Blocklist</th>
				  <th scope="col">Blocked (IP/Net)</th>
				  <th scope="col">Status | Updated</th>
				  <th scope="col">Link to List</th>
				</tr>
			  </thead>
				  <tbody>
					<tr class="table-info">
					<td><i class="fa-solid fa-crown text-warning"></i>
					<td>v64 Blocker Blocklist
					<td><span class="badge badge-warning">Comming Soon</span>
					<td><span class="badge badge-dark">Comming Soon</span>
					<td><span class="badge badge-dark">Comming Soon</span>
					</tr>
					<?php 
					$statement = $pdo->prepare("SELECT * FROM blocklisten");
					$result = $statement->execute();
					$blocklisten = $statement->fetchAll();
					foreach($blocklisten as $blockliste)
					{	$all_ips += $blockliste["ips"];
					?>
					<tr>
						<td><i class="fa-solid fa-check-double"></i>
						<td><?php echo $blockliste["name"];?>
						<td><span class="badge badge-dark" title="<?php echo $blockliste["ips"];?>"><?php echo formatLargeNumber($blockliste["ips"]);?></span>
						<td><span class="badge badge-success">Ok</span>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/ipv64_blocklist_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="<?php echo $blockliste["name"];?> RAW Format">
						<span class="badge badge-success">All</span></a>
						<?php if($blockliste["db_name"] != "bl_sh_drop_v4" AND $blockliste["db_name"] != "bl_sh_drop_v6") { ?>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v4_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="<?php echo $blockliste["name"];?> Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v6_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="<?php echo $blockliste["name"];?> Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
						<?php } ?>
					</tr>
					<?php
					}
					?>
					<tr class="table-info">
						<td><i class="fa-solid fa-crown text-warning"></i>
						<td>All IPs from all Lists
						<td><span class="badge badge-dark" title="<?php echo $all_ips;?>"><?php echo formatLargeNumber($all_ips);?></span>
						<td><span class="badge badge-success">Ok</span>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/ipv64_blocklist_all.txt" target="_blank" title="IPv64.net All Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<?php if($blockliste["db_name"] != "bl_sh_drop_v4" AND $blockliste["db_name"] != "bl_sh_drop_v6") { ?>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v4_all.txt" target="_blank" title="IPv64.net All Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/ipv64_blocklist_v6_all.txt" target="_blank" title="IPv64.net All Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
						<?php } ?>
					</tr>
					<tr class="table-secondary">
					<td><i class="fa-solid fa-globe"></i>
					<td><strong>Continent Blocklists</strong>
					<td><strong>Blocked (IP/Net)</strong>
					<td><strong>Status | Updated</strong>
					<td><strong>Link to List</strong>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-europe"></i>
						<td>Europe
						<td><span class="badge badge-dark" title="">-/-</span>
						<td><span class="badge badge-success">Ok</span>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_europe.txt" target="_blank" title="Europe Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_europe.txt" target="_blank" title="Europe Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_europe.txt" target="_blank" title="Europe Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-asia"></i>
						<td>Asia
						<td><span class="badge badge-dark" title="">-/-</span>
						<td><span class="badge badge-success">Ok</span>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_asia.txt" target="_blank" title="Asia Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_asia.txt" target="_blank" title="Asia Blocklist only v4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_asia.txt" target="_blank" title="Asia Blocklist only v6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-africa"></i>
						<td>Africa
						<td><span class="badge badge-dark" title="">-/-</span>
						<td><span class="badge badge-success">Ok</span>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_africa.txt" target="_blank" title="Africa Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_africa.txt" target="_blank" title="Africa Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_africa.txt" target="_blank" title="Africa Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr>
						<td><i class="fa-solid fa-earth-americas"></i>
						<td>North America
						<td><span class="badge badge-dark" title="">-/-</span>
						<td><span class="badge badge-success">Ok</span>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td><a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_north_america.txt" target="_blank" title="North America Blocklist RAW Format">
						<span class="badge badge-success">All</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_north_america.txt" target="_blank" title="North America Blocklist only IPv4 RAW Format">
						<span class="badge badge-dark">Only v4</span></a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_north_america.txt" target="_blank" title="North America Blocklist only IPv6 RAW Format">
						<span class="badge badge-secondary">Only v6</span></a>
					</tr>
					<tr class="table-secondary">
					<td><i class="fa-solid fa-flag"></i>
					<td><strong>Countries Blocklists</strong>
					<td><strong>Blocked (IP/Net)</strong>
					<td><strong>Status | Updated</strong>
					<td><strong>Link to List</strong>
					</tr>
					<?php 
					$statement = $pdo->prepare("SELECT * FROM blocklisten_countries ORDER BY country");
					$result = $statement->execute();
					$blocklisten = $statement->fetchAll();
					foreach($blocklisten as $blockliste)
					{
					?>
					<tr>
						<td><!-- <img src="/img/country/<?php echo strtolower($blockliste["country"]);?>.svg" width="20"> -->
						<td><?php echo $blockliste["country_name"];?>
						<td><span class="badge badge-dark" title="<?php echo $blockliste["ips"];?>"><?php echo formatLargeNumber($blockliste["ips"]);?></span>
						<td><span class="badge badge-success">Ok</span>
						<span class="badge badge-primary"> <?php echo timeago2($blockliste["last_updated"],date("Y-m-d H:i:s",time())); ?></span>
						<td>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="IP/Network List for <?php echo $blockliste["country_name"];?>">
						<span class="badge badge-success">All</span>
						</a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v4_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="IP/Network List for <?php echo $blockliste["country_name"];?>">
						<span class="badge badge-dark">Only v4</span>
						</a>
						<a href="https://ipv64.net/blocklists/countries/ipv64_blocklist_v6_<?php echo $blockliste["file_name"];?>.txt" target="_blank" title="IP/Network List for <?php echo $blockliste["country_name"];?>">
						<span class="badge badge-secondary">Only v6</span>
						</a>
					</tr>
					<?php 
					} 
					?>
				</tbody>
			</table>
		  </div>
		</div>
	  </div>
	  <div class="col-5">
	      <div class="card shadow-sm">
			<div class="card-header">
			<i class="fa-solid fa-info text-info"></i>
				Futher Information about IPv64.net Blocklists</strong>
			  </div>
			  <div class="card-body">
				<p>
				The <strong>IPv64.net Blocklists</strong> are various common and already tested blocklists replicated from the Internet. 
				We process these automatically and make them available to you free of charge. 
				</p>
				<p>
				The advantage of these processed blocklists is that they do not contain any comments, notes or other entries, but really 
				only IP addresses and entire subnets. Duplicate and false positive entries have been removed. The automation behind IPv64.net 
				always keeps these lists up to date.
				</p>
				<p>
					<ul><li><a href="v64_blocklist_integration_guide">Read the IPv64 Blocklist integration Guide <i class="fa-solid fa-book"></i></a></li></ul>
				</p>
			  </div>
		  </div>
		  <p></p>
		  <div class="card shadow-sm">
			<div class="card-header">
			<i class="fa-solid fa-info text-info"></i>
				Why should I use blocklists?</strong>
			  </div>
			  <div class="card-body">
				<p>
				Blocklists are in the <strong>"first line of defense"</strong> of your systems. If an attacker can't access your system in the first place 
				or even get as far as it, then you have already achieved 95% of your goal. Of course, there are many other ways into your 
				infrastructure, but this direct route remains completely blocked for third parties. 
				</p>
				<p>
				You need another Blocklist, which should be listed here in this list? Then please write to the forum with all the 
				information you need. At best, directly with a source where this list comes from.
				</p>
				<p>
				<a href="https://v64.tech/c/ipv64-services/v64-secure/9" target="_blank" alt="v64.tech Forum" class="btn btn-sm btn-primary">v64.tech Forum</a>
				</p>
			  </div>
		  </div>
	  </div>
	  </div>
		
		</div>
<div class="bd-masthead mb-3" id="content">
  <div class="container-xxl bd-gutter">
	<div class="col-md-8 mx-auto text-center">
	  <img src="/img/logo_64.png" height="165" alt="IPv64 Logo Minimal" class="d-block mx-auto mb-3">
	  <h1 class="mb-3 fw-semibold lh-1">First Level Protection with IPv64.net</h1>
	  <p class="lead mb-4">
		With IPv64.net you can effectively protect your systems and infrastructures against various attacks from the Internet. 
	  </p>
	</div>
  </div>
</div>
			
			
			
		</div>
	 </div>
	</div>
	</div>
	</div>
<p></p>
<?php 
include("footer.php");
?>
<script>
function hide_show_url() {
  var x = document.getElementById("dau");
    x.classList.toggle("inputdisc");
}
function copy_url1() {
  // Get the text field
  var copyText = document.getElementById("dau");
  // Select the text field
  copyText.select();
  copyText.setSelectionRange(0, 99999); // For mobile devices
   // Copy the text inside the text field
  navigator.clipboard.writeText(copyText.value);
}
</script>