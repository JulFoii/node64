<?php 
include("header.php");
include_once(__DIR__ . "/failover_hc2_lib.php"); //Monitore: alte oder neue Healthchecks (Schalter FAILOVER_HC2)

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\SMTP;
?>
	<?php if($userid != ""){ echo "<p></p>";?>
	<div class="container">
	 <div class="row">
	 <div class="col-12 col-sm-12 <?php echo $a1;?>">
	 <div class="row">
	 
	 <?php 

		$blid = $_GET["edit"];
		
		$statement = $pdo->prepare("SELECT failover_policies,failover_monitors,failover_rules FROM user_class WHERE id = :uid");
		$result = $statement->execute(array('uid' => $account["user_class"]));
		$accountclass = $statement->fetch();
		
		//Policy Pause
		if(isset($_GET["pause"]))
		{	
			$policyhash = htmlspecialchars($_GET["pause"]);
			$statement = $pdo->prepare("SELECT id,status FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :fh");
			$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
			$policy = $statement->fetch();
			if($policy["id"] != "" AND $policy["status"] != 2 AND $policy["status"] != 4 AND $policy["status"] != 5)
			{
				if($policy["status"] == 3){$status = "0";$call = "activated. Failover will be active in a few Seconds. Hold on.";}
				if($policy["status"] == 1 OR $policy["status"] == 0){$status = "3";$call = "paused.";}
				$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status WHERE failover_hash = :policyhash AND userid = :userid");
				$result = $statement->execute(array('status' => $status,'policyhash' => $policyhash,'userid' => $userid));
				
				$infopolicy = "<div class=\"alert alert-success\" role=\"alert\">DNS Failover Policy successful $call</div>";
				echo "<meta http-equiv=\"refresh\" content=\"2; URL=dns_failover\">";
				add_log($pdo,$userid,"0","DNS Failover","DNS Failover Policy successful $call.");
			}else{
				$infopolicy = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
			}
		}
		
		//Policy Manual Failover
		if(isset($_GET["failover"]))
		{	
			$policyhash = htmlspecialchars($_GET["failover"]);
			$statement = $pdo->prepare("SELECT id,status FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :fh");
			$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
			$policy = $statement->fetch();
			if($policy["id"] != "" AND $policy["status"] == 1)
			{
				$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status,manual = :manual WHERE failover_hash = :policyhash AND userid = :userid");
				$result = $statement->execute(array('status' => "4",'manual' => "1",'policyhash' => $policyhash,'userid' => $userid));
				
				$infopolicy = "<div class=\"alert alert-success\" role=\"alert\">DNS Failover was initiated. Hold on a few Seconds.</div>";
				echo "<meta http-equiv=\"refresh\" content=\"2; URL=dns_failover\">";
				add_log($pdo,$userid,"0","DNS Failover","DNS Failover was initiated manually. $policy[name]");
			}else{
				$infopolicy = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
			}
		}
		
		//Policy Manual Failover
		if(isset($_GET["fallback"]))
		{	
			$policyhash = htmlspecialchars($_GET["fallback"]);
			$statement = $pdo->prepare("SELECT id,status FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :fh");
			$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
			$policy = $statement->fetch();
			if($policy["id"] != "" AND $policy["status"] == 2)
			{
				$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status,manual = :manual WHERE failover_hash = :policyhash AND userid = :userid");
				$result = $statement->execute(array('status' => "5",'manual' => "1",'policyhash' => $policyhash,'userid' => $userid));
				
				$infopolicy = "<div class=\"alert alert-success\" role=\"alert\">DNS Fallback was initiated. Hold on a few Seconds.</div>";
				echo "<meta http-equiv=\"refresh\" content=\"2; URL=dns_failover\">";
				add_log($pdo,$userid,"0","DNS Fallback","DNS Fallback was initiated manually. $policy[name]");
			}else{
				$infopolicy = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
			}
		}
		
		//Add Policy
		if(isset($_GET["new"]))
		{	
			$statement = $pdo->prepare("SELECT count(id) as count FROM dns_failover_policies WHERE userid = :userid");
			$result = $statement->execute(array('userid' => $userid));
			$policy_limit = $statement->fetch();
			if($accountclass["failover_policies"] > $policy_limit["count"])
			{
				$chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
				$hash = substr(str_shuffle($chars),0,16);
				$statement = $pdo->prepare("INSERT INTO dns_failover_policies (userid,failover_hash) VALUES (:userid,:failover_hash)");
				$result = $statement->execute(array('userid'=> $userid,'failover_hash'=> $hash));
				$infopolicy = "<div class=\"alert alert-success\" role=\"alert\">New DNS Failover Policy successful created.</div>";
				echo "<meta http-equiv=\"refresh\" content=\"2; URL=dns_failover\">";
				add_log($pdo,$userid,"0","DNS Failover","Added new DNS Failover policy.");
			}else{
				$infopolicy = "<div class=\"alert alert-warning\" role=\"alert\">DNS Failover Policy Limit reached.</div>";
			}
		}
		
		//DELETE Policy
		if(isset($_GET["del"]))
		{	
			$policyhash = htmlspecialchars($_GET["del"]);
			$statement = $pdo->prepare("SELECT id,status FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :fh");
			$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
			$policy = $statement->fetch();
			if($policy["id"] != "" AND $policyhash != "" AND $policy["status"] != 2 AND $policy["status"] != 4 AND $policy["status"] != 5)
			{
				$statement = $pdo->prepare("DELETE FROM dns_failover_monitors WHERE userid = :userid AND failover_hash = :fh");
				$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
				$statement = $pdo->prepare("DELETE FROM dns_failover_rules WHERE userid = :userid AND failover_hash = :fh");
				$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
				$statement = $pdo->prepare("DELETE FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :fh");
				$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
				$infopolicy = "<div class=\"alert alert-success\" role=\"alert\">DNS Failover Policy successful deleted.</div>";
				add_log($pdo,$userid,"0","DNS Failover","DNS Failover policy deleted.");
			}else{
				$infopolicy = "<div class=\"alert alert-warning\" role=\"alert\">Permissions denied.</div>";
			}
		}

		
		if(isset($_GET["edit"]))
		{
			$policyhash = htmlspecialchars($_GET["edit"]);
			$statement = $pdo->prepare("SELECT id,status,failover_hash FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :fh");
			$result = $statement->execute(array('userid' => $userid,'fh' => $policyhash));
			$policy = $statement->fetch();
				
			if(isset($_GET["savegen"]))
			{
				$policyname = htmlspecialchars($_POST["policyname"]);
				$failovertype = htmlspecialchars($_POST["failovertype"]);
				$fallback_rule = htmlspecialchars($_POST["fallback_rule"]);
				if(!is_numeric($failovertype)){$failovertype = 0;}
				if(!is_numeric($fallback_rule)){$fallback_rule = 0;}
				
				$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :policyhash");
				$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
				$policy = $statement->fetch();
				if($policy["id"] != "" AND $policyname != "")
				{
					$statement = $pdo->prepare("UPDATE dns_failover_policies set name = :name, failover_type = :failover_type, fallback_rule = :fallback_rule WHERE failover_hash = :policyhash AND userid = :userid");
					$result = $statement->execute(array('name' => "$policyname",'failover_type' => "$failovertype",'fallback_rule' => "$fallback_rule",'policyhash' => $policyhash,'userid' => $userid));
					$setinfo = "<div class=\"alert alert-success\" role=\"alert\">Failover Settings saved.</div>";
				}else{
					$setinfo = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
				}
			}
			
			if(isset($_GET["saveinte"]))
			{
				$integration = implode(",",$_POST["integration"]);
				$disable_noti = htmlspecialchars($_POST["disable_noti"]);
				if(!is_numeric($disable_noti)){$disable_noti = 0;}
				
				$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :policyhash");
				$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
				$policy = $statement->fetch();
				if($policy["id"] != "")
				{
					$statement = $pdo->prepare("UPDATE dns_failover_policies set integration = :integration,disable_notifications = :disable_noti WHERE failover_hash = :policyhash AND userid = :userid");
					$result = $statement->execute(array('integration' => "$integration",'disable_noti' => "$disable_noti",'policyhash' => $policyhash,'userid' => $userid));
					$setinfo2 = "<div class=\"alert alert-success\" role=\"alert\">Integration Settings saved.</div>";
				}else{
					$setinfo2 = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
				}
			}
			
			if(isset($_GET["addhealthcheck"]))
			{
				$healthcheck = htmlspecialchars($_POST["healthcheck"]);
				$negate = $_POST["negate"];
				$linking = $_POST["linking"];
				if($negate != 1){$negate = 0;}
				if($linking != "and" AND $linking != "or"){$linking = "and";}
				
				if($policy["status"] != 2 AND $policy["status"] != 4 AND $policy["status"] != 5)
				{
					if($policy["status"] == 3){$status = 3;}else{$status = 0;}

				//Limits
				$statement = $pdo->prepare("SELECT count(id) as count FROM dns_failover_monitors WHERE userid = :userid");
				$result = $statement->execute(array('userid' => $userid));
				$hc_limit = $statement->fetch();
				if($accountclass["failover_monitors"] > $hc_limit["count"])
				{
				
				$hc = failover_check($pdo, (int)$userid, (string)$healthcheck) ?: array('id' => '', 'healthname' => '');
				$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :policyhash");
				$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
				$policy = $statement->fetch();
				$statement = $pdo->prepare("SELECT id FROM dns_failover_monitors WHERE userid = :userid AND BINARY healthtoken = :healthtoken AND failover_hash = :fh");
				$result = $statement->execute(array('userid' => $userid,'healthtoken' => $healthcheck,'fh' => $policyhash));
				$monitor = $statement->fetch();
				if($monitor == "" AND $policy["id"] != "" AND $hc["id"] != "" AND $healthcheck != "")
				{
						$statement = $pdo->prepare("INSERT INTO dns_failover_monitors (userid,failover_hash,healthtoken,negate) 
							VALUES (:userid,:failover_hash,:healthtoken,:negate)");
						$result = $statement->execute(array(
							'userid'=> $userid,
							'failover_hash'=> "$policyhash",
							'healthtoken'=> $healthcheck,
							'negate'=> $negate
							));
						$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status,linking = :linking WHERE failover_hash = :policyhash");
						$result = $statement->execute(array('status' => $status,'linking' => "$linking",'policyhash' => $policyhash));
					$monitorinfo = "<div class=\"alert alert-success\" role=\"alert\">Healthcheck added to DNS Failover Monitor. Failover active in a few seconds.</div>";
					add_log($pdo,$userid,"0","DNS Failover Monitor","Added new DNS Failover Monitor Healthcheck: $hc[healthname]");
				}else{
					$monitorinfo = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
				}
				}else{
					$monitorinfo = "<div class=\"alert alert-warning\" role=\"alert\">Monitor Limit exceeded.</div>";
				}
				}else{
					$monitorinfo = "<div class=\"alert alert-danger\" role=\"alert\">Do not any Changes while in Failover Mode.</div>";
				}
			}
			if(isset($_GET["delhealthcheck"]))
			{
				$hc = htmlspecialchars($_GET["delhealthcheck"]);
				if($policy["status"] != 2 AND $policy["status"] != 4 AND $policy["status"] != 5)
				{
					if($policy["status"] == 3){$status = 3;}else{$status = 0;}
				$statement = $pdo->prepare("SELECT * FROM dns_failover_monitors WHERE userid = :userid AND healthtoken = :healthtoken AND failover_hash = :fh");
				$result = $statement->execute(array('userid' => $userid,'healthtoken' => $hc,'fh' => $policyhash));
				$monitor = $statement->fetch();
				if($monitor["id"] != "")
				{
					$statement = $pdo->prepare("DELETE FROM dns_failover_monitors WHERE userid = :userid AND healthtoken = :healthtoken AND failover_hash = :fh");
					$result = $statement->execute(array('userid' => $userid,'healthtoken' => $hc,'fh' => $policyhash));
					$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status WHERE failover_hash = :policyhash");
						$result = $statement->execute(array('status' => $status,'policyhash' => $policyhash));
					$monitorinfo = "<div class=\"alert alert-success\" role=\"alert\">Healthcheck from DNS Failover Monitor removed.</div>";
					add_log($pdo,$userid,"0","DNS Failover Monitor","Removed DNS Failover Monitor");
				}else{
					$monitorinfo = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
				}
				}else{
					$monitorinfo = "<div class=\"alert alert-danger\" role=\"alert\">Do not any Changes while in Failover Mode.</div>";
				}
			}
			if(isset($_GET["addrule"]))
			{
				$subdomain_record = htmlspecialchars($_POST["subdomain_record"]);
				if(strlen($subdomain_record) == 32) 
				{
				$dst_record = htmlspecialchars($_POST["dst_record"]);
				$failoverdest = htmlspecialchars($_POST["failoverdest"]);
				if($policy["status"] != 2 AND $policy["status"] != 4 AND $policy["status"] != 5)
				{
					if($policy["status"] == 3){$status = 3;}else{$status = 0;}
				$statement = $pdo->prepare("SELECT count(id) as count FROM dns_failover_rules WHERE userid = :userid");
				$result = $statement->execute(array('userid' => $userid));
				$hc_limit = $statement->fetch();
				if($accountclass["failover_rules"] > $hc_limit["count"])
				{
				//Dst oder IP ?
				if(!filter_var($failoverdest, FILTER_VALIDATE_IP) AND strlen($dst_record) == 32)
				{	
					$statement = $pdo->prepare("SELECT content,id,record_key FROM subdomain_records WHERE userid = :userid AND record_key = :rk");
					$result = $statement->execute(array('userid' => $userid,'rk' => $dst_record));
					$sdst_record = $statement->fetch();
					if($sdst_record["id"] != ""){$failoverdest = $sdst_record["content"];$rec = 1;}
				}
				if(filter_var($failoverdest, FILTER_VALIDATE_IP))
				{
					//DNS Rule 
					$statement = $pdo->prepare("SELECT id FROM dns_failover_rules WHERE userid = :userid AND subdomain_record_key = :subdomain_record");
					$result = $statement->execute(array('userid' => $userid,'subdomain_record' => $subdomain_record));
					$recordkey = $statement->fetch();
					if($recordkey["id"] == "")
					{
						$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND record_key = :subdomain_record");
						$result = $statement->execute(array('userid' => $userid,'subdomain_record' => $subdomain_record));
						$record = $statement->fetch();
						$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :policyhash");
						$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
						$policy = $statement->fetch();
						if($record["id"] != "" AND $policy["id"] != "" AND $failoverdest != "" AND $subdomain_record != $dst_record)
						{
							if(($record["type"] == "A" AND filter_var($failoverdest, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) OR 
							($record["type"] == "AAAA" AND filter_var($failoverdest, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)))
							{
								if($rec == 1){$failoverdest = $sdst_record["record_key"];}
								$statement = $pdo->prepare("INSERT INTO dns_failover_rules (userid,failover_hash,subdomain_record_key,content,subdomain_id,record_id) 
									VALUES (:userid,:failover_hash,:subdomain_record_key,:content,:subdomain_id,:record_id)");
								$result = $statement->execute(array(
									'userid'=> $userid,
									'failover_hash'=> "$policyhash",
									'subdomain_record_key'=> $subdomain_record,
									'content'=> $failoverdest,
									'subdomain_id'=> $record["subdomain_id"],
									'record_id'=> $record["id"]
									));
								$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status WHERE failover_hash = :policyhash");
								$result = $statement->execute(array('status' => $status,'policyhash' => $policyhash));
								$ruleinfo = "<div class=\"alert alert-success\" role=\"alert\">Rule added to DNS Failover Policy. Failover active in a few seconds.</div>";
								add_log($pdo,$userid,"0","DNS Failover Rule","Added new DNS Failover Rule.");
							}else{
								$ruleinfo = "<div class=\"alert alert-warning\" role=\"alert\">No valid IP-Address entered.</div>";
							}
						}else{
							$ruleinfo = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
						}
					}else{
					$ruleinfo = "<div class=\"alert alert-warning\" role=\"alert\">DNS Record already exists in another failover policy.</div>";
					}
				}else{
					$ruleinfo = "<div class=\"alert alert-warning\" role=\"alert\">No valid IP address entered</div>";
				}
				}else{
					$ruleinfo = "<div class=\"alert alert-warning\" role=\"alert\">Rules Limit exceeded.</div>";
				}
				}else{
					$ruleinfo = "<div class=\"alert alert-danger\" role=\"alert\">Do not any Changes while in Failover Mode.</div>";
				}
				}else{
					$ruleinfo = "<div class=\"alert alert-danger\" role=\"alert\">Permission denied.</div>";
				}
			}
			if(isset($_GET["addrule_offline"]))
			{
				$subdomain_record = htmlspecialchars($_POST["subdomain_record"]);
				if(strlen($subdomain_record) == 32) 
				{
				$dst_offline_page = htmlspecialchars($_POST["dst_offline_page"]);

				if($policy["status"] != 2 AND $policy["status"] != 4 AND $policy["status"] != 5)
				{
					if($policy["status"] == 3){$status = 3;}else{$status = 0;}
				$statement = $pdo->prepare("SELECT count(id) as count FROM dns_failover_rules WHERE userid = :userid");
				$result = $statement->execute(array('userid' => $userid));
				$hc_limit = $statement->fetch();
				if($accountclass["failover_rules"] > $hc_limit["count"])
				{
				//Dst oder IP ? EGAL ist ja eine Page 
					//DNS Rule 
					$statement = $pdo->prepare("SELECT id FROM dns_failover_rules WHERE userid = :userid AND subdomain_record_key = :subdomain_record");
					$result = $statement->execute(array('userid' => $userid,'subdomain_record' => $subdomain_record));
					$recordkey = $statement->fetch();
					if($recordkey["id"] == "")
					{
						$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND record_key = :subdomain_record");
						$result = $statement->execute(array('userid' => $userid,'subdomain_record' => $subdomain_record));
						$record = $statement->fetch();
						$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :policyhash");
						$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
						$policy = $statement->fetch();
						if($record["id"] != "" AND $policy["id"] != "" AND $dst_offline_page != "")
						{
							if($record["type"] == "A"){$failoverdest = "188.34.152.170";}
							if($record["type"] == "AAAA"){$failoverdest = "2a01:4f8:c013:5959::1";}
							
								$statement = $pdo->prepare("INSERT INTO dns_failover_rules (userid,failover_hash,subdomain_record_key,content,subdomain_id,record_id,offlinepage_hash) 
									VALUES (:userid,:failover_hash,:subdomain_record_key,:content,:subdomain_id,:record_id,:offlinepage_hash)");
								$result = $statement->execute(array(
									'userid'=> $userid,
									'failover_hash'=> "$policyhash",
									'subdomain_record_key'=> $subdomain_record,
									'content'=> $failoverdest,
									'subdomain_id'=> $record["subdomain_id"],
									'record_id'=> $record["id"],
									'offlinepage_hash'=> $dst_offline_page
									));
								$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status WHERE failover_hash = :policyhash");
								$result = $statement->execute(array('status' => $status,'policyhash' => $policyhash));
								$ruleinfo2 = "<div class=\"alert alert-success\" role=\"alert\">Rule added to DNS Failover Policy. Failover active in a few seconds.</div>";
								add_log($pdo,$userid,"0","DNS Failover Rule","Added new DNS Failover Rule.");
						}else{
							$ruleinfo2 = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
						}
					}else{
					$ruleinfo2 = "<div class=\"alert alert-warning\" role=\"alert\">DNS Record already exists in another failover policy.</div>";
					}
				}else{
					$ruleinfo2 = "<div class=\"alert alert-warning\" role=\"alert\">Rules Limit exceeded.</div>";
				}
				}else{
					$ruleinfo2 = "<div class=\"alert alert-danger\" role=\"alert\">Do not any Changes while in Failover Mode.</div>";
				}
				}else{
					$ruleinfo2 = "<div class=\"alert alert-danger\" role=\"alert\">Permission denied.</div>";
				}
			}
			if(isset($_GET["delrule"]))
			{
				$rulekey = htmlspecialchars($_GET["delrule"]);
				if($policy["status"] != 2 AND $policy["status"] != 4 AND $policy["status"] != 5)
				{
					if($policy["status"] == 3){$status = 3;}else{$status = 0;}
				$statement = $pdo->prepare("SELECT * FROM dns_failover_rules WHERE userid = :userid AND subdomain_record_key = :subdomain_record_key AND failover_hash = :fh");
				$result = $statement->execute(array('userid' => $userid,'subdomain_record_key' => $rulekey,'fh' => $policyhash));
				$monitor = $statement->fetch();
				if($monitor["id"] != "")
				{
					$statement = $pdo->prepare("DELETE FROM dns_failover_rules WHERE userid = :userid AND subdomain_record_key = :subdomain_record_key AND failover_hash = :fh");
					$result = $statement->execute(array('userid' => $userid,'subdomain_record_key' => $rulekey,'fh' => $policyhash));
					$statement = $pdo->prepare("UPDATE dns_failover_policies set status = :status WHERE failover_hash = :policyhash");
					$result = $statement->execute(array('status' => $status,'policyhash' => $policyhash));
					$ruleinfo = "<div class=\"alert alert-success\" role=\"alert\">DNS Record Rule from DNS Failover removed.</div>";
					add_log($pdo,$userid,"0","DNS Failover Rule","Removed DNS Failover Rule.");
				}else{
					$ruleinfo = "<div class=\"alert alert-warning\" role=\"alert\">Permission denied.</div>";
				}
				}else{
					$ruleinfo = "<div class=\"alert alert-danger\" role=\"alert\">Do not any Changes while in Failover Mode.</div>";
				}
			}
			
			$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE userid = :userid AND failover_hash = :policyhash");
			$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
			$policy = $statement->fetch();
			
			if($policy["fallback_rule"] == 1){$ucheck = "checked";}else{$ucheck = "";}
			if($policy["disable_notifications"] == 1){$noti = "checked";}else{$noti = "";}
		?>
			<div class="col-12 col-sm-12 pb-3">
				<table class="table m-0 p-0 d-none d-sm-table">
					<tr><td width="33%" style="padding-top:0px;padding-left:0px;border-top:0px;!">
					<?php 
					if($policy["manual"] == "1"){$man = "Manual";}
					if($policy["status"] == 0) {$col = "bg-light"; $text = "text-black"; $status = "Pending..";}
					if($policy["status"] == 1) {$col = "bg-success"; $text = "text-white"; $status = "Active";}
					if($policy["status"] == 2) {$col = "bg-danger"; $text = "text-white"; $status = "$man Failed Over";}
					if($policy["status"] == 3) {$col = "bg-light"; $text = "text-black"; $status = "Paused";}
					if($policy["status"] == 4) {$col = "bg-light"; $text = "text-black"; $status = "Manual Failover";}
					if($policy["status"] == 5) {$col = "bg-light"; $text = "text-black"; $status = "Manual Fallback";}
						?>
					<div class="card <?php echo $text." ".$col;?>">
						<div class="card-body p-2"><i class="fa-solid fa-arrows-split-up-and-left fa-2xl float-right pt-4"></i>
							<p class="lead m-0">DNS Failover Status</p>
							<p class="card-text h3"><?php echo $status;?></p>
							
						</div>
					</div>
					<td width="33%" style="padding-top:0px;border-top:0px;!">
					<?php 
					$i=0;$k=0;$broken=0;$w=0;
					$statement = $pdo->prepare("SELECT * FROM dns_failover_monitors WHERE userid = :userid AND failover_hash = :policyhash");
					$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
					$monitors = $statement->fetchAll();
					foreach($monitors as $monitor)
					{	$i++;
						//if($i>1){$symbol = "<strong>AND</strong>";}else{$symbol = "<i class=\"fa-solid fa-heart-pulse pr-3\"></i>";}
						$hc = failover_check($pdo, (int)$userid, (string)$monitor["healthtoken"]) ?: array('status' => '');
						if($hc["status"] == "1" AND $monitor["negate"] == 1){$k++;$all++;}
						//if($hc["status"] == "2" AND $monitor["negate"] == 0){$k++;}
						//if($hc["status"] == "3" AND $monitor["negate"] == 0){$k++;}
						if($hc["status"] == "4" AND $monitor["negate"] == 0){$k++;$all++;$broken++;}
						if(in_array($hc["status"], array("0","2","3","5"))){$w++;}
						//if($hc["status"] == "5" AND $monitor["negate"] == 0){$k++;}
					} 
					if($policy["linking"] == "and") {
					if($all == $i){	$stat = "Unhealthy";$col2="bg-danger";$sum = $all."/".$i; $text = "text-white";}
					if($k == 0){	$stat = "Healthy";$col2="bg-success";$sum = $i."/".$i; $text = "text-white";}
					if($k == 0 AND $i == 0){$stat = "Choose at least one";$col2="bg-light";$sum = ""; $text = "text-black";}
					if($i > $k AND $k != 0){$stat = "Conditional";$col2="bg-warning";$sum = ($i-$k)."/".$i; $text = "text-black";}
					}elseif($policy["linking"] == "or") {
						if($k == 0){	$stat = "Healthy";$col2="bg-success";$sum = $i."/".$i; $text = "text-white";}
						if($k > 0){	$stat = "Unhealthy";$col2="bg-danger";$sum = ($i-$k)."/".$i; $text = "text-white";}
					}
					if($k == 0 AND $i == 0){$stat = "Choose at least one";$col2="bg-light";$sum = ""; $text = "text-black";}
					if($k == 0 AND $w > 0){$stat = "Warning";$col2="bg-warning";$sum = ($i-$w)."/".$i; $text = "text-black";}
					?>
					<div class="card <?php echo $text." ".$col2;?>">
						<div class="card-body p-2"><i class="fa-solid fa-heart-pulse fa-2xl float-right pt-4"></i>
							<p class="lead m-0">Monitor Status</p>
							<p class="card-text h3"><?php echo $stat." ".$sum;?></p>
							
						</div>
					</div>
					<td width="33%" style="padding-top:0px;padding-right:0px;border-top:0px;!">
					<div class="card bg-light">
						<div class="card-body p-2"><i class="fa-regular fa-file-lines fa-2xl float-right pt-4"></i>
							<p class="lead m-0">DNS Failover Events</p>
							<p class="card-text h3">0 last 24h</p>
							
						</div>
					</div>
				</table>
			</div>
			<div class="col-12 col-sm-12 col-lg-6">
			  <div class="card shadow-sm">
					<div class="card-header">
						<i class="fa-solid fa-arrows-split-up-and-left text-danger"></i>
						<strong>DNS Failover Policy</strong> | General Settings
					</div>
					<div class="card-body">
						<?php echo $setinfo;?>
						<form action="?edit=<?php echo $policyhash;?>&savegen" method="post">
						<div class="form-group">
							<label for="healthname">Failover Policy Name</label>
								<div class="input-group">
									<div class="input-group-prepend">
									  <div class="input-group-text"><i class="fa-solid fa-tag"></i></div>
									</div>
									<input type="text" value="<?php echo $policy["name"];?>" class="form-control" id="policyname" name="policyname" aria-describedby="policyname" placeholder="DNS Failover Policy" required>
								</div>
							<label for="healthname">Automated DNS Failover</label>
								<div class="input-group">
									<div class="input-group-prepend">
									  <div class="input-group-text"><i class="fa-solid fa-robot"></i></div>
									</div>
									<select name="failovertype" class="form-control float-right">
									<?php 
									if($policy["failover_type"] == 0){$sel1 = "selected";}
									if($policy["failover_type"] == 1){$sel2 = "selected";}
									if($policy["failover_type"] == 2){$sel3 = "selected";}
									?>
										<option value="1" <?php echo $sel2; ?>>Failover & Automated Fallback</option>
										<option value="0" <?php echo $sel1; ?>>Only automated Failover</option>
										<option value="2" <?php echo $sel3; ?>>Only manual Failover</option>
									</select>
								</div>
								<div class="form-check checkbox-lg pl-4">
								  <input class="form-check-input" type="checkbox" value="1" name="fallback_rule" id="fallback_rule" <?php echo $ucheck;?>>
								  <label class="form-check-label" for="fallback_rule">
									All Monitoring-Rules must be <strong class="text-success">healthy</strong> for <strong class="text-success">Fallback</strong>.
								  </label>
								</div>
							
						</div>
							<input type="submit" value="Save Settings" class="btn btn-sm btn-primary">
						</form>
					</div>
				</div>
				
			</div>
			<div class="col-12 col-sm-12 col-lg-6">
			  <div class="card shadow-sm">
					<div class="card-header">
						<i class="fa-solid fa-puzzle-piece text-primary"></i>
						<strong>DNS Failover Policy</strong> | Notification integration
					</div>
					<div class="card-body">
						<?php echo $setinfo2;?>
						<form action="?edit=<?php echo $policyhash;?>&saveinte" method="post">
						<label for="integration">Notification method <i>(Multiple selection)[Press CTRL]</i></label>
						<div class="input-group mb-2">
							<div class="input-group-prepend">
							  <div class="input-group-text"><i class="fa-solid fa-message"></i></div>
							</div>
							
							<select multiple class="custom-select"  class="form-control" id="integration" name="integration[]" rows="6" size="5">
							
							<?php 
							$spheal = explode(",",$policy["integration"]); $kk=0;
							$statement = $pdo->prepare("SELECT * FROM integrations WHERE userid = :userid AND status = '1' ORDER BY inte_used DESC,name DESC");
							$result = $statement->execute(array('userid' => $userid));
							$integrations = $statement->fetchAll();
								foreach($integrations as $integration)
								{	$kk++;
									if(in_array($integration["id"],$spheal)){ $sel = "selected"; 
									}else{$sel = "";}
									if($kk == 1) {
										if(in_array("0",$spheal)){echo "<option value=\"0\" selected>Account E-Mail (default)</option>";
										}else{echo "<option value=\"0\">Account E-Mail (default)</option>";}
									}
									
									echo "<option value=\"$integration[id]\" $sel>$integration[name]</option>";
								}
								if($kk == 0) {
										echo "<option value=\"0\" selected>Account E-Mail (default)</option>";
								}
							?>
							</select>
						</div>
						
						<div class="form-check checkbox-lg pl-4 float-left">
						  <input class="form-check-input" type="checkbox" value="1" name="disable_noti" id="disable_noti" <?php echo $noti;?>>
						  <label class="form-check-label" for="disable_noti">
							<strong class="text-danger">Disable</strong> all Notifications.
						  </label>
						</div>
						<input type="submit" value="Save Notifications" class="btn btn-sm btn-primary float-right mt-2">
						</form>
					</div>
				</div>
			</div>
		</div><br>
		<div class="row">
		<div class="col-12 col-sm-12 col-lg-12">
		<h2 class="lead">1. Select one or more Healtchecks to monitor the status
					<?php 
					$statement = $pdo->prepare("SELECT count(id) as id FROM dns_failover_monitors WHERE userid = :userid AND failover_hash = :policyhash");
					$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
					$monitors = $statement->fetch();
					if($monitors["id"] >= 1) { echo "<span class=\"badge badge-success \">Ok</span>"; }
					else{echo "<span class=\"badge badge-warning \">at least 1 Healthcheck</span>";}
					?>
		</h2>
		<div class="card shadow border-info mb-4">
			<div class="card-header mb-0">
					<i class="fa-solid fa-heart-pulse text-danger"></i>
					Monitor Healthcheck | Failover Trigger

				 </div>
				  <div class="card-body p-0">
				  <?php echo $monitorinfo; 
				  if($monitors["id"] >= 1) { ?>
				  <table class="tables table-sm table-striped m-0 p-0" width="100%">
					  <thead>
						  <tr>
						  <th>
						  <th scope="col">Status</th>
						  <th scope="col">Name</th>
						  <th scope="col">Type</th>
						  <th scope="col">Last Check</th>
						  <th scope="col">#</th>
						  </tr>
					  </thead>
				  <tbody>
				  <?php
				  }
					$i=0;$k=0;
					$statement = $pdo->prepare("SELECT * FROM dns_failover_monitors WHERE userid = :userid AND failover_hash = :policyhash");
					$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
					$monitors = $statement->fetchAll();
					foreach($monitors as $monitor)
					{	$i++; 
						
						$hc = failover_check($pdo, (int)$userid, (string)$monitor["healthtoken"]) ?: array('status' => '', 'healthname' => '(deleted)', 'type' => '', 'last_update_time' => '', 'healthtoken' => $monitor["healthtoken"]);
						
						if($monitor["negate"] == 1) { $negate = "&nbsp;<i class=\"fa-solid fa-shuffle\"></i>";}else{ $negate = "&nbsp;"; }
						if($i>1){
							if($monitor["negate"] == 1) {
								$symbol = "<strong>N".strtoupper($policy["linking"])."</strong>";
							}else{
								$symbol = "<strong>".strtoupper($policy["linking"])."</strong>";
							}
						}else{$symbol = "<i class=\"fa-solid fa-heart-pulse pr-3\"></i>";}
						
						if($hc["status"] == "0"){$status = "<i class=\"fa-solid fa-circle-check text-secondary fa-xl\"></i>";}
						if($hc["status"] == "1"){$status = "<i class=\"fa-solid fa-circle-check text-success fa-xl\"></i>";}
						if($hc["status"] == "2"){$status = "<i class=\"fa-solid fa-circle-pause text-secondary fa-xl\"></i>";$k++;}
						if($hc["status"] == "3"){$status = "<i class=\"fa-solid fa-triangle-exclamation text-warning fa-xl\"></i>";$k++;}
						if($hc["status"] == "4"){$status = "<i class=\"fa-solid fa-circle-exclamation text-danger fa-xl\"></i>";$k++;$all++;}
						if($hc["status"] == "5"){$status = "<i class=\"fa-regular fa-circle-check text-info fa-xl\"></i>";$k++;}
						
						echo "<tr>
								<td>$symbol
								<td>$status $negate
								<td>$hc[healthname]
								<td><span class=\"badge badge-dark\">".strtoupper($hc["type"])."
								<td><span class=\"badge badge-success\">".timeago2($hc["last_update_time"],date("Y-m-d H:i:s"))."</span>
								<td><a href=\"?edit=$policyhash&delhealthcheck=$hc[healthtoken]\"><i class=\"fa-solid fa-trash-can text-danger\"></i></a>
							</tr>";
						
					}
					?>
				  </table>
				  <?php if($i>=1){echo "<hr>";} ?>
				  
				  
					<form action="?edit=<?php echo $policyhash;?>&addhealthcheck" method="post" class="form-inline pt-2">
						<div class="col-7">
						<div class="input-group mb-2">
							<div class="input-group-prepend">
							  <div class="input-group-text"><i class="fa-solid fa-heart-circle-plus"></i></div>
							</div>
							<?php 
							if($i == 0) { ?>
									<select name="linking" class="form-control" style="max-width:80px;">
										<option value="and">AND</option>
										<option value="or">OR</option>
									</select>
							<?php }else{ echo "<input type=\"hidden\" name=\"linking\" value=\"$policy[linking]\">";} ?>
							<select name="healthcheck" class="form-control float-right">
								<option value="">Select a Healthcheck to add</option>
								<?php 
								$healthchecks = failover_checks($pdo, (int)$userid);
								foreach($healthchecks as $healthcheck)
								{
									$statement = $pdo->prepare("SELECT id FROM dns_failover_monitors WHERE userid = :userid AND BINARY failover_hash = :failover_hash AND healthtoken = :ht");
									$result = $statement->execute(array('userid' => $userid,'failover_hash' => $policyhash,'ht' => $healthcheck["healthtoken"]));
									$monitor = $statement->fetch();
									if($monitor["id"] == "") {
										echo "<option value=\"$healthcheck[healthtoken]\">$healthcheck[healthname]</option>";
									}
								}
								?>
							</select>
							<div class="input-group-append">
							  <div class="input-group-text">
								<input type="checkbox" class="form-check-input" name="negate" id="negate" value="1"> 
								<label for="negate">Negate</i></label>
							  </div>
							</div>
							</div>
						</div>
						<button type="submit" class="btn btn-info ml-2 mb-2">Add Healthcheck to Policy</button>
					</form>
				</div>
		</div></div>
		<div class="col-12 col-sm-12 col-lg-12">
		<h2 class="lead">2. Select appropriate rules for the DNS-Failover
			<?php 
			$statement = $pdo->prepare("SELECT count(id) as id FROM dns_failover_rules WHERE userid = :userid AND failover_hash = :policyhash");
			$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
			$monitors = $statement->fetch();
			if($monitors["id"] >= 1) { echo "<span class=\"badge badge-success \">Ok</span>"; }
			else{echo "<span class=\"badge badge-warning \">at least 1 Rule</span>";}
			?>
		</h2>
		<div class="card shadow border-success mb-2">
			<div class="card-header mb-0">
					<i class="fa-solid fa-globe text-primary"></i>
					DNS Failover Rules
				 </div>
				  <div class="card-body p-0">
				  <?php echo $ruleinfo; 
				  $statement = $pdo->prepare("SELECT count(id) as id FROM dns_failover_rules WHERE userid = :userid AND failover_hash = :policyhash AND offlinepage_hash = '0'");
				  $result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
				  $monitors = $statement->fetch();
				  if($monitors["id"] >= 1) {
					  ?>
				  <table class="tables table-sm table-striped m-0 p-0" width="100%">
					  <thead>
						  <tr>
						  <th scope="col">Domain Record</th>
						  <th scope="col">Type</th>
						  <th scope="col">Status</th>
						  <th scope="col">Destination</th>
						  <th scope="col"></th>
						  <th scope="col">Failover Destination</th>
						  <th scope="col">#</th>
						  </tr>
					  </thead>
				  <tbody>
				  <?php 
				  }
					$statement = $pdo->prepare("SELECT * FROM dns_failover_rules WHERE userid = :userid AND failover_hash = :policyhash AND offlinepage_hash = '0'");
					$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
					$rules = $statement->fetchAll();
					foreach($rules as $rule)
					{	$i++;
						
						if($i>1){$symbol = "<strong>AND</strong>";}else{$symbol = "<i class=\"fa-solid fa-heart-pulse pr-3\"></i>";}
						
						$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND record_key = :record_key");
						$result = $statement->execute(array('userid' => $userid,'record_key' => $rule["subdomain_record_key"]));
						$record = $statement->fetch();
						$statement = $pdo->prepare("SELECT * FROM subdomains WHERE id = :id");
						$result = $statement->execute(array('id' => $record["subdomain_id"]));
						$subdomain = $statement->fetch();
						
						if($record["praefix"] != ""){$praefix = $record["praefix"].".";}else{$praefix = "";}
						if($record["type"] == "A")	{$typs = "<span data-placement=\"top\" title=\"Record: $info[content]\" data-toggle=\"tooltip\" class=\"badge badge-primary\">A</span> ";		}
						if($record["type"] == "AAAA"){$typs = "<span data-placement=\"top\" title=\"Record: $info[content]\" data-toggle=\"tooltip\" class=\"badge badge-success\">AAAA</span> ";	}
						if($rule["status"] == 0){$status = "<span class=\"badge badge-secondary\">Passive</span>";}
						if($rule["status"] == 1){$status = "<span class=\"badge badge-warning\">Failoverd</span>";}
						if($rule["status"] == 2){$status = "<span class=\"badge badge-warning\">Failoverd</span>";}
						if(!filter_var($rule["content"], FILTER_VALIDATE_IP)) {
							$statement = $pdo->prepare("SELECT praefix,domainname,content,type,subdomain_id FROM subdomain_records WHERE userid = :userid AND record_key = :record_key");
							$result = $statement->execute(array('userid' => $userid,'record_key' => $rule["content"]));
							$dst_record = $statement->fetch();
							$statement = $pdo->prepare("SELECT * FROM subdomains WHERE id = :id");
							$result = $statement->execute(array('id' => $dst_record["subdomain_id"]));
							$subdomain2 = $statement->fetch();
							//Dest Präfix ?
							if($dst_record["type"] == "AAAA" AND str_starts_with($dst_record["content"],"::")) {
								$prefix = explode("::/",$subdomain2["ipv6prefix"]);
								$pref2 = "<strong>($prefix[0])</strong>";
								$dst_record["content"] = str_replace("::",":",$dst_record["content"]);
								
								$countpref = substr_count($prefix["0"], ':');
								$countsum = $countpref + substr_count($dst_record["content"], ':') + 1;
								if($countsum > 8){$valid = "<span class=\"badge badge-danger\">Not valid</span>"; }
							}else{$pref2="";}
							$rule["content"] = "$dst_record[praefix].$dst_record[domainname]<br>$pref2$dst_record[content]";
						}
						
						//Source Präfix ?
						if($record["type"] == "AAAA" AND str_starts_with($record["content"],"::")) {
							$prefix = explode("::/",$subdomain["ipv6prefix"]);
							$pref = "<strong>($prefix[0])</strong>";
							$record["content"] = str_replace("::",":",$record["content"]);
							
							$countpref = substr_count($prefix["0"], ':');
							$countsum = $countpref + substr_count($record["content"], ':') + 1;
							if($countsum > 8){$valid = "<span class=\"badge badge-danger\">Not valid</span>"; }
						}else{$pref="";}
						echo "<tr>
							<td>$praefix$record[domainname]
							<td>$typs
							<td>$status
							<td>$pref$record[content]
							<td><i class=\"fa-solid fa-right-long\"></i>
							<td>$rule[content]
							<td><a href=\"?edit=$policyhash&delrule=$rule[subdomain_record_key]\"><i class=\"fa-solid fa-trash-can text-danger\"></i></a>
							</tr>
							";
						
					}
					
				  ?>
					</tbody>
					</table>
					<?php if($i>=1){echo "<hr>";} ?>
					<form action="?edit=<?php echo $policyhash;?>&addrule" method="post" class="form-inline pt-2">
						<div class="col">
						<div class="input-group mb-2">
							<div class="input-group-prepend">
							  <div class="input-group-text"><i class="fa-solid fa-globe"></i></div>
							</div>
							<select name="subdomain_record" class="form-control float-right" required>
								<option value="">Select DNS Record</option>
								<?php 
								$statement = $pdo->prepare("SELECT * FROM subdomains WHERE userid = :userid ORDER BY subdomainname ASC");
								$result = $statement->execute(array('userid' => $userid));
								$subdomains = $statement->fetchAll();
								foreach($subdomains as $subdomain)
								{
									$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND subdomain_id = :sid AND 
									(type = :t1 OR type = :t2) AND ((deactivated = :da AND failover_policy = :fp) OR 
									(deactivated = :daa AND cdn_token != :cdnt)) AND cdn_tmp = :cdntmp ORDER BY domainname,praefix");
									$result = $statement->execute(array('userid' => $userid,'sid' => $subdomain["id"],'t1' => "A",'t2' => "AAAA"
									,'da' => "0",'fp' => "0",'daa' => "1",'cdnt' => "0",'cdntmp' => "0"));
									$records = $statement->fetchAll();
									foreach($records as $record)
									{	
										if($record["praefix"] != ""){$praefix = $record["praefix"].".";}else{$praefix = "";}
										$statement = $pdo->prepare("SELECT id FROM dns_failover_rules WHERE userid = :userid AND subdomain_record_key = :record_key");
										$result = $statement->execute(array('userid' => $userid,'record_key' => $record["record_key"]));
										$rulee = $statement->fetch();
										if($rulee["id"] == "") {
											echo "<option value=\"$record[record_key]\">$praefix$record[domainname] - $record[type] - $record[content]</option>";
										}
									}
									
								}
								?>
							</select>
							<div class="input-group-append">
							  <div class="input-group-text">
								Failover Dst. &nbsp;<i class="fa-solid fa-right-long"></i>
							  </div>
							</div>
							<select name="dst_record" class="form-control float-right">
								<option value="">Select predefined Dst.</option>
								<?php 
								$statement = $pdo->prepare("SELECT * FROM subdomains WHERE userid = :userid ORDER BY subdomainname ASC");
								$result = $statement->execute(array('userid' => $userid));
								$subdomains = $statement->fetchAll();
								foreach($subdomains as $subdomain)
								{
									$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND subdomain_id = :sid AND 
									(type = :t1 OR type = :t2) AND ((deactivated = :da AND failover_policy = :fp) OR 
									(deactivated = :daa AND cdn_token != :cdnt)) AND cdn_tmp = :cdntmp ORDER BY domainname,praefix");
									$result = $statement->execute(array('userid' => $userid,'sid' => $subdomain["id"],'t1' => "A",'t2' => "AAAA"
									,'da' => "0",'fp' => "0",'daa' => "1",'cdnt' => "0",'cdntmp' => "0"));
									$records = $statement->fetchAll();
									foreach($records as $record)
									{	
										if($record["praefix"] != ""){$praefix = $record["praefix"].".";}else{$praefix = "";}
										$statement = $pdo->prepare("SELECT id FROM dns_failover_rules WHERE userid = :userid AND subdomain_record_key = :record_key");
										$result = $statement->execute(array('userid' => $userid,'record_key' => $record["record_key"]));
										$rulee = $statement->fetch();
										if($rulee["id"] == "") {
											echo "<option value=\"$record[record_key]\">$praefix$record[domainname] - $record[type] - $record[content]</option>";
										}
									}
									
								}
								?>
							</select>
							<div class="input-group-append">
							  <div class="input-group-text">
								OR
							  </div>
							</div>
							<input type="text" class="form-control" id="failoverdest" name="failoverdest" aria-describedby="failoverdest" placeholder="Type dst. IP-Adress">

							<button type="submit" class="btn btn-info ml-2">Add Rule to Policy</button>
							</div>
						</div>	
					</form>
				</div>
		</div>
			<center class="pb-2"><strong>OR / AND</strong></center>
		<div class="card shadow border-success mb-2">
			<div class="card-header mb-0">
					<i class="fa-solid fa-file-circle-minus text-primary"></i>
					Offline Page
				 </div>
				  <div class="card-body p-0">
				  <?php echo $ruleinfo2;
				  
				  $statement = $pdo->prepare("SELECT count(id) as id FROM dns_failover_rules WHERE userid = :userid AND failover_hash = :policyhash AND offlinepage_hash != '0'");
				  $result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
				  $monitors = $statement->fetch();
				  if($monitors["id"] >= 1) {
					  ?>
				  <table class="tables table-sm table-striped m-0 p-0" width="100%">
					  <thead>
						  <tr>
						  <th scope="col">Domain Record</th>
						  <th scope="col">Type</th>
						  <th scope="col">Status</th>
						  <th scope="col">Destination</th>
						  <th scope="col"></th>
						  <th scope="col">Failover Destination</th>
						  <th scope="col">#</th>
						  </tr>
					  </thead>
				  <tbody>
				  <?php 
				  }
					$statement = $pdo->prepare("SELECT * FROM dns_failover_rules WHERE userid = :userid AND failover_hash = :policyhash AND offlinepage_hash != '0'");
					$result = $statement->execute(array('userid' => $userid,'policyhash' => $policyhash));
					$rules = $statement->fetchAll();
					foreach($rules as $rule)
					{	$i++;
						
						if($i>1){$symbol = "<strong>AND</strong>";}else{$symbol = "<i class=\"fa-solid fa-heart-pulse pr-3\"></i>";}
						
						$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND record_key = :record_key");
						$result = $statement->execute(array('userid' => $userid,'record_key' => $rule["subdomain_record_key"]));
						$record = $statement->fetch();
						
						if($record["praefix"] != ""){$praefix = $record["praefix"].".";}else{$praefix = "";}
						if($record["type"] == "A")	{$typs = "<span data-placement=\"top\" title=\"Record: $info[content]\" data-toggle=\"tooltip\" class=\"badge badge-primary\">A</span> ";		}
						if($record["type"] == "AAAA"){$typs = "<span data-placement=\"top\" title=\"Record: $info[content]\" data-toggle=\"tooltip\" class=\"badge badge-success\">AAAA</span> ";	}
						if($rule["status"] == 0){$status = "<span class=\"badge badge-secondary\">Passive</span>";}
						if($rule["status"] == 1){$status = "<span class=\"badge badge-warning\">Failoverd</span>";}
						if($rule["status"] == 2){$status = "<span class=\"badge badge-warning\">Failoverd</span>";}
						if($rule["offlinepage_hash"] == 1) {
							$rule["content"] = "Default IPv64.net Offline Page";
						}else{
							$statement = $pdo->prepare("SELECT name FROM dns_offline_pages WHERE userid = :userid AND page_hash = :page_hash");
							$result = $statement->execute(array('userid' => $userid,'page_hash' => $rule["offlinepage_hash"]));
							$page = $statement->fetch();
							$rule["content"] = "$page[name]";
						}
						echo "<tr>
							<td>$praefix$record[domainname]
							<td>$typs
							<td>$status
							<td>$record[content]
							<td><i class=\"fa-solid fa-right-long\"></i>
							<td>$rule[content]
							<td><a href=\"?edit=$policyhash&delrule=$rule[subdomain_record_key]\"><i class=\"fa-solid fa-trash-can text-danger\"></i></a>
							</tr>
							";
						
					}
					
				  ?>
					</tbody>
					</table>
				  
					<?php if($i>=1){echo "<hr>";} ?>
					<form action="?edit=<?php echo $policyhash;?>&addrule_offline" method="post" class="form-inline pt-2">
						<input type="hidden" name="offline_page" value="1">
						<div class="col">
						<div class="input-group mb-2">
							<div class="input-group-prepend">
							  <div class="input-group-text"><i class="fa-solid fa-globe"></i></div>
							</div>
							<select name="subdomain_record" class="form-control float-right" required>
								<option value="">Select DNS Record</option>
								<?php 
								$statement = $pdo->prepare("SELECT * FROM subdomains WHERE userid = :userid ORDER BY subdomainname ASC");
								$result = $statement->execute(array('userid' => $userid));
								$subdomains = $statement->fetchAll();
								foreach($subdomains as $subdomain)
								{
									$statement = $pdo->prepare("SELECT * FROM subdomain_records WHERE userid = :userid AND subdomain_id = :sid AND 
									(type = :t1 OR type = :t2) AND (deactivated = :da AND failover_policy = :fp) ORDER BY domainname,praefix");
									$result = $statement->execute(array('userid' => $userid,'sid' => $subdomain["id"],'t1' => "A",'t2' => "AAAA"
									,'da' => "0",'fp' => "0"));
									$records = $statement->fetchAll();
									foreach($records as $record)
									{	
										if($record["praefix"] != ""){$praefix = $record["praefix"].".";}else{$praefix = "";}
										$statement = $pdo->prepare("SELECT id FROM dns_failover_rules WHERE userid = :userid AND subdomain_record_key = :record_key");
										$result = $statement->execute(array('userid' => $userid,'record_key' => $record["record_key"]));
										$rulee = $statement->fetch();
										if($rulee["id"] == "") {
											echo "<option value=\"$record[record_key]\">$praefix$record[domainname] - $record[type] - $record[content]</option>";
										}
									}
									
								}
								?>
							</select>
							<div class="input-group-append">
							  <div class="input-group-text">
								Offline Page &nbsp;<i class="fa-solid fa-right-long"></i>
							  </div>
							</div>
							<select name="dst_offline_page" class="form-control float-right">
								<option value="1">Default IPv64.net Offline Page</option>
								<?php 
								$statement = $pdo->prepare("SELECT * FROM dns_offline_pages WHERE userid = :userid ORDER BY name ASC");
								$result = $statement->execute(array('userid' => $userid));
								$pages = $statement->fetchAll();
								foreach($pages as $page)
								{
									echo "<option value=\"$page[page_hash]\">$page[name]</option>";
								}
								?>
							</select>
							<button type="submit" class="btn btn-info ml-2">Add Rule to Policy</button>
							</div>
						</div>	
					</form>
				</div>
		</div>
		</div>
		<?php 	
		}else{
		?>
		<div class="col-12">
		<div class="card shadow">
		<div class="card-header p-2">
			    <i class="fa-solid fa-arrows-split-up-and-left"></i>
				DNS Failover Policys
				<a href="dns_failover?new" class="btn btn-sm btn-primary float-right">Create DNS Failover policy</a>
			 </div>
			  <div class="card-body m-0 p-0">
				<?php echo $infopolicy;?>
			  <table class="table table-striped">
			  <thead>
				<th>DNS Failover policy
				<th>Status / Last check
				<th>Healthchecks
				<th>Rules
				<th>
			  </thead>
			  <tbody>
				<?php 
				$statement = $pdo->prepare("SELECT * FROM dns_failover_policies WHERE userid = :uid");
				$result = $statement->execute(array("uid"=>$userid));
				$failovers = $statement->fetchAll();
				foreach($failovers as $failover)
				{
					$statement = $pdo->prepare("SELECT count(id) as count FROM dns_failover_rules WHERE userid = :userid AND failover_hash = :policyhash");
					$result = $statement->execute(array('userid' => $userid,'policyhash' => $failover["failover_hash"]));
					$rules = $statement->fetch();
					$statement = $pdo->prepare("SELECT count(id) as count FROM dns_failover_monitors WHERE userid = :userid AND failover_hash = :policyhash");
					$result = $statement->execute(array('userid' => $userid,'policyhash' => $failover["failover_hash"]));
					$monitor = $statement->fetch();
					if($failover["manual"] == "1"){$man = "Manual";}
					if($failover["status"] == "1" AND $rules["count"] >= "1" AND $monitor["count"] >= "1"){$status = "<span class=\"badge badge-success\">Active</span>";}
					elseif($failover["status"] == "2"){$status = "<span class=\"badge badge-danger\">$man Failed over</span>";}
					elseif($failover["status"] == "3"){$status = "<span class=\"badge badge-warning\">Paused</span>";}
					elseif($failover["status"] == "4"){$status = "<span class=\"badge badge-secondary\">Manual Failover initiated</span>";}
					elseif($failover["status"] == "5"){$status = "<span class=\"badge badge-secondary\">Manual Fallback initiated</span>";}
					elseif($rules["count"] <= "0" OR $monitor["count"] <= "0"){$status = "<span class=\"badge badge-warning\">Pending</span>";}
					elseif($failover["status"] == "0"){$status = "<span class=\"badge badge-warning\">Pending</span>";}
					
					if($failover["status"] != 0 AND $failover["manual"] == "0") { $jetzt = time();
						$status .= " <span class=\"badge badge-dark\">".timeago2($failover["last_check"],date("Y-m-d H:i:s",$jetzt))."</span>";
					}
					
					echo "
					<tr>
						<td><a href=\"dns_failover?edit=$failover[failover_hash]\">$failover[name]</a>
						<td>$status
						<td><span class=\"badge badge-info\">$monitor[count]</span>
						<td><span class=\"badge badge-info\">$rules[count]</span>
						<td>
							
						<div class=\"btn-group float-right\">
						  <button type=\"button\" class=\"btn btn-secondary btn-sm dropdown-toggle\" data-toggle=\"dropdown\" aria-expanded=\"false\">
							Failover Options <i class=\"fa-solid fa-arrow-right-arrow-left\"></i>
						  </button>
						  <div class=\"dropdown-menu\">
							<a class=\"dropdown-item\" href=\"?edit=$failover[failover_hash]\"><i class=\"fa-solid fa-edit text-primary\"></i> Settings</a>
							<div class=\"dropdown-divider\"></div>";
							if($failover["status"] == "1"){
								echo "<a class=\"dropdown-item\" href=\"?failover=$failover[failover_hash]\"><i class=\"fa-solid fa-arrows-split-up-and-left\"></i> Manual Failover</a>";
								echo "<div class=\"dropdown-divider\"></div>";
							}
							if($failover["status"] == "2"){
								echo "<a class=\"dropdown-item\" href=\"?fallback=$failover[failover_hash]\"><i class=\"fa-solid fa-arrows-split-up-and-left\"></i> Manual Fallback</a>";
							}
							
							if($failover["status"] == "0" OR $failover["status"] == "1") {
								echo "<a class=\"dropdown-item\" href=\"?pause=$failover[failover_hash]\"><i class=\"fa-solid fa-circle-pause text-warning\"></i> Pause Failover</a>";
							}elseif($failover["status"] == "3"){
								echo "<a class=\"dropdown-item\" href=\"?pause=$failover[failover_hash]\"><i class=\"fa-solid fa-circle-play text-success\"></i> Start Failover</a>";
							}
							echo "<div class=\"dropdown-divider\"></div>
								<a class=\"dropdown-item\" href=\"?del=$failover[failover_hash]\"><i class=\"fa fa-trash text-danger\"></i> Delete Failover</a>
							</div>
						</div>
					</tr>
					";
				}
			  ?>
			  </tbody>
			  </table>
				</div>
			</div><p></p>
		</div>
		<?php 
		}
		?>
		</div></div>
		<div class="col-12 col-sm-12 col-xl-4 <?php echo $b1;?>">
			<div class="row">
				<div class="col-12 col-xl-12">
				<?php echo account_status_card($pdo,$userid); ?>
				</div>
				
				<div class="col-12 col-xl-12">
				
				<div class="card mt-3 shadow-sm">
				  <div class="card-header">
				  <i class="fa-solid fa-person-praying"></i>
					Spende für das Projekt
				  </div>
				  <div class="card-body">
						<p>
						Dieses Projekt und der Service kann nur durch eure Spenden finanziert werden. Ich wäre also sehr dankbar 
						über eine kleine freiwillige Spende im Rahmen des Projekts.		
						</p>
						<p>
						<div id="donate-button-container">
							<div id="donate-button"></div>
							<script src="https://www.paypalobjects.com/donate/sdk/donate-sdk.js" charset="UTF-8"></script>
							<script>
							PayPal.Donation.Button({
							env:'production',
							hosted_button_id:'269PCDSZ6MYDW',
							image: {
							src:'https://www.paypalobjects.com/de_DE/DE/i/btn/btn_donateCC_LG.gif',
							alt:'Spenden mit dem PayPal-Button',
							title:'PayPal - The safer, easier way to pay online!',
							}
							}).render('#donate-button');
							</script>
						</div>
						</p>
					</div>

				</div>
				</div><p></p>
			</div>
	 </div>
	</div>
	</div>
	</div>
	
	<?php }else{ ?>
	</div>
		 </div>
		 </div>
		 </div>
		 <div class="jumbotron jumbotron-fluid d-none d-xl-block p-4 mb-0">
			<div class="container">
			  <h1 class="display-3"><img src="https://ipv64.net/img/logo_64.png" height="80" alt="IPv64 Logo" class="mb-3"> Automatic DNS Failover Protection
			  <i class="fa-solid fa-arrows-split-up-and-left"></i></h1>
			  <p class="lead">With IPv64.net it is possible to set up <strong>DNS failover policies</strong>, which allow an automatic failover of global DNS records. 
			  <br>IPv64 Healthchecks are used to monitor and trigger a DNS failover. This service is also suitable for free operation.</p>
			</div>
		  </div>
		  <div class="container pt-4">
			<div class="row">
				<div class="col-12 col-xl-5">
				<div class="row">
				<div class="col-12 col-sm-12 col-xl-12">
					<div class="list-group">
					  <a href="#" class="list-group-item list-group-item-action flex-column align-items-start list-group-item">
						<div class="d-flex w-100 justify-content-between">
						  <h5 class="mb-1"><i class="fa-solid fa-diagram-next"></i> Free to use</h5>
						</div>
						<p class="mb-1">The IPv64 DNS Failover Service is also available <strong>free of charge</strong> in the Free Tier Account. Additional triggers and rules can be activated with the account extension. </p>
					  </a>
					  <a href="#" class="list-group-item list-group-item-action flex-column align-items-start list-group-item-success">
						<div class="d-flex w-100 justify-content-between">
						  <h5 class="mb-1"><i class="fa-solid fa-arrow-down-up-lock"></i> Automatic DNS Failover</h5>
						</div>
						<p class="mb-1">IPv64 automatically switches DNS records to a stored fallback according to your specifications. These rules can be freely selected and set. </p>
					  </a>
					  <a href="#" class="list-group-item list-group-item-action flex-column align-items-start ">
						<div class="d-flex w-100 justify-content-between">
						  <h5 class="mb-1"><i class="fa-solid fa-diagram-next"></i> Manual Failover</h5>
						</div>
						<p class="mb-1">You can also simply be informed about an incident and then trigger failover and fallback manually. Automation can also be switched off completely.</p>
					  </a>
					  <a href="healthcheck" class="list-group-item list-group-item-action flex-column align-items-start">
						<div class="d-flex w-100 justify-content-between">
						  <h5 class="mb-1"><i class="fa-solid fa-heart-pulse text-danger"></i> IPv64 Healthchecks</h5>
						</div>
						<p class="mb-1">The IPv64 Healthchecks monitor your hosting services for reachability. If something goes wrong, this is detected and reported to you after a specified retention time. The DNS failover service is based on precisely these messages. </p>
					  </a>
					  <a href="#" class="list-group-item list-group-item-action flex-column align-items-start">
						<div class="d-flex w-100 justify-content-between">
						  <h5 class="mb-1"><i class="fa-solid fa-ethernet"></i> IPv4 & IPv6</h5>
						</div>
						<p class="mb-1">The DNS failover currently supports the automatic switching of A and AAAA entries. This means that IPv4 and IPv6 are fully integrated into the DNS failover. </p>
					  </a>
					  
					  <a href="account" class="list-group-item list-group-item-action list-group-item active">
						<div class="d-flex w-100 justify-content-between">
						  <h5 class="mb-1"><i class="fa-solid fa-id-card"></i> Register now</h5>
						</div>
						<p class="mb-1">The registration is completely free of charge and so is the use of the DynDNS service.</p>
					  </a>
					</div>
				</div>
				</div>
				</div>
				<div class="col-12 col-xl-7">
					<div class="card shadow-sm">
					  <div class="card-header">
					  <i class="fa-solid fa-arrows-split-up-and-left"></i>
						DNS Failover - More Informations
					  </div>
					  <div class="card-body"><center>
					  <img src="https://ipv64.net/img/automatic_dns_failover.png" alt="Automatic DNS Failover">
					  <br><hr><p>
					  <a href="https://ipv64.net/img/automatic_dns_failover_config1.png" target="_blank">
						<img class="float-left" src="https://ipv64.net/img/automatic_dns_failover_config1.png" alt="Automatic DNS Failover Configuration" width="45%">
					  </a>
					  <a href="https://ipv64.net/img/automatic_dns_failover_config2.png" target="_blank">
						<img class="float-right" src="https://ipv64.net/img/automatic_dns_failover_config2.png" alt="Automatic DNS Failover - DNS View" width="50%">
					</a>
					  </p>
					  </div>
					</div>
				</div>
				</div>
				</div>
	<?php } ?>
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