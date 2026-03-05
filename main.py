from adapters.chroma_adapter import ChromaAdapter
from adapters.sop_adapter import SOPAdapter
from core.risk_engine import RiskEngine
from core.log_aggregator_preprocessor import LogAggregator
import sys
import re
import csv

def extract_ip_from_log_line(log_line: str) -> str:
	# From Firewall logs
	ip_match = re.search(r'SRC=(\d{1,3}(?:\.\d{1,3}){3})\s', log_line)
	if ip_match:
		return ip_match.group(1)

	# From SSH/FTP logs
	ip_match = re.search(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})', log_line)
	if ip_match:
		return ip_match.group(1)

	# From custom app logs
	ip_match = re.search(r'Source:\s+(\d{1,3}(?:\.\d{1,3}){3})', log_line)
	if ip_match:
		return ip_match.group(1)	

	# If nothing else, return None
	return None

def append_to_risk_register(analysis, ip, impact_value = 0.9, asset_value = 50000):
	import csv
import os

def append_to_risk_register(analysis, ip, impact_value=0.9, asset_value=50000) -> bool:
	"""
	Appends a new risk entry based on your defined column structure.
	EMV (Expected Monetary Value) = Probability * Impact (Cost)
	"""
	try:
		file_path = "./output/risk_register.csv"
		headers = [
			"Risk ID", "Risk Description", "Risk Category", 
			"Probability", "Impact", "Risk Score", "Ranking", 
			"EMV", "Response", "Trigger (KRI)", "Owner", "Status"
		]
		
		# Calculate Quantitative Values
		probability = analysis['risk_score']
		emv = round(probability * asset_value * -1, 2)
		
		# Logic for Qualitative Ranking
		ranking = "Critical" if probability > 0.65 else "High" if probability > 0.45 else "Medium" if probability > 0.35 else "Low" if probability > 0.25 else None
		
		new_entry = {
			"Risk ID": f"RS-{analysis['matched_technique']['id']}",
			"Risk Description": f"Detected {analysis['matched_technique']} from {ip}",
			"Risk Category": "Technical/Cyber",
			"Probability": probability,
			"Impact": impact_value,
			"Risk Score": round(probability * impact_value, 4),
			"Ranking": ranking,
			"EMV": f"${emv}",
			"Response": "Execute SOP",
			"Trigger (KRI)": "Vector Match > 0.7",
			"Owner": "SOC Team",
			"Status": "Identified"
		}

		# Write to CSV
		file_exists = os.path.isfile(file_path)
		with open(file_path, "a", newline='') as f:
			writer = csv.DictWriter(f, fieldnames=headers)
			if not file_exists:
				writer.writeheader()
			writer.writerow(new_entry)
		return True
	except FileNotFoundError as fe:
		print(f"[!] ERROR: Exception - {fe}")
		return False
	except PermissionError as pe:
		print(f"[!] ERROR: Exception - {pe}")
		return False
	except IOError as ie:
		print(f"[!] ERROR: Exception -  {ie}")
		return False
	except Exception as e: 
		print(f"[!] ERROR: Exception -  {e}")
		return False


def main():
	# 1. Initialize the Chroma adapter
	# A. Threat frameworks collection
	chroma_adapter = ChromaAdapter(collection_name = "threat_frameworks")
	# B. SOP collection and adapter
	sop_adapter = ChromaAdapter(collection_name = "sop_playbooks")
	sop_engine = SOPAdapter(vector_store = sop_adapter)

	intel_count = chroma_adapter.get_count()
	print(f"Current items in Vault: {intel_count}")
	if intel_count == 0:
		print("[!] Vault is empty. Please run the seed_db script first.")
		return
	print(f"[*] Vector_ThreatID Online. Intelligence Vault: {intel_count} techniques loaded.")

	# 2. Inject the adapter into the core RiskEngine and define the log aggregator
	risk_engine = RiskEngine(vector_store = chroma_adapter, threshold = 0.7)
	log_aggregator = LogAggregator(window_size = 3)

	# logs = [
	# ("10.0.0.5", "cmd: powershell.exe execution started with hidden window"),
 #	("10.0.0.5", "powershell: webclient object created for remote download"),
 #	("10.0.0.5", "ALERT: Unauthorized process hollowing and memory injection detected in system process. Diagnostic code: 0x1F0FFF."),
 #	("10.0.0.5", "proxy: outbound email sent to external mailbox with sensisitve file."),
 #	("10.0.0.5", "Security Alert: Unauthorized memory access and process injection attempt into svchost.exe using remote thread creation.")
	# ]


	print("\n" + "="*60)
	print("STREAMING SECURITY TELEMETRY...")
	print("="*60)

	# 3. Process logs
	with open("./data/vector_threatid_test_50k.log", "r") as logs:
		print(f"Starting analysis ...")
		for log_line in logs:
			ip = extract_ip_from_log_line(log_line)
			if ip:
				context_block = log_aggregator.aggregate_logs(ip, log_line)
				analysis = risk_engine.evaluate_log(context_block)

				status = append_to_risk_register(analysis, ip)

				print(f"Analyzing Window: {context_block}")
				print(f"Risk Score: {analysis['risk_score']}")

				if analysis["trigger_rag"]:
					# 3. Print the Context Block to verify aggregation is working
					print(f"Analyzing Window: {context_block}")
					print(f"Risk Score: {analysis['risk_score']}")
					print(f"🚨 ALERT: Pattern detected! Similarity: {analysis['risk_score']}")

					mitre_id = analysis['matched_technique']
					print(f"\n🚨 [THREAT DETECTED] Match: {mitre_id}")
					
					status = append_to_risk_register(analysis, ip)
					
					# Fetch the specific SOP for this MITRE Technique
					playbook = sop_engine.get_playbook(mitre_id, access_level=3) # Critical-Level
					
					if playbook:
						print("-" * 30)
						print(f"SOP ID:	  {playbook['sop_id']}")
						print(f"ACTION TEAM: {playbook['metadata']['Team']}")
						print(f"LOCATION:	{playbook['metadata']['URL']}")
						print(f"PROCEDURE:	{playbook['instruction'][:100]}...")
						print("-" * 30 + "\n")
					else:
						print(f"[!] No specific SOP found for {mitre_id}. Escalate to Tier-3 Analyst.")

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print(f"\n[!] Keyboard interrupt! Exitinggg...")
		sys.exit(0)