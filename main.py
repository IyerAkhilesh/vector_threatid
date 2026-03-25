from pathlib import Path
from typing import Optional

from adapters.chroma_adapter import ChromaAdapter
from adapters.sop_adapter import SOPAdapter
from core.risk_engine import RiskEngine
from core.log_aggregator_preprocessor import LogAggregator
from security_utils import get_safe_file_path, SECURITY_LOGGER
import sys
import re
import csv
import os

logger = SECURITY_LOGGER

FIREWALL_IP_REGEX = re.compile(r'SRC=(\d{1,3}(?:\.\d{1,3}){3})\s')
SSH_FTP_IP_REGEX = re.compile(r'from\s+(\d{1,3}(?:\.\d{1,3}){3})')
CUSTOM_APP_IP_REGEX = re.compile(r'Source:\s+(\d{1,3}(?:\.\d{1,3}){3})')

def extract_ip_from_log_line(log_line: str) -> Optional[str]:
	# From Firewall logs. " := " assigns and compares in one operation, so we can check and extract in one step.
	if ip_match := FIREWALL_IP_REGEX.search(log_line):
		return ip_match.group(1)

	# From SSH/FTP logs
	elif ip_match := SSH_FTP_IP_REGEX.search(log_line):
		return ip_match.group(1)

	# From custom app logs
	elif ip_match := CUSTOM_APP_IP_REGEX.search(log_line):
		return ip_match.group(1)	

	# If nothing else, return None
	else:
		return None


def append_to_risk_register(analysis, ip, impact_value=0.9, asset_value=50000) -> bool:
	"""
	Appends a new risk entry based on your defined column structure.
	EMV (Expected Monetary Value) = Probability * Impact (Cost)
	"""
	try:
		file_path = get_safe_file_path("output/risk_register.csv")
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
			"Risk Description": f"Detected {analysis['matched_technique'].get('name', 'Unknown Technique')} from {ip}",  # GitHub Copilot optimization: Use technique name instead of dict for readable description.
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
	except FileNotFoundError:
		logger.error("ERROR: File not found.")
		return False
	except PermissionError:
		logger.error("ERROR: Permission denied.")
		return False
	except KeyError as e:
		logger.error(f"ERROR: Missing required field in analysis data: {e}")
		return False
	except TypeError as e:
		logger.error(f"ERROR: Invalid data type in analysis: {e}")
		return False
	except ValueError as e:
		logger.error(f"ERROR: Invalid value in analysis or CSV operation: {e}")
		return False
	except IOError as e:
		logger.error(f"ERROR: I/O error occurred: {e}")
		return False


def main():
	# 1. Initialize the Chroma adapter
	# A. Threat frameworks collection
	chroma_adapter = ChromaAdapter(collection_name = "threat_frameworks")
	# B. SOP collection and adapter
	sop_adapter = ChromaAdapter(collection_name = "sop_playbooks")
	sop_engine = SOPAdapter(vector_store = sop_adapter)

	intel_count = chroma_adapter.get_count()
	logger.info(f"Current items in Vault: {intel_count}")
	if intel_count == 0:
		logger.warning("[!] Vault is empty. Please run the seed_db script first.")
		return
	logger.info(f"[*] Vector_ThreatID Online. Intelligence Vault: {intel_count} techniques loaded.")

	# 2. Inject the adapter into the core RiskEngine and define the log aggregator
	risk_engine = RiskEngine(vector_store = chroma_adapter, threshold = 0.7)
	log_aggregator = LogAggregator(window_size = 3)

	logger.info("\n" + "="*60)
	logger.info("[*] STREAMING SECURITY TELEMETRY...")
	logger.info("="*60)

	# 3. Process logs
	log_file_path = get_safe_file_path("data/vector_threatid_test_50k.log")
	with open(log_file_path, "r") as logs:
		logger.info("[*] Starting analysis ...")
		for log_line in logs:
			ip = extract_ip_from_log_line(log_line)
			if ip:
				context_block = log_aggregator.aggregate_logs(ip, log_line)
				analysis = risk_engine.evaluate_log(context_block)

				if analysis["trigger_rag"]:
					logger.info(f"[*] Analyzing Window: {context_block}")
					logger.info(f"[*] Risk Score: {analysis['risk_score']}")
					logger.info(f"🚨 ALERT: Pattern detected! Similarity: {analysis['risk_score']}")

					mitre_id = analysis['matched_technique']['id']
					logger.info(f"\n🚨 [THREAT DETECTED] Match: {mitre_id}")
					status = append_to_risk_register(analysis, ip)
					
					# Fetch the specific SOP for this MITRE Technique
					playbook = sop_engine.get_playbook(mitre_id, access_level=3)
					if playbook:
						logger.info("-" * 30)
						logger.info(f"SOP ID:\t	{playbook['sop_id']}")
						logger.info(f"ACTION TEAM: {playbook['metadata']['Team']}")
						logger.info(f"LOCATION:\t{playbook['metadata']['URL']}")
						logger.info(f"PROCEDURE:\t{playbook['instruction'][:100]}...")
						logger.info("-" * 30 + "\n")
					else:
						logger.warning(f"[!] No specific SOP found for {mitre_id}. Escalate to Tier-3 Analyst.")


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		logger.info("\n[*] Keyboard interrupt! Exiting...")
		sys.exit(0)
if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		logger.info("\n[*] Keyboard interrupt! Exiting...")  # GitHub Copilot optimization: Corrected typo in message.
		sys.exit(0)