# from pathlib import Path
from typing import Optional

from json import JSONDecodeError
from adapters import sop_adapter
from adapters.chroma_adapter import ChromaAdapter
from adapters.sop_adapter import SOPAdapter
from core.risk_engine import RiskEngine
from core.log_aggregator_preprocessor import LogAggregator
from security_utils import get_safe_file_path, SECURITY_LOGGER, GENERAL_LOGGER
import sys
import re
import csv
import os

security_logger = SECURITY_LOGGER
general_logger = GENERAL_LOGGER

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
			"Risk ID": f"RS-{analysis['matched_technique']['mitre_id']}",
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
		general_logger.info(f"[*] Appending new risk entry to register at {file_path}")
		with open(file_path, "a", newline='') as f:
			writer = csv.DictWriter(f, fieldnames=headers)
			if not file_exists:
				security_logger.warning(f"[*] Risk register not found. Creating new file and adding header.")
				writer.writeheader()
			general_logger.info(f"[*] Appending new risk entry to register")
			writer.writerow(new_entry)
		return True
	except FileNotFoundError:
		security_logger.error("ERROR: File not found.")
		return False
	except PermissionError:
		security_logger.error("ERROR: Permission denied.")
		return False
	except KeyError as e:
		security_logger.error(f"ERROR: Missing required field in analysis data: {e}")
		return False
	except TypeError as e:
		security_logger.error(f"ERROR: Invalid data type in analysis: {e}")
		return False
	except ValueError as e:
		security_logger.error(f"ERROR: Invalid value in analysis or CSV operation: {e}")
		return False
	except IOError as e:
		security_logger.error(f"ERROR: I/O error occurred: {e}")
		return False


def main():
	# 1. Initialize the Chroma adapter
	# A. Threat frameworks collection
	chroma_adapter = ChromaAdapter(collection_name = "threat_frameworks")
	# B. SOP collection and adapter
	sop_adapter = ChromaAdapter(collection_name = "sop_playbooks")
	sop_engine = SOPAdapter(vector_store = sop_adapter)
	
	sop_count = sop_engine.get_count()
	general_logger.info(f"Current SOP playbooks in Vault: {sop_count}")
	if sop_count == 0:
		security_logger.warning("[!] SOP Vault is empty. Running ingestion script to ingest playbooks.")
		sop_engine.populate_from_json("data/mitre_enterprise_attack.json", default_access_level=3)
	else:
		general_logger.info(f"[*] SOP Adapter Online. SOP Vault: {sop_count} playbooks loaded.")
	
	intel_count = chroma_adapter.get_count()
	general_logger.info(f"Current items in Vault: {intel_count}")
	if intel_count == 0:
		security_logger.warning("[!] Vault is empty. Please run the seed_db script first.")
		return
	general_logger.info(f"[*] Vector_ThreatID Online. Intelligence Vault: {intel_count} techniques loaded.")

	# 2. Inject the adapter into the core RiskEngine and define the log aggregator
	risk_engine = RiskEngine(vector_store = sop_adapter, threshold = 0.65)
	log_aggregator = LogAggregator(window_size = 3)

	general_logger.info("\n" + "="*60)
	general_logger.info("[*] STREAMING SECURITY TELEMETRY...")
	general_logger.info("="*60)

	# 3. Process logs
	log_file_path = get_safe_file_path("data/vector_threatid_test_50k.log")
	with open(log_file_path, "r") as logs:
		general_logger.info("[*] Starting analysis ...")
		for log_line in logs:
			ip = extract_ip_from_log_line(log_line)
			if ip:
				context_block = log_aggregator.aggregate_logs(ip, log_line)
				analysis = risk_engine.evaluate_log(context_block)

				# print(f"[*] Analyzing Window: {context_block}")

				if analysis["trigger_rag"]:
					general_logger.info(f"🚨 ALERT: Pattern detected! Similarity: {analysis['risk_score']}")
					general_logger.info(f"[*] Analyzing Window: {context_block}")

					mitre_id = analysis['matched_technique']['mitre_id']	
					general_logger.info(f"\n🚨 [THREAT DETECTED] Match: {mitre_id}")
					
					status = append_to_risk_register(analysis, ip)
					if status:
						general_logger.info(f"[*] Risk entry for {mitre_id} added to the register.")
					else:
						security_logger.error(f"[*] Failed to add risk entry for {mitre_id}.")

					# Fetch the specific SOP for this MITRE Technique
					playbook = sop_engine.get_playbook(mitre_id, access_level=3)
					if playbook:
						general_logger.info("-" * 30)
						general_logger.info(f"SOP ID:\t	{playbook['sop_id']}")
						general_logger.info(f"ACTION TEAM: SOC")
						general_logger.info(f"INSTRUCTION:\t{playbook['metadata'].get('name', 'No name')}")
						general_logger.info(f"PROCEDURE:\t{playbook['instruction'][:100]}...")
						general_logger.info("-" * 30 + "\n")
					else:
						security_logger.warning(f"[!] No specific SOP found for {mitre_id}. Escalate to Tier-3 Analyst.")


if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		general_logger.info("\n[*] Keyboard interrupt! Exiting...")
		sys.exit(0)
	except ValueError as ve:
		security_logger.error(f"Value error: {ve}")
		sys.exit(1)
	except PermissionError as pe:
		security_logger.error(f"Permission error: {pe}")
		sys.exit(1)