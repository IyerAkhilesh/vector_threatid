import logging
import os
import json
from pathlib import Path
from typing import Optional
import datetime

import requests
from adapters.chroma_adapter import ChromaAdapter
from tqdm import tqdm
from security_utils import create_secure_session, get_safe_file_path, SECURITY_LOGGER

logger = SECURITY_LOGGER

# Constants
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
LOCAL_FILE = "data/mitre_enterprise_attack.json"

def fetch_latest_mitre() -> Optional[str]:
	"""Fetches the latest MITRE ATT&CK JSON from the public repo."""
	local_file_path = get_safe_file_path(LOCAL_FILE)
	try:
		logger.info(f"[*] Checking for updates from {MITRE_URL}...")
		
		# Create secure session with retries and SSL verification
		session = create_secure_session(verify_ssl=True)
		
		# Fetch with timeout and SSL verification
		response = session.get(MITRE_URL, timeout=30, verify=True)
		response.raise_for_status()
		
		# Validate response is valid JSON
		try:
			data = response.json()
			if not isinstance(data, (dict, list)):
				logger.error("Invalid JSON structure received from MITRE")
				return str(local_file_path) if os.path.exists(str(local_file_path)) else None
		except json.JSONDecodeError as e:
			logger.error(f"JSON parsing error from MITRE response: {e}")
			return str(local_file_path) if os.path.exists(str(local_file_path)) else None
		
		with open(local_file_path, "w", encoding="utf-8") as f:
			json.dump(data, f)
		logger.info("[+] Latest MITRE framework downloaded successfully.")
		return str(local_file_path)
	except requests.exceptions.Timeout:
		logger.error("Request timeout fetching MITRE data")
		return str(local_file_path) if os.path.exists(str(local_file_path)) else None
	except requests.exceptions.SSLError as e:
		logger.error(f"SSL verification failed: {e}")
		return str(local_file_path) if os.path.exists(str(local_file_path)) else None
	except requests.exceptions.RequestException as e:
		logger.warning(f"Network error fetching MITRE data: {e}. Falling back to existing local file.")
		return str(local_file_path) if os.path.exists(str(local_file_path)) else None
	except IOError as e:	
		logger.error(f"File I/O error writing MITRE data: {e}")

def check_ollama_availability() -> bool:
	"""Check if Ollama service is running and accessible."""
	try:
		session = create_secure_session(verify_ssl=False)
		response = session.get("http://localhost:11434/api/tags", timeout=5)
		return response.status_code == 200
	except Exception:
		return False


def generate_log_prototypes(name: str, description: str) -> Optional[str]:
	"""
	Generates synthetic log patterns using local LLM with comprehensive fallback.
	Returns realistic syslog/firewall log entries for threat pattern matching.
	"""
	# Validate inputs
	if not name or not isinstance(name, str) or len(name) > 500:
		logger.warning(f"Invalid name parameter for LLM. Name - {name}")
		return None
	if not description or not isinstance(description, str) or len(description) > 4000:
		logger.warning(f"Invalid description parameter for LLM. Description - {description[:100]}...")
		return None

	# Check if Ollama is available and models are working
	if not check_ollama_availability():
		logger.info("Ollama service not available. Using enhanced fallback log patterns.")
		return generate_fallback_log_patterns(name, description)

	try:
		payload = {
			"model": "llama3.2:1b",  # Use smaller, more compatible model
			"prompt": f"Task: Generate 3 realistic raw syslog/firewall log lines for security threat: {name}. Context: {description}. Output only the raw log lines, one per line.",
			"stream": False
		}

		session = create_secure_session(verify_ssl=True)

		response = session.post("http://localhost:11434/api/generate", json=payload, timeout=15, verify=True)
		response.raise_for_status()

		if not isinstance(response.json(), dict) or "response" not in response.json():
			logger.error("Invalid response format from LLM")
			return generate_fallback_log_patterns(name, description)

		output = response.json().get("response", "").strip()

		if not output or len(output) > 5000:
			logger.warning("LLM output is empty or too long")
			return generate_fallback_log_patterns(name, description)

		return output
	except requests.exceptions.RequestException as e:
		# If LLM fails, use enhanced fallback patterns
		logger.warning(f"LLM request failed: {e}. Using fallback log patterns.")
		return generate_fallback_log_patterns(name, description)
	except json.JSONDecodeError as e:
		logger.error(f"JSON parsing error from LLM response: {e}")
		return generate_fallback_log_patterns(name, description)
	except Exception as e:
		logger.error(f"Unexpected error in LLM generation: {e}")

def generate_fallback_log_patterns(name: str, description: str) -> str:
	"""
	Generate realistic fallback log patterns when LLM is unavailable.
	Creates multiple log variations based on threat characteristics.
	"""
	# Extract key threat indicators from description
	threat_indicators = []
	if "phishing" in description.lower():
		threat_indicators.extend(["suspicious email", "malicious link", "credential theft"])
	if "malware" in description.lower():
		threat_indicators.extend(["executable download", "suspicious process", "file modification"])
	if "intrusion" in description.lower():
		threat_indicators.extend(["unauthorized access", "brute force", "port scan"])
	if "data exfiltration" in description.lower():
		threat_indicators.extend(["large file transfer", "unusual outbound", "encrypted traffic"])

	# Default indicators if none found
	if not threat_indicators:
		threat_indicators = ["unauthorized access", "suspicious activity", "security violation"]

	# Generate multiple log patterns
	patterns = [
		f"SECURITY: {name} - {threat_indicators[0]} detected from IP 192.168.1.100",
		f"AUDIT: Failed authentication attempt for {name} - {threat_indicators[0]}",
		f"FIREWALL: Blocked connection attempt - {name} threat pattern matched"
	]

	return "\n".join(patterns)


def modify_and_sync_vault():
	file_path = fetch_latest_mitre()
	if not file_path:
		logger.error("CRITICAL ERROR: No MITRE framework data available to sync")
		return

	"""Parses, modifies, and updates the local Vector DB."""
	db = ChromaAdapter(collection_name="threat_frameworks")
	
	with open(file_path, 'r', encoding='utf-8') as f:
		data = json.load(f)

	techniques = [obj for obj in data.get('objects', []) if obj.get('type') == 'attack-pattern']
	docs, ids, metas = [], [], []


	logger.info(f"Beginning enrichment of {len(techniques)} techniques...")
	for tech in tqdm(techniques, desc = "Building the intelligence layer"):
		mitre_id = next((ref['external_id'] for ref in tech.get('external_references', []) 
						if ref.get('source_name') == 'mitre-attack'), None)
		if not mitre_id: continue

		# --- MODIFICATION LOGIC ---
		# Here you can inject custom keywords or modify descriptions to better
		# match your specific firewall/OS log terminology.
		name = tech.get("name")
		description = tech.get("description", "No description")
		synthetic_logs = generate_log_prototypes(name, description)
		enriched_document = f"TECHNIQUE: {name} | EXAMPLES: {synthetic_logs} | DESC: {description}"
		
		docs.append(enriched_document)
		ids.append(mitre_id)
		metas.append({
			"id": mitre_id,
				"type": "synthetic_anchor",
				"ver": "1.0",
			"last_sync": datetime.datetime.now().isoformat(),
			"status": "Verified"
		})

	# Upsert logic (Chroma handles overwriting existing IDs)
	db.add_vectors(documents=docs, ids=ids, metadatas=metas)
	logger.info(f"Synced {len(docs)} modified techniques to the Vault.")

if __name__ == "__main__":
	modify_and_sync_vault()