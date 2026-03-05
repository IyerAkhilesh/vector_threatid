# project_sentinel/scripts/sync_mitre.py
import os
import json
import requests
import datetime
from adapters.chroma_adapter import ChromaAdapter
from tqdm import tqdm

# Constants
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
LOCAL_FILE = os.path.join(DATA_DIR, "enterprise-attack.json")

def fetch_latest_mitre() -> str:
	"""Fetches the latest MITRE ATT&CK JSON from the public repo."""
	os.makedirs(DATA_DIR, exist_ok=True)
	try:
		print(f"[*] Checking for updates from {MITRE_URL}...")
		response = requests.get(MITRE_URL, timeout=30)
		response.raise_for_status() # Raises exception for HTTP 4xx and 5xx statuses
		with open(LOCAL_FILE, "w", encoding="utf-8") as f:
			json.dump(response.json(), f)
		print("[+] Latest MITRE framework downloaded successfully.")
		return LOCAL_FILE
	except requests.exceptions.RequestException as e:
		print(f"[-] Network Error: {e}. Falling back to existing local file if available.")
		return LOCAL_FILE if os.path.exists(LOCAL_FILE) else None

def generate_log_prototypes(name, description):
	"""
		 Generates synthetic anchors using local LLM with a safety net
	"""
	try:
		payload = {
		"model": "llama3",
		"prompt": f"Task: Generate 3 realistic raw syslog/firewall lines for: {name}. Context: {description}. Output only the raw logs.",
		"stream": "false"
		}
		response = requests.post("http://localhost:11434/api/generate", json = payload, timeout = 10)
		return response.json().get("response", "").strip()
	except Exception:
		# If LLM is off, use basic keyword correlation. This is the safety net
		return f"LOG_PATTERN: {name}, Unauthorized, Access Denied, Failed!"

def modify_and_sync_vault():
	file_path = fetch_latest_mitre()
	if not file_path:
		 print("[!] CRITICAL ERROR: No MITRE framework data available to sync")
		 return

	"""Parses, modifies, and updates the local Vector DB."""
	db = ChromaAdapter(collection_name="threat_frameworks")
	
	with open(LOCAL_FILE, 'r', encoding='utf-8') as f:
		data = json.load(f)

	techniques = [obj for obj in data.get('objects', []) if obj.get('type') == 'attack-pattern']
	docs, ids, metas = [], [], []


	print(f"[*] Beginning enrichment of {len(techniques)} techniques...")
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
	print(f"[+] Synced {len(docs)} modified techniques to the Vault.")

if __name__ == "__main__":
	modify_and_sync_vault()