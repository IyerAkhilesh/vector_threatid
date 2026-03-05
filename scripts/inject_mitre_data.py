import json
import os
import sys
from tqdm import tqdm
from datetime import datetime 
# Adding project root to path so we can import our adapters
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from adapters.chroma_adapter import ChromaAdapter


def generate_synthetic_anchors(name, description):
	"""
	Creates a 'Log-Like' string for the Vector DB to find.
	"""
	# This acts as a 'Semantic Glue' between logs and framework
	patterns = [
		f"LOG_EVENT: {name} detected",
		f"SYSLOG: failure for user from IP",
		f"FIREWALL: connection refused on sensitive port",
		f"AUTH: unauthorized access attempt"
	]
	return " | ".join(patterns)

def ingest_enriched_data(file_path):
	db = ChromaAdapter(collection_name="threat_frameworks")
	
	# CRITICAL: Clear the old 0.1-score data first to avoid stale matches
	# print("[*] Clearing old collection to reset similarity baselines...")
	# db.collection.delete(where={}) 

	with open(file_path, 'r', encoding='utf-8') as f:
		data = json.load(f)

	techniques = [obj for obj in data.get('objects', []) if obj.get('type') == 'attack-pattern']

	for tech in tqdm(techniques, desc="Building Enriched Vault"):
		name = tech.get('name')
		desc = tech.get('description', '')
		mitre_id = next((r['external_id'] for r in tech.get('external_references', []) if r.get('source_name') == 'mitre-attack'), None)
		
		if not mitre_id: continue

		# We combine the formal Intel with Log-Speak
		anchors = generate_synthetic_anchors(name, desc)
		
		# This is the 'Rich Document' that ChromaDB will index
		# By putting Anchors at the START, they get higher weight in many embedding models
		rich_document = f"MATCH_PATTERN: {anchors} | TECHNIQUE: {name} | DETAILS: {desc[:300]}"

		db.add_vectors(
			documents=[rich_document],
			ids=[mitre_id],
			metadatas={
				"id": mitre_id,
				"status": "Verified",
				"last_sync": datetime.now().isoformat(),
				"framework": "MITRE",
				"type": "Technique"
			}
		)


"""
def ingest_mitre_stix(file_path):
	# 1. Initialize our secure on-prem adapter
	db = ChromaAdapter(collection_name="threat_frameworks")
	
	if not os.path.exists(file_path):
		print(f"[-] Error: {file_path} not found. Please place the MITRE JSON file there.")
		return

	print(f"[*] Reading MITRE ATT&CK data from {file_path}...")	
	with open(file_path, 'r', encoding='utf-8') as f:
		stix_data = json.load(f)

	# 2. Filter for 'attack-pattern' objects (Techniques)
	# We ignore relationships and other STIX noise for the vector anchors
	techniques = [
		obj for obj in stix_data.get('objects', []) 
		if obj.get('type') == 'attack-pattern' and not obj.get('revoked', False)
	]

	docs, ids, metas = [], [], []

	for tech in tqdm(techniques, desc="Vectorizing Techniques"):
		name = tech.get('name')
		description = tech.get('description', 'No description provided.')
		# Get the MITRE ID (e.g., T1110) from external references
		ext_refs = tech.get('external_references', [])
		mitre_id = next((ref['external_id'] for ref in ext_refs if ref.get('source_name') == 'mitre-attack'), "N/A")

		if mitre_id == "N/A": continue

		# We create a 'Semantic Anchor': Name + Description
		# This is what the embedding model uses to create the 384-dimensional vector
		docs.append(f"Technique: {name}. Context: {description}")
		ids.append(mitre_id)
		metas.append({
			"id": mitre_id,
			"name": name,
			"framework": "MITRE",
			"type": "Technique"
		})

	# 3. Batch Upload to local ChromaDB
	# We use chunks of 100 to prevent memory spikes in the venv
	batch_size = 100
	for i in range(0, len(docs), batch_size):
		db.add_vectors(
			documents=docs[i:i+batch_size],
			ids=ids[i:i+batch_size],
			metadatas=metas[i:i+batch_size]
		)

	print(f"[+] Success: Ingested {len(docs)} MITRE techniques into the Vault.")
"""
if __name__ == "__main__":
	MITRE_PATH = os.path.join("data", "enterprise-attack.json")
	ingest_enriched_data(MITRE_PATH)

# !!!!!!!!!! THIS IS TO CLEAR THE DB. DO NOT EXECUTE WITHOUT PERMISSION !!!!!!!!!!!!!
	# db = ChromaAdapter(collection_name="threat_frameworks")
	# db.collection.delete(where={"id": {"$ne": "NULL_ID_RESET_TRIGGER"}})