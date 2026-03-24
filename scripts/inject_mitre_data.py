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
	try:
		db = ChromaAdapter(collection_name="threat_frameworks")
		
		# CRITICAL: Clear the old 0.1-score data first to avoid stale matches
		# print("[*] Clearing old collection to reset similarity baselines...")
		# db.collection.delete(where={}) 

		with open(file_path, 'r', encoding='utf-8') as f:
			data = json.load(f)

		techniques = [obj for obj in data.get('objects', []) if obj.get('type') == 'attack-pattern']

		docs, ids, metas = [], [], []

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

			docs.append(rich_document)
			ids.append(mitre_id)
			metas.append({
				"id": mitre_id,
				"status": "Verified",
				"last_sync": datetime.now().isoformat(),
				"framework": "MITRE",
				"type": "Technique"
			})

		batch_size = 100
		for i in range(0, len(docs), batch_size):
			db.add_vectors(
				documents=docs[i:i+batch_size],
				ids=ids[i:i+batch_size],
				metadatas=metas[i:i+batch_size]
			)

		print(f"[+] Success: Ingested {len(docs)} MITRE techniques into the Vault.")
		return len(docs)
	except FileNotFoundError:
		print(f"[!] Error: File not found.")
		return 0
	except json.JSONDecodeError as e:
		print(f"[!] Error: Invalid JSON in the file: {e}")
		return 0
	except Exception as e:
		print(f"[!] Error during ingestion: {e}")
		return 0

if __name__ == "__main__":
	MITRE_PATH = os.path.join("data", "enterprise-attack.json")
	ingested_count = ingest_enriched_data(MITRE_PATH)
	if ingested_count > 0:
		print(f"Ingestion completed successfully with {ingested_count} techniques.")
	else:
		print("Ingestion failed.")