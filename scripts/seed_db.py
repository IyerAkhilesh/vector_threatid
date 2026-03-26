import os
import chromadb
from security_utils import SECURITY_LOGGER

logger = SECURITY_LOGGER

def seed():
		current_dir = os.path.dirname(os.path.abspath(__file__))
		project_root = os.path.dirname(current_dir)
		db_path = os.path.join(project_root, "vault_storage")
		
		client = chromadb.PersistentClient(path=db_path)
		collection = client.get_or_create_collection(name="vector_threatid_vault", metadata = {"hnsw:space": "cosine"})   # Explicitly setting the search metric

		techniques = [
			{
				"id": "T1110", 
				"content": "Brute Force Chain: Multiple failed login attempts for root or admin followed by a successful session opening. Common in SSH and RDP logs."
			},
			{
				"id": "T1055", 
				"content": "Process Injection Chain: Allocation of memory in remote processes, often seeing 0x1F0FFF or similar hex codes, followed by shell execution."
			},
			{
				"id": "T1078", 
				"content": "Valid Accounts Chain: Unauthorized access using legitimate credentials, often following a brute force window. Look for 'session opened' after 'failed'."
			},
			{
				"id": "T1059",
				"content": "Command and Scripting Interpreter: Execution of base64 encoded strings, powershell, or shell scripts immediately after a successful login."
			}
		]

		for tech in techniques:
			collection.add(
				documents=[tech["content"]],
				ids=[tech["id"]],
				metadatas=[{"type": "technique_narrative"}]
			)
		logger.info(f"Vector_ThreatID Vault seeded with {len(techniques)} procedural narratives.")

if __name__ == "__main__":
	seed()
