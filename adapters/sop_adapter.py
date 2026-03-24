# vector_threatidtinel/adapters/sop_adapter.py
from typing import Dict, Optional

class SOPAdapter:
	def __init__(self, vector_store):
		"""
		Takes a ChromaAdapter instance initialized with the 'sop_playbooks' collection.
		"""
		self.store = vector_store

	def get_playbook(self, mitre_id: str, access_level: int = 1) -> Optional[Dict]:
		"""
		Queries the SOP collection for a specific MITRE Technique ID.
		Includes a metadata filter for Access Level.
		"""
		# We query the collection using the MITRE ID (e.g., 'T1110')
		# We use metadata filtering to ensure the analyst has sufficient clearance
		results = self.store.collection.query(
			query_texts=[f"Procedure for {mitre_id}"],
			n_results=1,
			where={"Access_Level": {"$lte": access_level}} # Level must be less than or equal to user's
		)

		# Check if any matching SOP was found
		if not results['ids'] or len(results['ids'][0]) == 0:
			return None

		return {
			"sop_id": results['ids'][0][0],
			"instruction": results['documents'][0][0],
			"metadata": results['metadatas'][0][0]
		}