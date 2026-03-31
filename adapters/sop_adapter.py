# vector_threatidtinel/adapters/sop_adapter.py
from typing import Dict, Optional
from security_utils import SECURITY_LOGGER, get_safe_file_path
import json

logger = SECURITY_LOGGER

class SOPAdapter:
	def __init__(self, vector_store):
		"""
		Takes a ChromaAdapter instance initialized with the 'sop_playbooks' collection.
		"""
		self.store = vector_store

	def populate_from_json(self, file_path: str, default_access_level: int = 1):
		"""
		Parses the MITRE ATT&CK JSON and populates the Chroma collection.
		"""
		if not isinstance(default_access_level, int) or not (0 <= default_access_level <= 5):
			raise ValueError("The default access level must be between 0 and 5")
		try:
			safe_file_path = get_safe_file_path(file_path)
			with open(safe_file_path, 'r') as f:
				data = json.load(f)

			# MITRE STIX files are usually lists of objects
			if not isinstance(data, dict):
				raise ValueError("Invalid JSON Format: Expected a JSON object at the root of the file.")
			
			objects = data.get("objects", [data]) 
			if not objects: 
				logger.warning(f"No objects found in {file_path}. Nothing to ingest.")
				return
			
			documents, metadatas, ids = [], [], []

			for obj in objects:
				# We only want active Course of Action (Mitigation) objects
				if obj.get("type") != "course-of-action" or obj.get("x_mitre_deprecated"):
					continue

				# Extract the MITRE ID (e.g., T1081) from external_references
				mitre_id = next(
					(ref.get("external_id") for ref in obj.get("external_references", []) if ref.get("source_name") == "mitre-attack"), 
					None)

				if not mitre_id:
					continue

				# Prepare content for the Vector Store
				# Combining name and description provides better semantic context for RAG
				content = f"Mitigation Strategy for {mitre_id} ({obj.get('name', 'Unnamed')}): {obj.get('description', 'No description provided.')}"
				
				documents.append(content)
				ids.append(obj.get("id"))
				metadatas.append({
					"mitre_id": mitre_id,
					"name": obj.get("name"),
					"Access_Level": default_access_level,
					"modified": obj.get("modified", "unknown")
				})

			if ids:
				self.store.collection.add(
					documents=documents,
					metadatas=metadatas,
					ids=ids
				)
				logger.info(f"Successfully ingested {len(ids)} playbooks into Vector_ThreatID.")		
		except json.JSONDecodeError:
			logger.error(f"Invalid JSON format in file: {file_path}")
			raise
		except PermissionError as pe:
			logger.error(f"Permission denied when accessing file: {file_path} - {pe}")
			raise
		except Exception as e:
			logger.error(f"An error occurred while populating SOPs: {e}")
			raise

	def get_playbook(self, mitre_id: str, access_level: int = 1) -> Optional[Dict]:
		"""
		Queries the SOP collection for a specific MITRE Technique ID.
		Includes a metadata filter for Access Level.
		"""
		 # Validate inputs
		if not isinstance(mitre_id, str) or len(mitre_id) > 50:
			raise ValueError("Invalid MITRE ID")
		
		if not isinstance(access_level, int) or not 0 <= access_level <= 5:
			raise ValueError("Invalid access level")
		
		# We query the collection using the MITRE ID (e.g., 'T1110')
		# We use metadata filtering to ensure the analyst has sufficient clearance
		results = self.store.collection.query(
			query_texts=[f"Procedure for {mitre_id}"],
			n_results=1,
			where={"Access_Level": {"$lte": access_level}} # Level must be less than or equal to user's
		)

		# Check if any matching SOP was found
		if not results['ids'] or len(results['ids'][0]) == 0:
			logger.warning(f"No SOP found for MITRE ID {mitre_id} at access_level {access_level}")
			return None

		logger.info(f"SOP loaded for MITRE ID {mitre_id} with access_level {access_level}")
		return {
			"sop_id": results['ids'][0][0],
			"instruction": results['documents'][0][0],
			"metadata": results['metadatas'][0][0]
		}
	
	def get_count(self) -> int:
		return self.store.collection.count()