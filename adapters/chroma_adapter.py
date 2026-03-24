import chromadb
import os
from typing import List, Dict, Optional, Any
from chromadb.api.models.Collection import QueryResult
from ports.vector_store import VectorStorePort


class ChromaAdapter:
	def __init__(self, collection_name: str = "vector_threatid_vault"):
		"""
		Initializes the local persistent storage.
		All data remains on-premise in the specified 'path'.
		"""
		current_dir = os.path.dirname(os.path.abspath(__file__))
		project_root = os.path.dirname(current_dir)
		self.db_path = os.path.join(project_root, "vault_storage")
		
		self.client = chromadb.PersistentClient(path=self.db_path)
		self.collection = self.client.get_or_create_collection(name=collection_name, metadata = {"hnsw:space": "cosine"})	# Explicitly setting the search metric

	def add_vectors(self, documents: List[str], ids: List[str], metadatas: List[Any]) -> None:
		"""
		Adds frameworks like MITRE ATT&CK, CVE/CWE, OWASP, ISO, NIST, OSINT, etc. or logs to the vector space.
		Note: We don't pass embeddings here because we'll handle 
		vectorization in the core logic or via a separate port.
		"""
		self.collection.add(documents = documents, ids = ids, metadatas = metadatas)


	def query_similarity(self, query_text: str, n_results: int = 1, metadata_filter: Optional[Dict] = None) -> QueryResult:
		"""
		The 'Detection' engine. 
		metadata_filter allows for strict scoping (e.g., {"Access_Level": 3}).
		"""
		return self.collection.query(
			query_texts = [query_text],
			n_results = n_results,
			where = metadata_filter
			)

	def get_count(self) -> int:
		return self.collection.count()
