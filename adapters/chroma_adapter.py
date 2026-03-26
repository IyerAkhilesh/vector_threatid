from pathlib import Path
import chromadb
import os
from typing import List, Dict, Optional, Any
from chromadb.api.models.Collection import QueryResult
from chromadb.config import Settings
from ports.vector_store import VectorStorePort
from security_utils import get_safe_file_path, SECURITY_LOGGER
from functools import wraps
import time

logger = SECURITY_LOGGER


def rate_limit(max_calls: int, time_window: int):
    """Decorator to rate limit function calls."""
    def decorator(func):
        calls = []
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            calls[:] = [c for c in calls if c > now - time_window]
            if len(calls) >= max_calls:
                raise ValueError("Rate limit exceeded")
            calls.append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator

class ChromaAdapter:
	def __init__(self, collection_name: str = ""):
		"""
		Initializes the local persistent storage.
		All data remains on-premise in the specified 'path'.
		"""
		if collection_name == "":
			collection_name = os.getenv(
				"CHROMA_COLLECTION_NAME",
				"threat_frameworks"
			)
			if not collection_name:
				raise ValueError("Collection name must be configured")
		try:
			self.db_path = get_safe_file_path("vault_storage")
			

			settings = Settings(
				chroma_db_impl="duckdb+parquet",
				persist_directory=str(self.db_path),	
				anonymized_telemetry=False
			)

			self.client = chromadb.Client(settings=settings)
		except Exception as e:
			self.client = chromadb.PersistentClient(path=self.db_path)

			self.collection = self.client.get_or_create_collection(name=collection_name, metadata = {"hnsw:space": "cosine"})	# Explicitly setting the search metric

	def add_vectors(self, documents: List[str], ids: List[str], metadatas: List[Any]) -> None:
		"""
		Adds frameworks like MITRE ATT&CK, CVE/CWE, OWASP, ISO, NIST, OSINT, etc. or logs to the vector space.
		Note: We don't pass embeddings here because we'll handle 
		vectorization in the core logic or via a separate port.
		"""
		self.collection.add(documents = documents, ids = ids, metadatas = metadatas)
		logger.info(f"Added {len(documents)} vectors to collection {self.collection.name}")

	@rate_limit(max_calls=5000, time_window=60)
	def query_similarity(self, query_text: str, n_results: int = 1, metadata_filter: Optional[Dict] = None) -> QueryResult:
		"""
		The 'Detection' engine. 
		metadata_filter allows for strict scoping (e.g., {"Access_Level": 3}).
		"""
		result = self.collection.query(
			query_texts = [query_text],
			n_results = n_results,
			where = metadata_filter
			)
		logger.debug(f"Chroma query executed, query_text={query_text[:80]}, n_results={n_results}")
		return result

	def get_count(self) -> int:
		return self.collection.count()
