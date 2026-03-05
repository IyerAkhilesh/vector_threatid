from abc import ABC, abstractmethod
from typing import List, Dict

class VectorStorePort(ABC):
	@abstractmethod
	def add_vectors(self, documents: List[str], ids: List[str], metadatas: List[Dict]):
		pass

	@abstractmethod
	def query_similarity(self, vector: List[float], n_results: int) -> Dict:
		pass