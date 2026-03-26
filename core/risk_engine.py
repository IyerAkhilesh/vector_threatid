from typing import List, Dict
from scripts.owasp_standards_ingester import OwaspIngestor
import math
from typing import Dict, List, Optional, Any
from security_utils import SECURITY_LOGGER

logger = SECURITY_LOGGER

class RiskEngine:
	# Threshold here is up for change
	def __init__(self, vector_store, threshold: float = 0.7):
		self.store = vector_store
		self.threshold = threshold

		# Ingest the OWASP standards once (they load from the cache if its < 7 days old)
		owasp_ingester = OwaspIngestor()
		self.owasp_standards = owasp_ingester.get_owasp_data()
		logger.info(f"RiskEngine online with {len(self.owasp_standards)} OWASP categories loaded.")


	def _get_semantic_anchor(self, context_block) -> tuple[Optional[str], Optional[str]]:
		"""
		Dynamically scans the log for OWASP keywords to 'anchor' the vector query.
		This provides the semantic 'hint' ChromaDB needs to break the 0.5 score barrier.
		"""
		for category in self.owasp_standards:
			# Check 'common_vectors' list from the dynamic OWASP cache
			keywords = category.get('common_vectors', [])
			if any(keyword.lower() in context_block.lower() for keyword in keywords):
				return category['id'], category['name']
		return None, None

	def evaluate_log(self, context_block: str) -> Dict[str, Any]:
		"""
		Analyzes a log line, calculates distance using Exponential Distance Scaling, and checks for RAG trigger.
		"""

		# Get the enriched name and id values
		category_id, category_name = self._get_semantic_anchor(context_block)
		search_query = context_block
		if category_id:
			# We prepend the OWASP standard to the context block to make the vector come nearer to the MITRE neighbour
			search_query = f"OWASP {category_id}: {category_name} | {context_block}"
		logger.debug(f"Search query - {search_query}")
		# Search the framework table for similarity
		similarity_results = self.store.query_similarity(
			query_text = search_query,
			n_results = 1
			)

		# 2. Distance logic from Chroma. For the Cosine function, 0.0 is an exact match, and 2.0 is an exact mismatch

		# SAFETY CHECK: If the DB is empty or no results returned
		if not similarity_results or not similarity_results['distances'] or len(similarity_results['distances'][0]) == 0:
			return {
				"risk_score": 0.0,
				"trigger_rag": False,
			}
		else:
			cosine_distance = similarity_results['distances'][0][0]
			tau = 0.65
			risk_score = round(math.exp(-cosine_distance * tau), 4)
			is_critical = risk_score >= self.threshold

			return {
				"risk_score": risk_score,
				"trigger_rag": is_critical,
				"distance_raw": round(cosine_distance, 4),
				"owasp_category": category_name or "General Technical Risk",
				"matched_technique": similarity_results["metadatas"][0][0] if similarity_results["metadatas"][0][0] else "UNKNOWN",
				"log_line": context_block[:100] + "..."
			}

