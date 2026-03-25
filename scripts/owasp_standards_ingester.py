import json
import os
import time
import requests
from pathlib import Path
from security_utils import SECURITY_LOGGER

logger = SECURITY_LOGGER

class OwaspIngestor:
	def __init__(self, cache_file="standards_cache.json"):
		current_dir = os.path.dirname(os.path.abspath(__file__))
		project_root = os.path.dirname(current_dir)
		self.file_path = os.path.join(project_root, "data/"+cache_file)
		
		self.cache_path = Path(self.file_path)
		self.one_week = 7 * 24 * 60 * 60  # 604,800 seconds

	def get_owasp_data(self) -> list:
		# 1. Check if cache exists and is fresh
		if self.cache_path.exists():
			file_age = time.time() - os.path.getmtime(self.cache_path)
			if file_age < self.one_week:
				logger.info("Loading OWASP standards from local weekly cache.")
				with open(self.cache_path, "r") as f:
					return json.load(f)

		# 2. Otherwise, fetch and refresh
		return self._refresh_cache()


	def _refresh_cache(self):
		self.owasp_url = "https://raw.githubusercontent.com/STEVNS/owasp-top-10-json/main/owasp_top_10_2021.json"
		logger.warning("Local cache expired or missing. Fetching fresh OWASP Top 10...")
		try:
			response = requests.get(self.owasp_url, timeout=10)
			response.raise_for_status() # Checks if the URL exists

			if "<html>" in response.text.lower():
				raise ValueError("Received HTML instead of JSON")

			data = response.json()['categories']
			# Save to disk
			self.cache_path.parent.mkdir(parents=True, exist_ok=True)
			with open(self.cache_path, "w") as f:
				json.dump(data, f)
			os.chmod(self.cache_path, 0o600)
			return data
		except requests.RequestException as re:
			logger.error(f"Sync failed: {re}. Falling back to old cache if available.")
			static_list = [{"id": "A01", "name": "Broken Access Control", "keywords": ["unauthorized", "admin", "root", "privilege"]},
				{"id": "A03", "name": "Injection", "keywords": ["injection", "0x1F0FFF", "exec", "cmd", "script", "hollowing"]},
				{"id": "A07", "name": "Auth Failures", "keywords": ["failed", "password", "login", "brute", "invalid"]}]
			return json.load(self.cache_path.open()) if self.cache_path.exists() else static_list
		except (ValueError, json.JSONDecodeError) as je:
			logger.error(f"Data parsing failed: {je}. Falling back to old cache if available.")
			return json.load(self.cache_path.open()) if self.cache_path.exists() else []
		except IOError as ioe:
			logger.error(f"File I/O error: {ioe}. Unable to read/write cache.")
			return []