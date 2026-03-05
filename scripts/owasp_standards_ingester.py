import json
import os
import time
import requests
from pathlib import Path

class OwaspIngestor:
	def __init__(self, cache_file="../data/standards_cache.json"):
		self.cache_path = Path(cache_file)
		self.one_week = 7 * 24 * 60 * 60  # 604,800 seconds

	def get_owasp_data(self):
		# 1. Check if cache exists and is fresh
		if self.cache_path.exists():
			file_age = time.time() - os.path.getmtime(self.cache_path)
			if file_age < self.one_week:
				print("[*] Loading OWASP standards from local weekly cache.")
				with open(self.cache_path, "r") as f:
					return json.load(f)

		# 2. Otherwise, fetch and refresh
		return self._refresh_cache()

	def _refresh_cache(self):
		self.owasp_url = "https://raw.githubusercontent.com/STEVNS/owasp-top-10-json/main/owasp_top_10_2021.json"
		print("[!] Local cache expired or missing. Fetching fresh OWASP Top 10...")
		try:
			response = requests.get(self.owasp_url, timeout=10)
			response.raise_for_status() # Checks if the URL exists

			# GitHub sometimes returns HTML even for raw links if there's a redirect
			if "<html>" in res.text.lower():
				raise ValueError("Received HTML instead of JSON")

			data = response.json()['categories']
			# Save to disk
			self.cache_path.parent.mkdir(parents=True, exist_ok=True)
			with open(self.cache_path, "w") as f:
				json.dump(data, f)
			return data
		except Exception as e:
			print(f"[ERROR] Sync failed: {e}. Falling back to old cache if available.")
            static_list = [{"id": "A01", "name": "Broken Access Control", "keywords": ["unauthorized", "admin", "root", "privilege"]},
                {"id": "A03", "name": "Injection", "keywords": ["injection", "0x1F0FFF", "exec", "cmd", "script", "hollowing"]},
                {"id": "A07", "name": "Auth Failures", "keywords": ["failed", "password", "login", "brute", "invalid"]}]
			return json.load(self.cache_path.open()) if self.cache_path.exists() else static_list