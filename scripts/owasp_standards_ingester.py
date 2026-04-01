import json
import os
import time
import requests
from pathlib import Path
from security_utils import SECURITY_LOGGER, get_safe_file_path

logger = SECURITY_LOGGER

class OwaspIngestor:
	def __init__(self):
		self.owasp_file_path = get_safe_file_path("data/owasp_top_10.json")	

	def get_owasp_data(self) -> dict:
		# 1. Check if cache exists and is fresh
		logger.info("Loading OWASP standards from local weekly cache.")
		try:
			category = {}
			with open(self.owasp_file_path, "r") as f:
				data = json.load(f)
				# We want to extract the 'common_vectors' for each category to use as semantic anchors in the RiskEngine
				for field in data:
					name = field.get("name", "")
					description = field.get("description", "")
					# Combine name and description to create a richer set of keywords
					combined_text = f"{name} {description}".lower()
					# Extract keywords by splitting on spaces and removing common stop words (this is a simple approach; can be improved with NLP techniques)
					stop_words = set(["the", "and", "is", "in", "of", "to", "a", "for", "with", "on", "by", "as", "are"])
					keywords = [word.strip(",.()").lower() for word in combined_text.split() if word not in stop_words and len(word) > 3]
					category["id"] = field.get("id", "")
					category["name"] = name

					category['common_vectors'] = keywords
			return category
		except FileNotFoundError:
			logger.error("OWASP standards file not found. Please ensure it exists.")
			return {}
		except IOError as ioe:
			logger.error(f"File I/O error: {ioe}. Unable to read input file.")
			return {}
		except json.JSONDecodeError as jde:
			logger.error(f"JSON decode error: {jde}. Input file may be corrupted.")
			return {}