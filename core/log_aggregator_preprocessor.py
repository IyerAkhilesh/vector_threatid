"""
Since single logs are often benign but sequences are malicious, we need a Pre-Processor that aggregates logs before they hit the engine.
"""
from collections import deque
import re

class LogAggregator:
	# Windows size is up for change
	def __init__(self, window_size = 5):
		# Stores last N logs per source ip or other identifier to provide multi-line context
		self.context_windows = {}
		self.window_size = window_size

	def sanitize_log(self, unsanitized_log: str) -> str:
		"""
			Removes all noise that can affect vector accuracy. These are things in logs like timestamps, PIDs, hexcodes, and even IP addresses. IP addresses will be tracked on the application layer and used to id an attacker.
		"""

		# Remove timestamps
		unsanitized_log = re.sub(r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', '', unsanitized_log)

		#Remove PIDs and hexcodes 
		unsanitized_log = re.sub(r'\[\d+\]|0x[0-9A-Fa-f]+', '', unsanitized_log)



	def aggregate_logs(self, source_ip: str, current_log_line: str) -> str:
		if source_ip not in self.context_windows:
			self.context_windows[source_ip] = deque(maxlen = self.window_size)

		self.context_windows[source_ip].append(current_log_line)
		# print(f"In aggregator - IP: {source_ip}, Log Line: {current_log_line}, \nContext Block: {self.context_windows}")
		# Merging the context window into a single semantic block
		return " | ".join(list(self.context_windows[source_ip]))