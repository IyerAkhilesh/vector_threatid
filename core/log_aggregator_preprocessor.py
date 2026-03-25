"""
Since single logs are often benign but sequences are malicious, we need a Pre-Processor that aggregates logs before they hit the engine.
"""
from collections import deque
import re
from security_utils import SECURITY_LOGGER

logger = SECURITY_LOGGER


class LogAggregator:
	# Window size is up for change
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


		return unsanitized_log.strip()


	def aggregate_logs(self, source_ip: str, current_log_line: str) -> str:
		if source_ip not in self.context_windows:
			self.context_windows[source_ip] = deque(maxlen = self.window_size)

		sanitized_log = self.sanitize_log(current_log_line)
		self.context_windows[source_ip].append(sanitized_log)
		logger.debug(f"Aggregated log for IP={source_ip}, window_size={len(self.context_windows[source_ip])}")
		return " | ".join(list(self.context_windows[source_ip]))