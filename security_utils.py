"""
SECURITY REMEDIATION UTILITIES
Quick-start implementations for security fixes
"""

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
from typing import Optional, Dict, Any
import ipaddress
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import json
from functools import wraps
import time

# Suppress verbose urllib3 connection retry warnings
logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

# ============================================================================
# 1. SECURITY LOGGING SETUP
# ============================================================================

def setup_security_logger() -> logging.Logger:
    """Configure security logger with rotating file handler."""
    logger = logging.getLogger("vectorthreatid.security")
    logger.setLevel(logging.DEBUG)
    
    # Create logs directory
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True, mode=0o750)
    
    # File handler for security events
    handler = RotatingFileHandler(
        log_dir / "security.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    handler.setLevel(logging.WARNING)
    
    # Structured format with timestamp
    formatter = logging.Formatter(
        '%(asctime)s|%(name)s|%(levelname)s|%(filename)s:%(lineno)d|%(message)s',
        datefmt='%Y-%m-%dT%H:%M:%SZ'
    )
    handler.setFormatter(formatter)
    
    logger.addHandler(handler)
    return logger


SECURITY_LOGGER = setup_security_logger()


# ============================================================================
# 2. INPUT VALIDATION
# ============================================================================

def validate_and_sanitize_log_line(log_line: str, max_length: int = 4096) -> Optional[str]:
    """Validate and sanitize log input."""
    if not log_line or not isinstance(log_line, str):
        SECURITY_LOGGER.warning("Invalid log input: not a string")
        return None
    
    if len(log_line) > max_length:
        SECURITY_LOGGER.warning(f"Log exceeds max length: {len(log_line)} > {max_length}. Truncating to fit the limit.")
        log_line = log_line[:max_length]
    
    # Replace all malicious characters to prevent log injection
    log_line = log_line.replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')

    # Escape \\ to prevent backslash injection issues in logs
    log_line = log_line.replace('\\', '\\\\')

    # Use Deterministic Pseudonymization. We can hash IPs or sensitive data if needed, but for now we just log the sanitized version.
    # The code for that would be something like:
    # im_port <hash>lib
    # define pseudonymize<parenthesis>value<colon> str<parenthesis> <arrow> str:
    #     re_turn <hash>lib<dot>sha256<parenthesis>value<dot>encode<parentheses><parenthesis><dot>hexdigest<parentheses>

    # Strip whitespace
    log_line = log_line.strip()
    
    # Remove control characters
    log_line = ''.join(c for c in log_line if (c.isprintable() or c in '\t\n\r') and c != '\x00')
    
    return log_line

def validate_ip_address(ip_str: str) -> Optional[str]:
    """Validate and normalize IP address."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        
        # Log private IP detection for audit trail
        if ip_obj.is_private:
            SECURITY_LOGGER.debug(f"Private IP address: {ip_str}")
        
        return str(ip_obj)
    except ValueError:
        SECURITY_LOGGER.warning(f"Invalid IP address format: {ip_str}")
        return None


def sanitize_csv_field(value: Any) -> str:
    """Sanitize value for CSV output."""
    if value is None:
        return ""
    
    value_str = str(value)
    
    # Remove control characters that could break CSV
    value_str = ''.join(c for c in value_str if (c.isprintable() or c == '\t') and c != '\x00')
    
    # Escape quotes
    value_str = value_str.replace('"', '""')
    
    # Limit length
    value_str = value_str[:1000]
    
    return value_str


def validate_mitre_id(mitre_id: str) -> bool:
    """Validate MITRE Technique ID format."""
    if not mitre_id or not isinstance(mitre_id, str):
        return False
    
    # MITRE IDs are format: T1234, T1234.001, etc.
    if len(mitre_id) < 5 or len(mitre_id) > 20:
        return False
    
    if not mitre_id[0] == 'T' or not mitre_id[1:].replace('.', '').isdigit():
        return False
    
    return True


# ============================================================================
# 3. PATH & FILE HANDLING
# ============================================================================

def get_project_root() -> Path:
    """Get project root directory."""
    return Path(__file__).parent


def get_safe_file_path(relative_path: str, base_dir: Optional[Path] = None) -> Path:
    """Get a safe file path with directory traversal protection."""
    if base_dir is None:
        base_dir = get_project_root()
    
    # Resolve to absolute path
    file_path = (base_dir / relative_path).resolve()
    base_dir = base_dir.resolve()
    
    # Verify path is within base directory
    try:
        file_path.relative_to(base_dir)
    except ValueError:
        raise ValueError(f"Path traversal attempt: {relative_path}")
    
    return file_path


def ensure_output_directory(dir_name: str = "output") -> Path:
    """Ensure output directory exists with proper permissions."""
    output_dir = get_project_root() / dir_name
    output_dir.mkdir(exist_ok=True, mode=0o755)
    
    if not output_dir.is_dir():
        raise ValueError(f"{output_dir} must be a directory")
    
    SECURITY_LOGGER.info(f"Output directory ensured: {output_dir}")
    return output_dir


def ensure_cache_directory() -> Path:
    """Ensure cache directory exists with secure permissions."""
    cache_dir = get_project_root() / "data" / ".cache"
    cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)  # rwx------
    
    return cache_dir


# ============================================================================
# 4. EXTERNAL API CALLS
# ============================================================================

def create_secure_session(verify_ssl: bool = True) -> requests.Session:
    """Create requests session with security hardening."""
    session = requests.Session()
    
    # Configure retries with exponential backoff
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,  # 1s, 2s, 4s
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "HEAD"]  # Only retry safe methods
    )
    
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # Force certificate verification
    session.verify = verify_ssl
    
    return session


def fetch_external_json(url: str, timeout: int = 30, verify_ssl: bool = True) -> Optional[Dict | list]:
    """Safely fetch JSON from external source."""
    if not url or not isinstance(url, str):
        SECURITY_LOGGER.error("Invalid URL provided")
        return None
    
    if not url.startswith(("http://", "https://")):
        SECURITY_LOGGER.error(f"Invalid URL scheme: {url}")
        return None
    
    try:
        session = create_secure_session(verify_ssl=verify_ssl)
        
        response = session.get(url, timeout=timeout)
        response.raise_for_status()
        
        # Validate response is JSON
        data = response.json()
        
        if not isinstance(data, (dict, list)):
            SECURITY_LOGGER.error("Invalid JSON structure received")
            return None
        
        SECURITY_LOGGER.info(f"Successfully fetched from {url}")
        return data
        
    except requests.exceptions.Timeout:
        SECURITY_LOGGER.error(f"Request timeout: {url}")
        return None
    except requests.exceptions.SSLError as e:
        SECURITY_LOGGER.error(f"SSL verification failed: {e}")
        return None
    except requests.exceptions.RequestException as e:
        SECURITY_LOGGER.error(f"Request failed: {e}")
        return None
    except json.JSONDecodeError:
        SECURITY_LOGGER.error("Invalid JSON response")
        return None


def query_local_llm_safely(prompt: str, max_retries: int = 3) -> Optional[str]:
    """Query local LLM with validation."""
    
    # Input validation
    if not prompt or not isinstance(prompt, str):
        SECURITY_LOGGER.warning("Invalid LLM prompt")
        return None
    
    if len(prompt) > 2000:
        SECURITY_LOGGER.warning("LLM prompt exceeds max length")
        prompt = prompt[:2000]
    
    try:
        payload = {
            "model": "llama3",
            "prompt": prompt,
            "stream": False
        }
        
        session = create_secure_session(verify_ssl=False)
        
        response = session.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        
        # Validate response structure
        if not isinstance(response.json(), dict):
            SECURITY_LOGGER.error("Invalid LLM response format")
            return None
        
        output = response.json().get("response", "").strip()
        
        # Validate output
        if not output or len(output) > 5000:
            SECURITY_LOGGER.error("Invalid LLM output size")
            return None
        
        return output
        
    except requests.exceptions.Timeout:
        SECURITY_LOGGER.error("LLM request timeout")
        return None
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        SECURITY_LOGGER.error(f"LLM query failed: {e}")
        return None



# ============================================================================
# 5. RATE LIMITING
# ============================================================================

def rate_limit(max_calls: int, time_window: int):
    """Decorator to rate limit function calls."""
    def decorator(func):
        calls = []
        
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = time.time()
            # Remove old calls outside window
            calls[:] = [c for c in calls if c > now - time_window]
            
            if len(calls) >= max_calls:
                SECURITY_LOGGER.warning(
                    f"Rate limit exceeded for {func.__name__}: "
                    f"{len(calls)} calls in {time_window}s"
                )
                raise ValueError(f"Rate limit exceeded: {max_calls} calls per {time_window}s")
            
            calls.append(now)
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


# ============================================================================
# 6. EXCEPTION HANDLING PATTERNS
# ============================================================================

def safe_file_operation(file_path: Path, operation: str = "read") -> bool:
    """Perform file operation with proper error handling."""
    try:
        if operation == "read":
            if not file_path.exists():
                SECURITY_LOGGER.error(f"File not found: {file_path}")
                return False
            if not file_path.is_file():
                SECURITY_LOGGER.error(f"Path is not a file: {file_path}")
                return False
        
        elif operation == "write":
            if file_path.exists() and not file_path.is_file():
                SECURITY_LOGGER.error(f"Path exists but is not a file: {file_path}")
                return False
        
        return True
        
    except (OSError, IOError) as e:
        SECURITY_LOGGER.error(f"File operation error: {e}")
        return False
    except Exception as e:
        SECURITY_LOGGER.error(f"Unexpected error in file operation: {type(e).__name__}: {e}")
        return False


# ============================================================================
# 7. CONFIGURATION MANAGEMENT
# ============================================================================

def load_env_config() -> Dict[str, Any]:
    """Load and validate configuration from environment."""
    from dotenv import load_dotenv
    
    load_dotenv()
    
    config = {
        "chroma_collection": os.getenv("CHROMA_COLLECTION_NAME", "threat_frameworks"),
        "chroma_db_path": os.getenv("CHROMA_DB_PATH", "./vault_storage"),
        "mitre_timeout": int(os.getenv("MITRE_TIMEOUT", "30")),
        "owasp_cache_age_days": int(os.getenv("OWASP_CACHE_AGE_DAYS", "7")),
        "log_level": os.getenv("LOG_LEVEL", "INFO"),
        "max_log_line_length": int(os.getenv("MAX_LOG_LINE_LENGTH", "4096")),
    }
    
    # Validate configuration
    if config["mitre_timeout"] < 5 or config["mitre_timeout"] > 300:
        SECURITY_LOGGER.warning("MITRE timeout out of acceptable range, using default")
        config["mitre_timeout"] = 30
    
    if config["owasp_cache_age_days"] < 1 or config["owasp_cache_age_days"] > 30:
        SECURITY_LOGGER.warning("OWASP cache age out of range, using default")
        config["owasp_cache_age_days"] = 7
    
    return config


# ============================================================================
# 8. TYPE-SAFE OPERATIONS
# ============================================================================

def get_nested_dict_value(data: Dict[str, Any], keys: list, default=None) -> Any:
    """Safely get nested dictionary value."""
    if not isinstance(data, dict):
        return default
    
    current = data
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return default
    
    return current


# ============================================================================
# USAGE EXAMPLES
# ============================================================================

if __name__ == "__main__":
    # Example: Validate IP
    ip = validate_ip_address("192.168.1.1")
    SECURITY_LOGGER.info(f"Validated IP: {ip}")
    
    # Example: Safe file path
    try:
        safe_path = get_safe_file_path("data/vector_threatid_test_50k.log")
        SECURITY_LOGGER.info(f"Safe path: {safe_path}")
    except ValueError as e:
        SECURITY_LOGGER.error(f"Path error: {e}")
    
    # Example: Fetch external JSON
    data = fetch_external_json(
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        timeout=30
    )
    if data and isinstance(data, dict):
        SECURITY_LOGGER.info(f"Fetched {len(data.get('objects', []))} MITRE objects")
    elif data and isinstance(data, list):
        SECURITY_LOGGER.info(f"Fetched {len(data)} MITRE objects")
    
    # Example: Rate limited function
    @rate_limit(max_calls=5, time_window=60)
    def limited_query():
        return "Query result"
    
    for i in range(3):
        try:
            result = limited_query()
            SECURITY_LOGGER.info(f"Call {i+1}: {result}")
        except ValueError as e:
            SECURITY_LOGGER.warning(f"Rate limit: {e}")
