import os


API_URL = os.getenv("SIEM_API_URL", "http://127.0.0.1:5000/ingest")
API_KEY = os.getenv("SIEM_API_KEY", "agent123")

BATCH_SIZE = int(os.getenv("SIEM_BATCH_SIZE", "50"))
COLLECT_LIMIT = int(os.getenv("SIEM_COLLECT_LIMIT", "200"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("SIEM_REQUEST_TIMEOUT", "15"))

# Continuous mode
POLL_SECONDS = int(os.getenv("SIEM_POLL_SECONDS", "30"))
FAIL_RETRY_SECONDS = int(os.getenv("SIEM_FAIL_RETRY_SECONDS", "10"))
DEDUPE_CACHE_SIZE = int(os.getenv("SIEM_DEDUPE_CACHE_SIZE", "5000"))
