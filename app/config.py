from __future__ import annotations

import os
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("ANALYZER_DATA_DIR", ROOT_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "analysis.sqlite3"
STATIC_DIR = ROOT_DIR / "static"

MODEL_BASE_URL = os.getenv("MODEL_BASE_URL", "http://127.0.0.1:8080")
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(25 * 1024 * 1024)))

# The complete prompt + generated answer must remain within 2,048 tokens.
MAX_CONTEXT_TOKENS = 2048
MAX_OUTPUT_TOKENS = 320
SAFETY_TOKENS = 96
MAX_PROMPT_TOKENS = MAX_CONTEXT_TOKENS - MAX_OUTPUT_TOKENS - SAFETY_TOKENS

# The tokenizer, not this record count, determines the final chunk boundary.
MAX_RECORDS_PER_CHUNK = 40
MAX_HISTORY_CHARS = 300
MODEL_TIMEOUT_SECONDS = float(os.getenv("MODEL_TIMEOUT_SECONDS", "120"))
