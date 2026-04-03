"""Runtime configuration for leak detection service."""

from __future__ import annotations

import os

from dotenv import load_dotenv

load_dotenv()

MAX_TEXT_LENGTH = int(os.getenv("MAX_TEXT_LENGTH", "10000"))
PROCESSING_TIMEOUT = int(os.getenv("PROCESSING_TIMEOUT", "5"))
CHUNK_SIZE = int(os.getenv("CHUNK_SIZE", "10000"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL", "300"))

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"

SEVERITY_CRITICAL = int(os.getenv("SEVERITY_CRITICAL", "90"))
SEVERITY_HIGH = int(os.getenv("SEVERITY_HIGH", "70"))
SEVERITY_MEDIUM = int(os.getenv("SEVERITY_MEDIUM", "40"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
