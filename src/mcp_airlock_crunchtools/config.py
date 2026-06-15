"""Configuration for mcp-airlock-crunchtools."""

from __future__ import annotations

import json
import os
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

from pydantic import SecretStr

_config: Config | None = None

DEFAULT_MODEL = "gemini-2.5-flash-lite"
DEFAULT_SEARCH_MODEL = "gemini-2.5-flash"
DEFAULT_FALLBACK = "layer1"
DEFAULT_MAX_CONTENT = 100_000
DEFAULT_DB_PATH = "/data/airlock.db"
DEFAULT_CLASSIFIER_THRESHOLD = 0.5
DEFAULT_CLASSIFIER_MODEL_PATH = "/models/prompt-guard-2-86m"


class Config:
    """Airlock configuration from environment variables.

    Requires GEMINI_API_KEY for Layer 2 (Q-Agent) operations.
    Layer 1 (deterministic sanitization) works without it.
    """

    def __init__(self) -> None:
        raw_key = os.environ.get("GEMINI_API_KEY", "")
        self.api_key: SecretStr = SecretStr(raw_key) if raw_key else SecretStr("")
        self.model: str = os.environ.get("QUARANTINE_MODEL", DEFAULT_MODEL)
        self.search_model: str = os.environ.get(
            "QUARANTINE_SEARCH_MODEL", DEFAULT_SEARCH_MODEL
        )
        self.fallback: str = os.environ.get("QUARANTINE_FALLBACK", DEFAULT_FALLBACK)
        self.max_content: int = int(
            os.environ.get("QUARANTINE_MAX_CONTENT", str(DEFAULT_MAX_CONTENT))
        )

        self.classifier_threshold: float = float(
            os.environ.get("CLASSIFIER_THRESHOLD", str(DEFAULT_CLASSIFIER_THRESHOLD))
        )
        self.classifier_model_path: str = os.environ.get(
            "CLASSIFIER_MODEL_PATH", DEFAULT_CLASSIFIER_MODEL_PATH
        )

        home_db = str(Path.home() / ".local" / "share" / "mcp-airlock" / "airlock.db")
        self.db_path: str = os.environ.get("QUARANTINE_DB", home_db)

        trust_config_path = os.environ.get(
            "QUARANTINE_TRUST_CONFIG",
            str(Path.home() / ".config" / "mcp-env" / "mcp-airlock-trust.json"),
        )
        try:
            with open(trust_config_path) as fh:
                self._trust_config: dict[str, list[str] | str] = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            self._trust_config = {
                "trusted_domains": [],
                "trusted_paths": [],
                "default_trust": "untrusted",
            }

    @property
    def has_api_key(self) -> bool:
        """Check if a Gemini API key is configured."""
        return bool(self.api_key.get_secret_value())

    def is_trusted_domain(self, url: str) -> bool:
        """Check if a URL's domain is in the trust allowlist."""
        trusted_domains = self._trust_config.get("trusted_domains", [])
        if not isinstance(trusted_domains, list):
            return False
        try:
            parsed = urlparse(url)
            domain = parsed.hostname or ""
            return any(domain == td or domain.endswith(f".{td}") for td in trusted_domains)
        except ValueError:
            return False

    def is_trusted_path(self, file_path: str) -> bool:
        """Check if a file path matches the trust allowlist."""
        trusted_paths = self._trust_config.get("trusted_paths", [])
        if not isinstance(trusted_paths, list):
            return False
        return any(fnmatch(file_path, pattern) for pattern in trusted_paths)

    def ensure_db_dir(self) -> None:
        """Create the database directory if it does not exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)


def get_config() -> Config:
    """Get or create the singleton configuration."""
    global _config
    if _config is None:
        _config = Config()
    return _config
