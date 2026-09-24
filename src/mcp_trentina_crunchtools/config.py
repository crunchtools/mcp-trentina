"""Configuration for mcp-trentina-crunchtools."""

from __future__ import annotations

import json
import logging
import os
from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlparse

from pydantic import SecretStr

logger = logging.getLogger(__name__)

_config: Config | None = None

DEFAULT_PROVIDER = "gemini"
DEFAULT_MODEL = "gemini-2.5-flash-lite"
DEFAULT_SEARCH_MODEL = "gemini-2.5-flash"
DEFAULT_MAX_CONTENT = 100_000
DEFAULT_CLASSIFIER_THRESHOLD = 0.5
DEFAULT_CLASSIFIER_MODEL_PATH = "/models/prompt-guard-2-86m"
DEFAULT_CLASSIFIER_MAX_TOKENS = 32_768
"""Token ceiling for a Layer 2 scan, ~74 sliding windows at stride 448.

Kept above what DEFAULT_MAX_CONTENT (100k chars, roughly 28k tokens of
ordinary prose) can produce, so the two limits never fight: content small
enough for the Q-Agent is always small enough to scan in full."""

DEFAULT_CLASSIFIER_THREADS = 4
"""ONNX intra-op threads. Its own default is one per core with a spin-wait,
which lets a single inference saturate the host.

Set this to match the container's CPU allocation. Threads beyond that just
contend for the same quota and make scans slower — measured on host01
(6 vCPU) against a 9,100-token article:

    --cpus=2, threads=2   39.2s
    --cpus=2, threads=4   44.5s   <- contention, worse than half the threads
    --cpus=6, threads=6   28.0s
    --cpus=4, threads=4   23.2s   <- deployed
"""
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_OLLAMA_MODEL = "qwen2.5:0.5b"
SUPPORTED_PROVIDERS = ("gemini", "openai", "anthropic", "ollama")


def bool_env(name: str, default: bool) -> bool:
    """Read a true/false environment variable; anything unrecognised is the default.

    A typo in a security opt-out must not silently open it, so only an
    explicit false-ish value turns a default-true setting off.
    """
    raw = os.environ.get(name, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    if raw:
        logger.warning("config: %s=%r is not a boolean — using %s", name, raw, default)
    return default


def int_env(name: str, default: int, *, minimum: int | None = None) -> int:
    """Read an integer environment variable, recovering from a bad value.

    A typo in a tuning knob must not stop the gateway from starting: it takes
    the documented default, says which variable it could not read, and
    continues. The name is in the message because the alternative — a silent
    fallback — looks identical to the value having been applied.

    ``minimum`` clamps rather than rejects, for knobs where a small value is
    meaningful but a tiny one is pathological (a one-second sweep interval,
    say). Clamping keeps the operator's intent, which was "make it small".

    Every caller's variable belongs in README.md's environment table.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default if minimum is None else max(minimum, default)
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "config: %s=%r is not an integer — using %d",
            name,
            raw,
            default,
        )
        return default if minimum is None else max(minimum, default)
    return value if minimum is None else max(minimum, value)


DEFAULT_PROVIDER_FALLBACK: list[str] = []


class Config:
    """Trentina configuration from environment variables.

    Requires GEMINI_API_KEY for Layer 2 (Q-Agent) operations.
    Layer 1 (deterministic detection) works without it.
    """

    def __init__(self) -> None:
        self.provider: str = os.environ.get(
            "TRENTINA_MODEL_PROVIDER",
            DEFAULT_PROVIDER,
        )

        raw_key = os.environ.get("GEMINI_API_KEY", "")
        self.api_key: SecretStr = SecretStr(raw_key) if raw_key else SecretStr("")
        self.openai_api_key: str = os.environ.get("OPENAI_API_KEY", "")
        self.anthropic_api_key: str = os.environ.get("ANTHROPIC_API_KEY", "")
        self.ollama_base_url: str = os.environ.get(
            "OLLAMA_BASE_URL",
            DEFAULT_OLLAMA_BASE_URL,
        )
        self.ollama_model: str = os.environ.get("OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL)

        self.model: str = os.environ.get("QUARANTINE_MODEL", DEFAULT_MODEL)
        self.search_model: str = os.environ.get("QUARANTINE_SEARCH_MODEL", DEFAULT_SEARCH_MODEL)
        if "QUARANTINE_FALLBACK" in os.environ:
            from .errors import ConfigError

            # Gone as of 0.31.0, and refused rather than ignored: it only ever
            # governed clean_*, defaulted to failing OPEN, and an operator who
            # still sets it believes a knob exists that no longer does.
            raise ConfigError(
                "QUARANTINE_FALLBACK no longer exists (0.31.0). block_* and clean_* "
                "now refuse when a layer cannot run; set TRENTINA_REQUIRE_L3=false "
                "(or TRENTINA_REQUIRE_L2=false) to deliver with a warning instead."
            )
        # Constitution-level default: block and clean need a verdict from
        # every layer. False turns that layer's ABSENCE into a warning; it
        # never excuses a partial scan and never stops a layer that can run.
        self.require_l2: bool = bool_env("TRENTINA_REQUIRE_L2", True)
        self.require_l3: bool = bool_env("TRENTINA_REQUIRE_L3", True)
        self.max_content: int = int(
            os.environ.get("QUARANTINE_MAX_CONTENT", str(DEFAULT_MAX_CONTENT))
        )

        fallback_raw = os.environ.get("TRENTINA_PROVIDER_FALLBACK", "")
        fallback_list = [p.strip() for p in fallback_raw.split(",") if p.strip()]
        for p in fallback_list:
            if p not in SUPPORTED_PROVIDERS:
                from .errors import ConfigError

                raise ConfigError(
                    f"Unknown fallback provider {p!r}. Supported: {SUPPORTED_PROVIDERS}"
                )
        self.provider_fallback: list[str] = fallback_list

        self.classifier_threshold: float = float(
            os.environ.get("CLASSIFIER_THRESHOLD", str(DEFAULT_CLASSIFIER_THRESHOLD))
        )
        self.classifier_model_path: str = os.environ.get(
            "CLASSIFIER_MODEL_PATH", DEFAULT_CLASSIFIER_MODEL_PATH
        )
        self.classifier_max_tokens: int = int(
            os.environ.get("CLASSIFIER_MAX_TOKENS", str(DEFAULT_CLASSIFIER_MAX_TOKENS))
        )
        self.classifier_threads: int = int(
            os.environ.get("CLASSIFIER_THREADS", str(DEFAULT_CLASSIFIER_THREADS))
        )

        home_db = str(Path.home() / ".local" / "share" / "mcp-trentina" / "trentina.db")
        self.db_path: str = os.environ.get("QUARANTINE_DB", home_db)

        # The perimeter's own store, deliberately a SEPARATE database file
        # rather than another table next to the blocklist. On today's
        # single-uid deployment that buys no isolation — both files belong
        # to the same process — but it is what makes a later move to a real
        # database able to give the two a different owner and a different
        # code path. Cheap now, impossible to retrofit once callers assume
        # one connection.
        self.perimeter_db_path: str = os.environ.get(
            "TRENTINA_PERIMETER_DB",
            str(Path(self.db_path).parent / "perimeter.db"),
        )

        trust_config_path = os.environ.get(
            "QUARANTINE_TRUST_CONFIG",
            str(Path.home() / ".config" / "mcp-env" / "mcp-trentina-trust.json"),
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

    def ensure_perimeter_db_dir(self) -> None:
        """Create the perimeter database directory if it does not exist."""
        Path(self.perimeter_db_path).parent.mkdir(parents=True, exist_ok=True)


def get_config() -> Config:
    """Get or create the singleton configuration."""
    global _config
    if _config is None:
        _config = Config()
    return _config
