"""Pydantic v2 models for gateway profile configuration.

Profiles are loaded from YAML and define which backend MCP servers a consumer
can reach, which tools per backend are allowed, and which defense layers
apply to responses. Phase 1 stores the defense flags but does not apply
them — Phase 2 wires the defense pipeline in.

All models use `extra="forbid"` per the constitution; unrecognized keys in
profile YAML are a hard error at load time.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

PROFILE_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
BACKEND_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
GLOB_PATTERN_RE = re.compile(r"^[a-zA-Z0-9_*][a-zA-Z0-9_*-]*$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")

MAX_BACKEND_TIMEOUT_SECONDS = 300.0


class AuthConfig(BaseModel):
    """Per-profile bearer-token auth config.

    `bearer_token_env` is the env var name holding the actual token value;
    `bearer_token` is resolved at load time and never serialized.
    """

    model_config = ConfigDict(extra="forbid")

    bearer_token_env: str = Field(
        ..., description="Env var name whose value is the profile's bearer token"
    )
    bearer_token: SecretStr | None = Field(
        default=None, exclude=True, description="Resolved token (load-time only)"
    )

    @field_validator("bearer_token_env")
    @classmethod
    def env_name_is_uppercase_identifier(cls, v: str) -> str:
        """Reject lowercase, leading digits, or non-identifier characters."""
        if not ENV_NAME_RE.match(v):
            raise ValueError(
                f"bearer_token_env {v!r} must be an UPPERCASE env-var identifier"
            )
        return v


class Backend(BaseModel):
    """Per-profile backend MCP server config."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="MCP streamable-http URL of the backend")
    tools_allow: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Tool-name glob patterns to allow (default: all)",
    )
    tools_deny: list[str] = Field(
        default_factory=list,
        description="Tool-name glob patterns to deny (wins over tools_allow)",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Extra HTTP headers to send to the backend",
    )
    timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=MAX_BACKEND_TIMEOUT_SECONDS,
        description="Per-call backend timeout",
    )

    @field_validator("url")
    @classmethod
    def url_is_http_or_https(cls, v: str) -> str:
        """Restrict the URL scheme to http or https. SSE / stdio not supported."""
        if not v.startswith(("http://", "https://")):
            raise ValueError(f"Backend URL must start with http:// or https://: {v!r}")
        return v

    @field_validator("tools_allow", "tools_deny")
    @classmethod
    def glob_patterns_valid(cls, v: list[str]) -> list[str]:
        """Each glob must match GLOB_PATTERN_RE — restricted character set, no regex metachars."""
        for pat in v:
            if not GLOB_PATTERN_RE.match(pat):
                raise ValueError(
                    f"Invalid glob pattern {pat!r}: allowed characters are "
                    "alphanumerics, underscore, hyphen, and '*'; first character "
                    "may not be a hyphen"
                )
        return v


class DefenseConfig(BaseModel):
    """Per-profile defense-layer toggles. Phase 1 stores them; Phase 2 applies them."""

    model_config = ConfigDict(extra="forbid")

    sanitize: bool = Field(default=True, description="L1 sanitization on responses")
    classify: bool = Field(default=True, description="L2 Prompt Guard 2 classifier")
    classify_threshold: float = Field(
        default=0.5, ge=0.0, le=1.0, description="L2 score above which to flag"
    )
    quarantine: bool = Field(
        default=True,
        description="L3 quarantined Gemini re-extraction (token-cost control)",
    )
    quarantine_threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="L2 score above which to trigger L3 (when quarantine=true)",
    )
    audit: bool = Field(default=True, description="Write passthrough rows to SQLite")


class Profile(BaseModel):
    """One consumer profile: name, auth, backends, defense config."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Profile name (URL-safe slug)")
    auth: AuthConfig
    backends: dict[str, Backend] = Field(
        default_factory=dict,
        description="Backend MCP servers reachable from this profile",
    )
    defense: DefenseConfig = Field(default_factory=DefenseConfig)

    @field_validator("name")
    @classmethod
    def name_matches_re(cls, v: str) -> str:
        """Profile name must be a URL-safe slug (matches PROFILE_NAME_RE)."""
        if not PROFILE_NAME_RE.match(v):
            raise ValueError(f"Profile name {v!r} must match ^[a-z][a-z0-9-]*$")
        return v

    @field_validator("backends")
    @classmethod
    def backend_names_match_re(cls, v: dict[str, Backend]) -> dict[str, Backend]:
        """Each backend dict key must be a URL-safe slug (matches BACKEND_NAME_RE)."""
        for name in v:
            if not BACKEND_NAME_RE.match(name):
                raise ValueError(f"Backend name {name!r} must match ^[a-z][a-z0-9-]*$")
        return v
