"""Pydantic input validation models for mcp-trentina-crunchtools."""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

MAX_URL_LENGTH = 4096
MAX_PATH_LENGTH = 1024
MAX_PROMPT_LENGTH = 2000
MAX_CONTENT_DISPLAY = 50_000

ALLOWED_TEXT_EXTENSIONS = frozenset(
    {
        ".md",
        ".txt",
        ".rst",
        ".adoc",
        ".asciidoc",
        ".py",
        ".js",
        ".ts",
        ".go",
        ".rs",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".rb",
        ".php",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".yaml",
        ".yml",
        ".toml",
        ".json",
        ".xml",
        ".csv",
        ".html",
        ".htm",
        ".css",
        ".scss",
        ".cfg",
        ".ini",
        ".conf",
        ".env.example",
        ".dockerfile",
        ".containerfile",
        ".gitignore",
        ".dockerignore",
        ".editorconfig",
    }
)


class FetchInput(BaseModel, extra="forbid"):
    """Input for quarantine_fetch and safe_fetch."""

    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    prompt: str = Field(
        default="Extract the main content from this page.",
        max_length=MAX_PROMPT_LENGTH,
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            msg = "URL must start with http:// or https://"
            raise ValueError(msg)
        return v


class ReadInput(BaseModel, extra="forbid"):
    """Input for quarantine_read and safe_read."""

    path: str = Field(..., min_length=1, max_length=MAX_PATH_LENGTH)
    prompt: str = Field(
        default="Extract the main content from this file.",
        max_length=MAX_PROMPT_LENGTH,
    )

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str) -> str:
        if ".." in v:
            msg = "Path traversal not allowed"
            raise ValueError(msg)
        return v


class ScanInput(BaseModel, extra="forbid"):
    """Input for quarantine_scan."""

    url: str | None = Field(default=None, max_length=MAX_URL_LENGTH)
    path: str | None = Field(default=None, max_length=MAX_PATH_LENGTH)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith(("http://", "https://")):
            msg = "URL must start with http:// or https://"
            raise ValueError(msg)
        return v

    @field_validator("path")
    @classmethod
    def validate_path(cls, v: str | None) -> str | None:
        if v is not None and ".." in v:
            msg = "Path traversal not allowed"
            raise ValueError(msg)
        return v
