"""Tests for gateway/profile.py and gateway/loader.py."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
from mcp_trentina_crunchtools.gateway.loader import load_profiles
from mcp_trentina_crunchtools.gateway.profile import (
    AuthConfig,
    Backend,
    DefenseConfig,
    ParameterConstraint,
    Profile,
)


class TestProfileModel:
    """Pydantic-level unit tests for Profile / Backend / DefenseConfig."""

    def test_minimal_profile_valid(self) -> None:
        p = Profile(
            name="josui",
            auth=AuthConfig(bearer_token_env="AIRLOCK_PROFILE_JOSUI_TOKEN"),
        )
        assert p.name == "josui"
        assert p.auth.bearer_token_env == "AIRLOCK_PROFILE_JOSUI_TOKEN"
        assert p.backends == {}
        assert p.defense.sanitize is True
        assert p.defense.quarantine is True

    def test_profile_with_backends(self) -> None:
        p = Profile(
            name="kagetora",
            auth=AuthConfig(bearer_token_env="AIRLOCK_PROFILE_KAGETORA_TOKEN"),
            backends={
                "mcp-slack": Backend(url="http://mcp-slack:8005/mcp"),
                "mcp-atlassian": Backend(
                    url="http://mcp-atlassian:8021/mcp",
                    tools_deny=["jira_delete_issue"],
                ),
            },
        )
        assert len(p.backends) == 2
        assert p.backends["mcp-atlassian"].tools_deny == ["jira_delete_issue"]

    def test_bad_profile_name(self) -> None:
        with pytest.raises(ValidationError):
            Profile(
                name="Has_Underscore",
                auth=AuthConfig(bearer_token_env="X"),
            )

    def test_bad_backend_name(self) -> None:
        with pytest.raises(ValidationError):
            Profile(
                name="ok",
                auth=AuthConfig(bearer_token_env="X"),
                backends={"BAD_NAME": Backend(url="http://example/mcp")},
            )

    def test_bad_url_scheme(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="ftp://example/mcp")

    def test_internal_url_scheme_accepted(self) -> None:
        b = Backend(url="internal://web")
        assert b.is_internal is True

    def test_http_backend_is_not_internal(self) -> None:
        assert Backend(url="http://x/mcp").is_internal is False

    def test_internal_url_requires_slug_label(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="internal://")
        with pytest.raises(ValidationError):
            Backend(url="internal://Bad_Label")

    def test_bad_env_name(self) -> None:
        with pytest.raises(ValidationError):
            AuthConfig(bearer_token_env="lowercase_not_allowed")

    def test_extra_keys_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            Profile.model_validate(
                {
                    "name": "x",
                    "auth": {"bearer_token_env": "T"},
                    "extra_unexpected_key": True,
                }
            )

    def test_bad_glob_pattern_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", tools_allow=["bad/pattern"])
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", tools_allow=["-leading-hyphen"])
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", tools_deny=["has space"])

    def test_glob_pattern_allowed(self) -> None:
        b = Backend(
            url="http://x/mcp",
            tools_allow=["*", "delete_*", "get_*_thing", "*_suffix"],
        )
        assert "*" in b.tools_allow

    def test_backend_with_parameter_guards(self) -> None:
        b = Backend(
            url="http://x/mcp",
            parameter_guards={
                "send_gmail_message": {
                    "to": ParameterConstraint(allow=["scott@gmail.com"]),
                    "cc": ParameterConstraint(allow=["scott@gmail.com"], deny=["banned@x.com"]),
                }
            },
        )
        assert "send_gmail_message" in b.parameter_guards
        assert b.parameter_guards["send_gmail_message"]["to"].allow == ["scott@gmail.com"]
        assert b.parameter_guards["send_gmail_message"]["cc"].deny == ["banned@x.com"]

    def test_parameter_guard_invalid_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ParameterConstraint(allow=["has;semicolon"])

    def test_parameter_guard_extra_keys_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ParameterConstraint.model_validate(
                {"allow": ["*"], "unknown_field": True}
            )

    def test_parameter_guard_valid_patterns(self) -> None:
        c = ParameterConstraint(allow=["*@redhat.com", "scott.mccarty@gmail.com", "*"])
        assert len(c.allow) == 3

    def test_list_timeout_defaults(self) -> None:
        b = Backend(url="http://x/mcp")
        assert b.list_timeout_seconds == 10.0
        assert b.timeout_seconds == 30.0

    def test_list_timeout_custom(self) -> None:
        b = Backend(url="http://x/mcp", list_timeout_seconds=5.0)
        assert b.list_timeout_seconds == 5.0

    def test_list_timeout_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", list_timeout_seconds=0)
        with pytest.raises(ValidationError):
            Backend(url="http://x/mcp", list_timeout_seconds=61.0)

    def test_defense_defaults(self) -> None:
        d = DefenseConfig()
        assert d.sanitize is True
        assert d.classify is True
        assert d.quarantine is True
        assert d.audit is True
        assert 0.0 <= d.classify_threshold <= 1.0
        assert 0.0 <= d.quarantine_threshold <= 1.0

    def test_defense_threshold_bounds(self) -> None:
        with pytest.raises(ValidationError):
            DefenseConfig(classify_threshold=1.5)
        with pytest.raises(ValidationError):
            DefenseConfig(quarantine_threshold=-0.1)

    def test_defense_provider_defaults_to_none(self) -> None:
        d = DefenseConfig()
        assert d.provider is None

    def test_defense_provider_valid_values(self) -> None:
        for name in ("gemini", "openai", "anthropic", "ollama"):
            d = DefenseConfig(provider=name)
            assert d.provider == name

    def test_defense_provider_invalid_rejected(self) -> None:
        with pytest.raises(ValidationError, match="Unknown provider"):
            DefenseConfig(provider="unsupported-llm")

    def test_defense_provider_in_profile_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  josui:
    auth:
      bearer_token_env: TEST_TOK
    defense:
      provider: anthropic
"""
        )
        monkeypatch.setenv("TEST_TOK", "x")
        gateway_cfg = load_profiles(cfg)
        assert gateway_cfg.profiles["josui"].defense.provider == "anthropic"

    def test_defense_provider_omitted_in_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  takeda:
    auth:
      bearer_token_env: TEST_TOK
"""
        )
        monkeypatch.setenv("TEST_TOK", "x")
        gateway_cfg = load_profiles(cfg)
        assert gateway_cfg.profiles["takeda"].defense.provider is None


class TestLoader:
    """End-to-end tests for the YAML profile loader."""

    def test_load_happy_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  josui:
    auth:
      bearer_token_env: AIRLOCK_PROFILE_JOSUI_TOKEN
    backends:
      mcp-slack:
        url: http://mcp-slack:8005/mcp
        tools_allow: ["*"]
        tools_deny: ["slack_destructive_*"]
"""
        )
        monkeypatch.setenv("AIRLOCK_PROFILE_JOSUI_TOKEN", "tok-josui")
        gateway_cfg = load_profiles(cfg)
        assert set(gateway_cfg.profiles) == {"josui"}
        token = gateway_cfg.profiles["josui"].auth.bearer_token
        assert token is not None
        assert token.get_secret_value() == "tok-josui"

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ProfileConfigError, match="not found"):
            load_profiles(tmp_path / "nope.yaml")

    def test_invalid_yaml(self, tmp_path: Path) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text("not: valid: yaml: [")
        with pytest.raises(ProfileConfigError, match="Invalid YAML"):
            load_profiles(cfg)

    def test_top_level_not_a_mapping(self, tmp_path: Path) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text("- a\n- b\n")
        with pytest.raises(ProfileConfigError, match="top-level mapping"):
            load_profiles(cfg)

    def test_missing_profiles_key(self, tmp_path: Path) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text("other_key: value\n")
        with pytest.raises(ProfileConfigError, match="non-empty 'profiles'"):
            load_profiles(cfg)

    def test_header_env_ref_expanded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  kagetora:
    auth:
      bearer_token_env: AIRLOCK_PROFILE_KAGETORA_TOKEN
    backends:
      memory:
        url: http://mcp-memory:8765/mcp
        headers:
          Authorization: "Bearer ${MCP_MEMORY_API_KEY}"
"""
        )
        monkeypatch.setenv("AIRLOCK_PROFILE_KAGETORA_TOKEN", "tok")
        monkeypatch.setenv("MCP_MEMORY_API_KEY", "memsecret")
        gateway_cfg = load_profiles(cfg)
        assert (
            gateway_cfg.profiles["kagetora"].backends["memory"].headers["Authorization"]
            == "Bearer memsecret"
        )

    def test_header_env_ref_missing_fails_closed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  kagetora:
    auth:
      bearer_token_env: AIRLOCK_PROFILE_KAGETORA_TOKEN
    backends:
      memory:
        url: http://mcp-memory:8765/mcp
        headers:
          Authorization: "Bearer ${MCP_MEMORY_API_KEY}"
"""
        )
        monkeypatch.setenv("AIRLOCK_PROFILE_KAGETORA_TOKEN", "tok")
        monkeypatch.delenv("MCP_MEMORY_API_KEY", raising=False)
        with pytest.raises(ProfileConfigError, match="MCP_MEMORY_API_KEY"):
            load_profiles(cfg)

    def test_missing_token_env(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  alice:
    auth:
      bearer_token_env: NEVER_SET_IN_ENV_FOR_TEST_123
"""
        )
        monkeypatch.delenv("NEVER_SET_IN_ENV_FOR_TEST_123", raising=False)
        with pytest.raises(ProfileConfigError, match="not set or empty"):
            load_profiles(cfg)

    def test_extra_key_in_yaml_rejected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(
            """
profiles:
  alice:
    auth:
      bearer_token_env: TEST_TOK
    unknown_field: oops
"""
        )
        monkeypatch.setenv("TEST_TOK", "x")
        with pytest.raises(ProfileConfigError):
            load_profiles(cfg)
