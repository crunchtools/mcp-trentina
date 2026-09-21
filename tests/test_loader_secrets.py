"""_FILE secret indirection in gateway/loader.py.

The crunchtools mcp-server profile requires every credential env var FOO to
also be readable from the file named by FOO_FILE, because that is what podman
secrets, Kubernetes secret volumes and systemd LoadCredential= produce. The
value then lives in a mode-0600 file rather than in /proc/<pid>/environ, which
anything able to inspect the container can read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
from mcp_trentina_crunchtools.gateway.loader import (
    _expand_env_refs,
    _read_secret_env,
    _require_env,
    load_profiles,
)

PROFILE_YAML = """\
profiles:
  josui:
    auth:
      bearer_token_env: TEST_BEARER
    backends: {}
"""


class TestReadSecretEnv:
    def test_plain_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_X", "from-env")
        assert _read_secret_env("SECRET_X") == "from-env"

    def test_absent_is_empty_not_an_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SECRET_X", raising=False)
        monkeypatch.delenv("SECRET_X_FILE", raising=False)
        assert _read_secret_env("SECRET_X") == ""

    def test_file_variant(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        secret = tmp_path / "token"
        secret.write_text("from-file\n")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert _read_secret_env("SECRET_X") == "from-file"

    def test_file_takes_precedence_over_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A mounted secret is the deployment-time answer; a stale inherited
        env var must not quietly outrank it."""
        secret = tmp_path / "token"
        secret.write_text("from-file")
        monkeypatch.setenv("SECRET_X", "from-env")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert _read_secret_env("SECRET_X") == "from-file"

    def test_trailing_newline_stripped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("  padded  \n\n")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert _read_secret_env("SECRET_X") == "padded"

    def test_missing_file_is_an_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Named-but-unreadable is a broken deployment, not an absent secret,
        so it must not fall through to the plain env var."""
        monkeypatch.setenv("SECRET_X", "from-env")
        monkeypatch.setenv("SECRET_X_FILE", str(tmp_path / "nope"))
        with pytest.raises(ProfileConfigError, match="cannot read secret file"):
            _read_secret_env("SECRET_X")

    def test_empty_file_is_empty(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("\n")
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        assert _read_secret_env("SECRET_X") == ""

    def test_loose_permissions_warn_but_do_not_fail(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("value")
        secret.chmod(0o644)
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        with caplog.at_level("WARNING"):
            assert _read_secret_env("SECRET_X") == "value"
        assert "more permissive than 0600" in caplog.text

    def test_tight_permissions_are_silent(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        secret = tmp_path / "token"
        secret.write_text("value")
        secret.chmod(0o600)
        monkeypatch.setenv("SECRET_X_FILE", str(secret))
        with caplog.at_level("WARNING"):
            _read_secret_env("SECRET_X")
        assert "more permissive" not in caplog.text


class TestConsumersRouteThroughIt:
    """Every secret path, not just the new ones — a half-compliant loader is
    worse than one that was never started."""

    def test_require_env_reads_the_file_variant(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "tok"
        secret.write_text("bearer-from-file")
        monkeypatch.delenv("TEST_BEARER", raising=False)
        monkeypatch.setenv("TEST_BEARER_FILE", str(secret))
        assert _require_env("p", "TEST_BEARER", "bearer token").get_secret_value() == (
            "bearer-from-file"
        )

    def test_require_env_error_names_both_spellings(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEST_BEARER", raising=False)
        monkeypatch.delenv("TEST_BEARER_FILE", raising=False)
        with pytest.raises(ProfileConfigError, match="TEST_BEARER_FILE"):
            _require_env("p", "TEST_BEARER", "bearer token")

    def test_backend_header_expansion(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = tmp_path / "hdr"
        secret.write_text("hdr-from-file")
        monkeypatch.delenv("HDR_TOKEN", raising=False)
        monkeypatch.setenv("HDR_TOKEN_FILE", str(secret))
        out = _expand_env_refs("Bearer ${HDR_TOKEN}", context="t")
        assert out == "Bearer hdr-from-file"

    def test_end_to_end_profile_load(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cfg = tmp_path / "profiles.yaml"
        cfg.write_text(PROFILE_YAML)
        secret = tmp_path / "bearer"
        secret.write_text("tok-from-file\n")
        monkeypatch.delenv("TEST_BEARER", raising=False)
        monkeypatch.setenv("TEST_BEARER_FILE", str(secret))

        loaded = load_profiles(cfg)
        token = loaded.profiles["josui"].auth.bearer_token
        assert token is not None
        assert token.get_secret_value() == "tok-from-file"
