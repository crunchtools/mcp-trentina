"""Tests for tools/reload.py — apply a profiles.yaml edit without a restart.

The reload is exercised against a real YAML file on disk and the real loader,
because the bug it fixes lived exactly in the gap between the file and the
in-memory registry: a test that hands the tool a pre-built Profile would
never notice that gap reopening.

Two properties get the most attention here, because they are the two that
make the tool worth having rather than merely present:

* a refused reload leaves the running config untouched, and
* a reload re-judges nothing, so it costs seconds instead of the forty
  minutes a restart spends re-running ingress defense over every tool
  description.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mcp_trentina_crunchtools.gateway import compress
from mcp_trentina_crunchtools.gateway.compress import set_profiles
from mcp_trentina_crunchtools.gateway.filter import filter_tools
from mcp_trentina_crunchtools.gateway.loader import (
    get_active_config,
    load_profiles,
    register_active_config,
    reset_active_config,
)
from mcp_trentina_crunchtools.gateway.router import (
    _profile_tools_cache,
    invalidate_profile_cache,
    route_jsonrpc,
)
from mcp_trentina_crunchtools.gateway.sessions import session_registry
from mcp_trentina_crunchtools.quarantine.classifier import ClassifierResult
from mcp_trentina_crunchtools.tools.reload import reload_profiles

pytestmark = pytest.mark.asyncio

_ROUTER = "mcp_trentina_crunchtools.gateway.router"
_INGRESS = "mcp_trentina_crunchtools.gateway.ingress_defense"

_BENIGN = ClassifierResult(label="BENIGN", score=0.01, latency_ms=1.0)

BASE_YAML = """\
profiles:
  alpha:
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      jira:
        url: http://jira:1/mcp
        tools_allow: ["*"]
        tools_deny: []
  beta:
    auth:
      bearer_token_env: TEST_BETA_TOKEN
    backends:
      wiki:
        url: http://wiki:1/mcp
        tools_allow: ["*"]
"""

# alpha alone: the tail of the file, from "  beta:" on, cut off.
ALPHA_ONLY_YAML = BASE_YAML.split("  beta:", maxsplit=1)[0]

DENIED_YAML = BASE_YAML.replace(
    '        tools_deny: []\n',
    '        tools_deny: ["jira_delete_issue"]\n',
)


@pytest.fixture
def profiles_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """A running gateway: profiles on disk, loaded, and registered as live."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "alpha-secret")
    monkeypatch.setenv("TEST_BETA_TOKEN", "beta-secret")
    path = tmp_path / "profiles.yaml"
    path.write_text(BASE_YAML, encoding="utf-8")
    config = load_profiles(path)
    register_active_config(path, config, {})
    set_profiles(config.profiles)
    yield path
    reset_active_config()
    compress._profiles = None
    session_registry.reset()


def _registry() -> dict[str, Any]:
    active = get_active_config()
    assert active is not None
    return active.config.profiles


def _tools_result(names: list[str]) -> list[dict[str, Any]]:
    return [{"name": n, "description": f"{n} does a thing", "inputSchema": {}} for n in names]


async def _list_tools(profile_name: str) -> list[str]:
    """Run a real tools/list against a mocked backend, returning tool names."""
    response = await route_jsonrpc(
        _registry()[profile_name],
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    return [t["name"] for t in response["result"]["tools"]]


class TestRefusedReload:
    async def test_uninitialized_gateway_reports_instead_of_raising(self) -> None:
        """A reload before startup is an answerable question, not a crash."""
        reset_active_config()
        result = await reload_profiles()
        assert result["reloaded"] is False
        assert result["error"] == "gateway not initialized"

    async def test_invalid_yaml_keeps_the_running_config(
        self, profiles_path: Path
    ) -> None:
        """A file that does not parse changes nothing and says why."""
        profiles_path.write_text("profiles: [this is not a mapping]", encoding="utf-8")
        result = await reload_profiles()

        assert result["reloaded"] is False
        assert "profiles" in result["error"]
        assert result["note"] == "running configuration left unchanged"
        assert sorted(_registry()) == ["alpha", "beta"]

    async def test_missing_env_var_keeps_the_running_config(
        self, profiles_path: Path
    ) -> None:
        """Half a config is never installed: the unresolvable secret refuses it."""
        profiles_path.write_text(
            BASE_YAML + """\
  gamma:
    auth:
      bearer_token_env: TEST_GAMMA_TOKEN_NOT_SET
    backends:
      wiki:
        url: http://wiki:1/mcp
""",
            encoding="utf-8",
        )
        result = await reload_profiles()

        assert result["reloaded"] is False
        assert "TEST_GAMMA_TOKEN_NOT_SET" in result["error"]
        assert "gamma" not in _registry()

    async def test_dangling_llm_provider_reference_is_refused(
        self, profiles_path: Path
    ) -> None:
        """Startup's cross-validation is re-run, or the 502 arrives later instead."""
        profiles_path.write_text(
            BASE_YAML.replace(
                "  beta:\n",
                "  beta:\n    llm_keys:\n      anthropic:\n        api_key: sk-test\n",
            ),
            encoding="utf-8",
        )
        result = await reload_profiles()

        assert result["reloaded"] is False
        assert "anthropic" in result["error"]
        assert not _registry()["beta"].llm_keys


class TestAppliedReload:
    async def test_deny_edit_is_in_force_immediately(
        self, profiles_path: Path
    ) -> None:
        """The edit that used to be inert: a new deny pattern, applied."""
        backend = _registry()["alpha"].backends["jira"]
        assert filter_tools([{"name": "jira_delete_issue"}], backend)

        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        result = await reload_profiles()

        assert result["reloaded"] is True
        reloaded_backend = _registry()["alpha"].backends["jira"]
        assert not filter_tools([{"name": "jira_delete_issue"}], reloaded_backend)

    async def test_registry_dict_identity_survives_the_swap(
        self, profiles_path: Path
    ) -> None:
        """Every route holds THIS dict; replacing it would strand them all."""
        before = _registry()
        compress_view = compress.get_profiles()

        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        await reload_profiles()

        assert _registry() is before
        assert compress_view is before

    async def test_diff_reports_allow_deny_and_backend_moves(
        self, profiles_path: Path
    ) -> None:
        profiles_path.write_text(
            DENIED_YAML.replace(
                "      wiki:\n        url: http://wiki:1/mcp\n"
                "        tools_allow: [\"*\"]\n",
                "      rt:\n        url: http://rt:1/mcp\n"
                "        tools_allow: [\"rt_get*\"]\n",
            ),
            encoding="utf-8",
        )
        result = await reload_profiles()

        assert result["profiles"]["changed"] == ["alpha", "beta"]
        alpha = result["changes"]["alpha"]["backends_changed"]["jira"]
        assert alpha["tools_deny"] == {"added": ["jira_delete_issue"], "removed": []}
        assert result["changes"]["beta"]["backends_added"] == ["rt"]
        assert result["changes"]["beta"]["backends_removed"] == ["wiki"]

    async def test_diff_names_guard_parameters_without_echoing_patterns(
        self, profiles_path: Path
    ) -> None:
        """The motivating edit: a destructive tool gets a parameter guard."""
        profiles_path.write_text(
            BASE_YAML.replace(
                '        tools_deny: []\n',
                '        tools_deny: []\n'
                '        parameter_guards:\n'
                '          jira_delete_issue:\n'
                '            key:\n'
                '              deny: ["PROD-*"]\n',
            ),
            encoding="utf-8",
        )
        result = await reload_profiles()

        guards = result["changes"]["alpha"]["backends_changed"]["jira"]["parameter_guards"]
        assert guards == {"jira_delete_issue": {"parameters_added": ["key"]}}
        assert "PROD-" not in str(result)

    async def test_added_and_removed_profiles_are_reported_and_applied(
        self, profiles_path: Path
    ) -> None:
        swapped_yaml = ALPHA_ONLY_YAML + """\
  gamma:
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends:
      wiki:
        url: http://wiki:1/mcp
"""
        profiles_path.write_text(swapped_yaml, encoding="utf-8")
        result = await reload_profiles()

        assert result["profiles"]["added"] == ["gamma"]
        assert result["profiles"]["removed"] == ["beta"]
        assert sorted(_registry()) == ["alpha", "gamma"]

    async def test_unchanged_profiles_are_left_alone(
        self, profiles_path: Path
    ) -> None:
        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        result = await reload_profiles()

        assert result["profiles"]["unchanged"] == ["beta"]
        assert list(result["changes"]) == ["alpha"]

    async def test_sessions_for_a_removed_profile_are_dropped(
        self, profiles_path: Path
    ) -> None:
        """A session whose profile no longer exists can only 404 from here."""
        session_registry.create_session("beta")
        profiles_path.write_text(ALPHA_ONLY_YAML, encoding="utf-8")

        result = await reload_profiles()

        assert result["sessions_dropped"] == 1
        assert not session_registry.get_sessions_for_profile("beta")

    async def test_changed_profile_notifies_its_sessions(
        self, profiles_path: Path
    ) -> None:
        """Clients refresh their tool list without a manual /mcp reconnect."""
        session_id = session_registry.create_session("alpha")
        queue = session_registry.subscribe(session_id)
        profiles_path.write_text(DENIED_YAML, encoding="utf-8")

        result = await reload_profiles()

        assert result["sessions_notified"] == {"alpha": 1}
        assert queue.get_nowait()["method"] == "notifications/tools/listChanged"


class TestUnappliedSections:
    async def test_llm_providers_change_is_reported_as_restart_only(
        self, profiles_path: Path
    ) -> None:
        """The section bound into a route closure at startup cannot reload."""
        profiles_path.write_text(
            BASE_YAML + """\
llm_providers:
  anthropic:
    base_url: https://api.anthropic.com
    api_key_env: TEST_ALPHA_TOKEN
""",
            encoding="utf-8",
        )
        result = await reload_profiles()

        assert result["reloaded"] is True
        assert any("llm_providers" in note for note in result["not_applied"])

    async def test_a_plain_profile_edit_reports_nothing_unapplied(
        self, profiles_path: Path
    ) -> None:
        profiles_path.write_text(DENIED_YAML, encoding="utf-8")
        result = await reload_profiles()
        assert result["not_applied"] == []


class TestCacheBehaviour:
    async def test_changed_profile_rebuilds_and_unchanged_one_does_not(
        self, profiles_path: Path
    ) -> None:
        """Only the edited profile's aggregate is thrown away."""
        with patch(
            f"{_ROUTER}.list_backend_tools",
            AsyncMock(return_value=_tools_result(["jira_get_issue"])),
        ), patch(
            "mcp_trentina_crunchtools.defense.classify_async",
            AsyncMock(return_value=_BENIGN),
        ):
            await _list_tools("alpha")
            await _list_tools("beta")
            assert set(_profile_tools_cache) == {"alpha", "beta"}

            profiles_path.write_text(DENIED_YAML, encoding="utf-8")
            result = await reload_profiles()

        assert result["caches_invalidated"] == ["alpha"]
        assert set(_profile_tools_cache) == {"beta"}

    async def test_reload_rejudges_no_tool_descriptions(
        self, profiles_path: Path
    ) -> None:
        """The whole point: a profile edit costs zero defense-pipeline runs.

        A restart re-judges every description through L1/L2/L3 because the
        process loses the verdict cache. A reload keeps it, and the verdict
        key is (kind, thresholds, text) — none of which a tools_deny edit
        touches — so the rebuilt aggregate is a pure cache read.
        """
        from mcp_trentina_crunchtools.gateway import ingress_defense

        judged: list[str] = []
        real_defend = ingress_defense.defend

        async def counting_defend(*args: Any, **kwargs: Any) -> Any:
            judged.append(str(kwargs.get("source")))
            return await real_defend(*args, **kwargs)

        with patch(
            f"{_ROUTER}.list_backend_tools",
            AsyncMock(return_value=_tools_result(["jira_get_issue", "jira_delete_issue"])),
        ), patch(
            "mcp_trentina_crunchtools.defense.classify_async",
            AsyncMock(return_value=_BENIGN),
        ), patch(f"{_INGRESS}.defend", counting_defend):
            assert await _list_tools("alpha") == ["jira__jira_get_issue", "jira__jira_delete_issue"]
            after_warmup = len(judged)
            assert after_warmup == 2

            profiles_path.write_text(DENIED_YAML, encoding="utf-8")
            await reload_profiles()

            assert await _list_tools("alpha") == ["jira__jira_get_issue"]

        assert len(judged) == after_warmup

    async def test_an_inflight_build_is_not_cached_across_an_invalidation(
        self, profiles_path: Path
    ) -> None:
        """An aggregate assembled from the pre-reload profile must not land.

        Popping the cache key is not enough on its own: the build already
        running writes after the pop, and would reinstate the allowlist the
        reload just replaced.
        """
        gate = asyncio.Event()

        async def slow_list(*_args: Any, **_kwargs: Any) -> list[dict[str, Any]]:
            await gate.wait()
            return _tools_result(["jira_delete_issue"])

        with patch(f"{_ROUTER}.list_backend_tools", slow_list), patch(
            "mcp_trentina_crunchtools.defense.classify_async",
            AsyncMock(return_value=_BENIGN),
        ):
            build = asyncio.create_task(_list_tools("alpha"))
            await asyncio.sleep(0)
            invalidate_profile_cache("alpha")
            gate.set()
            assert await build == ["jira__jira_delete_issue"]

        assert "alpha" not in _profile_tools_cache
