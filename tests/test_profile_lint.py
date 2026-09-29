"""profiles.yaml posture lint (#269): shared write backends, toxic flows, fail-closed defaults."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_trentina_crunchtools.gateway import profile_lint
from mcp_trentina_crunchtools.gateway.profile_lint import (
    check_require_defaults,
    classify,
    held_tools,
    lint_file,
    main,
)

FIXTURES = Path(__file__).parent / "fixtures" / "profile-lint"
REPO = Path(__file__).resolve().parent.parent


def _codes(path: Path) -> list[str]:
    return [f.code for f in lint_file(path)]


class TestClassify:
    @pytest.mark.parametrize(
        "name",
        [
            "create_issue",
            "memory_store",
            "github_update_issue",
            "trigger_workflow",
            "rerun_failed_jobs",
            "set_ticket_status",
            "deletePostTool",
            "add_time_worked",
        ],
    )
    def test_writes(self, name: str) -> None:
        assert "write" in classify(name)

    @pytest.mark.parametrize(
        "name",
        [
            "send_message",
            "personal_send_gmail_message",
            "reply_to_ticket",
            "crunch_create_post",
            "integrationSchedulePostTool",
            "add_ticket_comment",
        ],
    )
    def test_outbound(self, name: str) -> None:
        assert "outbound" in classify(name)

    @pytest.mark.parametrize(
        "name", ["get_ticket", "crunch_get_post", "list_posts", "search_messages", "wiki_search"]
    )
    def test_reads(self, name: str) -> None:
        assert classify(name) == set()

    def test_a_wildcard_holds_what_it_could_admit(self) -> None:
        assert held_tools({"tools_allow": ["*"]})["*"] >= {"write", "outbound"}
        assert "write" in held_tools({"tools_allow": ["memory_*"]})["memory_*"]
        assert held_tools({"tools_allow": ["get_*", "list_*"]}) == {}

    def test_deny_is_honoured(self) -> None:
        backend = {"tools_allow": ["*"], "tools_deny": ["*"]}
        assert held_tools(backend) == {}


class TestFixtures:
    def test_clean(self) -> None:
        assert lint_file(FIXTURES / "clean.yaml") == []

    def test_shared_write_backends(self) -> None:
        messages = [str(f) for f in lint_file(FIXTURES / "shared_write.yaml")]
        shared = [m for m in messages if m.startswith("shared-write-backend")]
        # memory: kagetora/takeda declared; josui pairs with each of them are not.
        # rt: kagetora/josui declared with an empty reason, which does not count.
        assert len(shared) == 3, messages
        assert not any("'kagetora'" in m and "'takeda'" in m for m in shared)
        assert any("mcp-rt" in m and "'josui'" in m and "'kagetora'" in m for m in shared)

    def test_toxic_flow(self) -> None:
        findings = [str(f) for f in lint_file(FIXTURES / "toxic.yaml")]
        toxic = sorted(f for f in findings if f.startswith("toxic-flow"))
        assert len(toxic) == 2, findings
        assert "'catch-all'" in toxic[0]
        toxic = toxic[1:]
        assert "'toxic'" in toxic[0]
        assert "personal_send_gmail_message" in toxic[0]
        assert "postiz:*" in toxic[0]

    def test_the_shipped_example_is_clean(self) -> None:
        assert lint_file(REPO / "examples" / "profiles-agent1.yaml") == []


class TestRequireDefaults:
    def test_the_real_config_is_fail_closed(self) -> None:
        assert check_require_defaults() == []

    @pytest.mark.parametrize(
        "source",
        [
            'x = bool_env("TRENTINA_REQUIRE_L3", False)',
            'x = bool_env("TRENTINA_REQUIRE_L2")',
            'x = os.environ.get("TRENTINA_REQUIRE_L2", "true")',
            'x = bool_env(name="TRENTINA_REQUIRE_L2", default=False)',
            'x = os.getenv(key="TRENTINA_REQUIRE_L3")',
        ],
    )
    def test_an_open_default_is_a_finding(self, source: str) -> None:
        assert [f.code for f in check_require_defaults(source)] == ["require-default-open"]

    def test_a_keyword_default_of_true_is_closed(self) -> None:
        assert check_require_defaults('x = bool_env("TRENTINA_REQUIRE_L2", default=True)') == []

    def test_losing_the_switch_is_a_finding(self) -> None:
        assert [f.code for f in check_require_defaults("x = 1")] == ["require-default-open"]


class TestEntrypoint:
    def test_exit_codes(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main([str(FIXTURES / "clean.yaml")]) == 0
        assert main([str(FIXTURES / "toxic.yaml")]) == 1
        assert "toxic-flow" in capsys.readouterr().out
        assert main([str(FIXTURES / "missing.yaml")]) == 2
        assert main([]) == 2

    def test_module_is_runnable(self) -> None:
        assert callable(profile_lint.main)
