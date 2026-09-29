"""The boundary-review eval suite is well-formed, and its grader grades (#90).

No network: the model calls themselves run in CI's boundary-review job, only
when ANTHROPIC_API_KEY is set. This keeps EVAL.yml, the fixtures and the
grading rules from rotting in between.
"""

from __future__ import annotations

import ast
import json
import re
from typing import Any

import httpx
import pytest

from tests.boundary_review_eval import (
    DEFAULT_EVAL,
    REPO,
    Client,
    EvalSetupError,
    cheap_match,
    load_suite,
    over_severity,
    run,
    run_case,
)

SKILL = DEFAULT_EVAL.parent / "SKILL.md"


def _finding(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "file": "x.py",
        "line": 1,
        "obligation": "O1",
        "verdict": "UNSOUND",
        "severity": "high",
        "title": "",
        "evidence": [],
        "scenario": "",
        "fix": "",
    }
    return {**base, **kw}


class TestSuite:
    def test_loads_with_enough_cases(self) -> None:
        suite = load_suite(DEFAULT_EVAL)
        kinds = [c["kind"] for c in suite["cases"]]
        assert kinds.count("known_bad") >= 6
        assert kinds.count("control") >= 2

    def test_every_fixture_exists_and_parses(self) -> None:
        suite = load_suite(DEFAULT_EVAL)
        base = (DEFAULT_EVAL.parent / suite["fixtures_dir"]).resolve()
        assert base.is_relative_to(REPO)
        for case in suite["cases"]:
            ast.parse((base / case["fixture"]).read_text())

    def test_every_expected_obligation_is_defined_in_the_skill(self) -> None:
        skill = SKILL.read_text()
        suite = load_suite(DEFAULT_EVAL)
        for case in suite["cases"]:
            for item in case.get("must_find", []):
                for code in item["obligations"]:
                    assert f"| {code} " in skill, (case["name"], code)

    def test_skill_frontmatter_names_its_directory(self) -> None:
        head = SKILL.read_text().split("---")[1]
        assert "name: trentina-boundary-review" in head
        assert "allowed-tools:" in head


class TestGrader:
    def test_obligation_code_matches(self) -> None:
        assert cheap_match({"obligations": ["O4"]}, [_finding(obligation="O4 OUTCOME-FIDELITY")])

    def test_keyword_matches_case_insensitively(self) -> None:
        found = [_finding(obligation="O9", title="Refusal echoes Detected_At")]
        assert cheap_match({"obligations": ["O2"], "keywords": ["detected_at"]}, found)

    def test_neither_is_a_miss(self) -> None:
        assert not cheap_match({"obligations": ["O6"], "keywords": ["redirect"]}, [_finding()])

    def test_severity_ceiling_is_inclusive(self) -> None:
        found = [_finding(severity="low"), _finding(severity="medium"), _finding(severity="high")]
        assert [f["severity"] for f in over_severity(found, "medium")] == ["medium", "high"]

    async def test_refuses_to_run_without_a_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(EvalSetupError, match="ANTHROPIC_API_KEY"):
            await run(DEFAULT_EVAL, [])


def _message(body: dict[str, Any]) -> httpx.Response:
    return httpx.Response(
        200,
        json={"stop_reason": "end_turn", "content": [{"type": "text", "text": json.dumps(body)}]},
    )


SUITE = load_suite(DEFAULT_EVAL)
CASES = {c["name"]: c for c in SUITE["cases"]}


async def _run(name: str, findings: list[dict[str, Any]], judge_yes: bool) -> Any:
    """Run one case against a mocked API: the reviewer returns ``findings`` and
    the judge answers ``judge_yes`` for every id it is asked about."""

    def api(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert request.headers["x-api-key"] == "k"
        assert body["output_config"]["format"]["type"] == "json_schema"
        if body["model"] == SUITE["reviewer_model"]:
            assert "trentina-boundary-review" in body["system"]
            return _message({"findings": findings, "proved": []})
        ids = re.findall(r"id=([\w-]+)", body["messages"][0]["content"])
        return _message({"verdicts": [{"id": i, "yes": judge_yes, "reason": ""} for i in ids]})

    skill = SKILL.read_text()
    async with httpx.AsyncClient(transport=httpx.MockTransport(api)) as http:
        return await run_case(Client("k", http), SUITE, skill, CASES[name], DEFAULT_EVAL.parent)


class TestMockedRun:
    """One case end to end over a mocked Messages API: request shape and grading."""

    async def test_a_known_bad_case_found_passes(self) -> None:
        found = [_finding(obligation="O5", title="classify blocks the event loop")]
        result = await _run("bad_02_sync_classify_in_coroutine", found, judge_yes=True)
        assert result.passed, result.notes

    async def test_the_judge_can_veto_a_keyword_hit(self) -> None:
        found = [_finding(obligation="O5", title="unrelated regex")]
        result = await _run("bad_02_sync_classify_in_coroutine", found, judge_yes=False)
        assert not result.passed

    async def test_a_control_flagged_fails(self) -> None:
        found = [_finding(obligation="O2", severity="high", title="head only")]
        result = await _run("ctrl_01_flag_mode_truncated_head", found, judge_yes=False)
        assert not result.passed

    async def test_a_network_failure_is_a_setup_error(self) -> None:
        def down(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("down", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(down)) as http:
            with pytest.raises(EvalSetupError, match="ConnectError"):
                await Client("k", http).structured(
                    model="m", system="s", user="u", schema={}, max_tokens=1
                )

    async def test_a_control_left_alone_passes(self) -> None:
        found = [_finding(obligation="O13", severity="low", title="missing TRUST comment")]
        result = await _run("ctrl_01_flag_mode_truncated_head", found, judge_yes=False)
        assert result.passed, result.notes
