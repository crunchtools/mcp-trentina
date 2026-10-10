"""The L2 obfuscation gate, recorded in the manifest and enforced at startup (#362).

No model is needed: the gate is run against stand-in detectors, and the
manifest is two small files in a temporary directory.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from benchmarks import l2_obfuscation
from trentina import posture
from trentina.errors import ConfigError
from trentina.perimeter_db import perimeter_stamp
from trentina.quarantine import classifier
from trentina.quarantine.obfuscation import (
    GATE_KEY,
    TRANSFORMS,
    gate_state,
    run_gate,
)

_ATTACKS = ["first sample line of text", "second sample line of text", "third one here"]


def _passing() -> dict[str, Any]:
    return run_gate(_ATTACKS, lambda _text: True)


def _model_dir(tmp_path: Path, gate: object = None) -> str:
    (tmp_path / "config.json").write_text(json.dumps({"id2label": {"0": "SAFE", "1": "INJECTION"}}))
    manifest: dict[str, Any] = {"id": "m", "revision": "r", "threshold": 0.7}
    if gate is not None:
        manifest[GATE_KEY] = gate
    (tmp_path / classifier.MANIFEST_FILE).write_text(json.dumps(manifest))
    return str(tmp_path)


class TestRunGate:
    def test_a_model_that_reads_through_everything_passes(self) -> None:
        record = _passing()
        assert record["passed"] is True
        assert record["plain"] == record["attacks"] == len(_ATTACKS)
        assert set(record["transforms"]) == set(TRANSFORMS)

    def test_a_model_one_transform_blinds_fails(self) -> None:
        record = run_gate(_ATTACKS, lambda text: "\u200b" not in text)
        assert record["passed"] is False
        assert record["transforms"]["zero-width, every letter"] == 0
        assert record["transforms"]["fullwidth"] == len(_ATTACKS)

    def test_max_drop_is_the_allowance(self) -> None:
        assert run_gate(_ATTACKS, _misses_one_in_base64, max_drop=1)["passed"] is True
        assert run_gate(_ATTACKS, _misses_one_in_base64, max_drop=0)["passed"] is False

    def test_every_transform_changes_the_text(self) -> None:
        for name, transform in TRANSFORMS.items():
            assert transform(_ATTACKS[0]) != _ATTACKS[0], name


def _misses_one_in_base64(text: str) -> bool:
    if not text.startswith("Note: "):
        return True
    return "third" not in base64.b64decode(text.removeprefix("Note: ")).decode()


class TestGateState:
    def test_no_record_is_unrecorded(self) -> None:
        assert gate_state({}) == "unrecorded"

    def test_a_passing_record(self) -> None:
        assert gate_state({GATE_KEY: _passing()}) == "passed"

    def test_the_verdict_comes_from_the_counts_not_the_claim(self) -> None:
        blinded = run_gate(_ATTACKS, lambda text: text.isascii())
        assert gate_state({GATE_KEY: blinded}) == "failed"
        assert gate_state({GATE_KEY: {**blinded, "passed": True}}) == "failed"
        assert gate_state({GATE_KEY: {**_passing(), "passed": False}}) == "passed"

    def test_a_record_allowing_a_larger_drop_fails(self) -> None:
        loose = run_gate(_ATTACKS, _misses_one_in_base64, max_drop=3)
        assert loose["passed"] is True
        assert gate_state({GATE_KEY: {**loose, "max_drop": 3}}) == "failed"

    @pytest.mark.parametrize(
        "record",
        [True, "passed", [], {"passed": True}, {"passed": True, "transforms": {}}],
    )
    def test_a_malformed_record_is_unrecorded(self, record: object) -> None:
        assert gate_state({GATE_KEY: record}) == "unrecorded"

    @pytest.mark.parametrize("field", ["plain", "max_drop"])
    @pytest.mark.parametrize("value", [None, "41", -1, True, 1.5])
    def test_a_count_that_is_not_a_count_is_unrecorded(self, field: str, value: object) -> None:
        assert gate_state({GATE_KEY: {**_passing(), field: value}}) == "unrecorded"

    def test_an_extra_or_uncounted_transform_is_unrecorded(self) -> None:
        extra = _passing()
        extra["transforms"]["rot13"] = 3
        assert gate_state({GATE_KEY: extra}) == "unrecorded"
        uncounted = _passing()
        uncounted["transforms"]["base64"] = "all"
        assert gate_state({GATE_KEY: uncounted}) == "unrecorded"

    def test_a_record_missing_a_transform_is_unrecorded(self) -> None:
        record = _passing()
        del record["transforms"]["base64"]
        assert gate_state({GATE_KEY: record}) == "unrecorded"

    def test_resolve_model_carries_the_state(self, tmp_path: Path) -> None:
        assert classifier.resolve_model(_model_dir(tmp_path)).gate == "unrecorded"
        assert classifier.resolve_model(_model_dir(tmp_path, _passing())).gate == "passed"


def _startup_gaps(gate: str | None) -> list[str]:
    # The benign gate (tests/test_benign_gate.py) passes here: this file is
    # about the obfuscation gate's own state.
    model = (
        None
        if gate is None
        else classifier.ModelInfo("m", "r", 0.7, (1,), gate=gate, benign_gate="passed")
    )
    with patch.object(classifier, "model_info", return_value=model):
        return posture.check_l2_gate().gaps


class TestStartup:
    def test_a_passing_model_is_no_gap(self) -> None:
        assert _startup_gaps("passed") == []

    def test_no_model_is_not_this_gap(self) -> None:
        assert _startup_gaps(None) == []

    @pytest.mark.parametrize("gate", ["failed", "unrecorded"])
    def test_any_other_state_is_named(self, gate: str, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert _startup_gaps(gate) == [f"l2_obfuscation_gate_{gate}"]
        assert f"l2_obfuscation_gate_{gate}" in caplog.text

    def test_require_hardened_refuses_to_start(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_REQUIRE_HARDENED", "true")
        with pytest.raises(ConfigError, match="l2_obfuscation_gate_unrecorded"):
            _startup_gaps("unrecorded")
        assert _startup_gaps("passed") == []


def test_the_gate_state_is_in_the_perimeter_stamp() -> None:
    def stamp(gate: str) -> str:
        model = classifier.ModelInfo("m", "r", 0.7, (1,), gate=gate)
        with patch.object(classifier, "resolve_model", return_value=model):
            return perimeter_stamp()

    assert ":gate-passed:" in stamp("passed")
    assert stamp("passed") != stamp("unrecorded")


class TestRecord:
    """``benchmarks/l2_obfuscation.py --record`` against a stand-in classifier."""

    def _run(self, tmp_path: Path, detected: bool) -> int:
        config = type("C", (), {"classifier_model_path": _model_dir(tmp_path)})()
        with (
            patch.object(l2_obfuscation, "is_classifier_available", return_value=True),
            patch.object(
                l2_obfuscation, "_detected", side_effect=lambda t: detected or t.isascii()
            ),
            patch.object(l2_obfuscation, "get_config", return_value=config),
        ):
            return l2_obfuscation.main(["--record"])

    def test_a_pass_is_written_and_exits_zero(self, tmp_path: Path) -> None:
        assert self._run(tmp_path, detected=True) == 0
        resolved = classifier.resolve_model(str(tmp_path))
        assert resolved.gate == "passed"
        assert resolved.id == "m", "the rest of the manifest is kept"

    def test_a_failure_is_written_and_exits_one(self, tmp_path: Path) -> None:
        assert self._run(tmp_path, detected=False) == 1
        assert classifier.resolve_model(str(tmp_path)).gate == "failed"
