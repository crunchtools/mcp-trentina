"""Tests for SQLite blocklist database."""

from __future__ import annotations

import inspect
import sqlite3
from unittest.mock import patch

from mcp_trentina_crunchtools import database


def _fresh_db() -> sqlite3.Connection:
    """Create a fresh in-memory database with schema applied."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(database.SCHEMA)
    return conn


class TestBlocklist:
    """Test blocklist operations."""

    def test_record_and_check_detection(self) -> None:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            detection_id = database.record_detection(
                source_type="url",
                source="https://evil.com/page",
                domain="evil.com",
                layer1_stats={"unicode_zero_width_chars": 5},
                risk_level="high",
            )
            assert detection_id > 0

            blocked = database.is_blocked("https://evil.com/page")
            assert blocked is not None
            assert blocked["risk_level"] == "high"

    def test_unblocked_source_returns_none(self) -> None:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            assert database.is_blocked("https://clean.com") is None

    def test_domain_blocked(self) -> None:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            database.record_detection(
                source_type="url",
                source="https://evil.com/page1",
                domain="evil.com",
                layer1_stats={},
                risk_level="critical",
            )
            blocked = database.is_domain_blocked("evil.com")
            assert blocked is not None

    def test_blocklist_stats(self) -> None:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            database.record_detection(
                source_type="url",
                source="https://evil1.com",
                domain="evil1.com",
                layer1_stats={},
                risk_level="high",
            )
            database.record_detection(
                source_type="file",
                source="/tmp/bad.md",
                domain=None,
                layer1_stats={},
                risk_level="medium",
            )
            stats = database.get_blocklist_stats()
            assert stats["total_blocked"] == 2
            assert len(stats["recent_detections"]) == 2

    def test_qagent_assessment_stored(self) -> None:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            database.record_detection(
                source_type="url",
                source="https://evil.com",
                domain="evil.com",
                layer1_stats={},
                risk_level="high",
                qagent_assessment={
                    "injection_detected": True,
                    "risk_level": "high",
                },
            )
            blocked = database.is_blocked("https://evil.com")
            assert blocked is not None
            assert blocked["qagent_assessment"] is not None


class TestEveryLayersVerdict:
    """#204: a row credited to one layer still says what the others thought."""

    def test_verdicts_round_trip(self) -> None:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            database.record_detection(
                source_type="tool_response",
                source="jira:get_issue",
                domain=None,
                layer1_stats={},
                risk_level="high",
                verdicts={
                    "flagged_by": "L2",
                    "l2_label": "MALICIOUS",
                    "l2_score": 0.91,
                    "l3_verdict": "clean",
                },
            )
            row = conn.execute("SELECT * FROM detections").fetchone()
        assert (row["flagged_by"], row["l2_label"], row["l3_verdict"]) == (
            "L2",
            "MALICIOUS",
            "clean",
        )
        assert row["l2_score"] == 0.91
        assert row["l3_risk"] is None

    def test_an_older_table_gains_the_columns(self) -> None:
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute(
            "CREATE TABLE detections (id INTEGER PRIMARY KEY, source_type TEXT, "
            "source TEXT, domain TEXT, detected_at TEXT, layer1_stats TEXT, "
            "qagent_assessment TEXT, risk_level TEXT, blocked BOOLEAN)"
        )
        conn.execute(
            "CREATE TABLE gateway_calls (id INTEGER PRIMARY KEY, timestamp REAL, "
            "profile TEXT, backend TEXT, tool TEXT, success BOOLEAN, duration_ms INTEGER)"
        )
        database._migrate(conn)
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(detections)")}
        assert {"flagged_by", "l2_label", "l2_score", "l3_verdict", "l3_risk"} <= columns

    def test_the_insert_names_the_verdict_columns_in_tuple_order(self) -> None:
        """Values are bound positionally from _VERDICT_COLUMNS; the INSERT must agree."""
        source = inspect.getsource(database.record_detection)
        names = ", ".join(column for column, _ in database._VERDICT_COLUMNS)
        assert f"{names})" in source
