"""Tests for SQLite blocklist database."""

from __future__ import annotations

import inspect
import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from trentina import database


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

            assert database.is_blocked("https://evil.com/page", None, gateway_wide=True)

    def test_unblocked_source_returns_none(self) -> None:
        conn = _fresh_db()
        with (
            patch.object(database, "_db", conn),
            patch.object(database, "get_db", return_value=conn),
        ):
            assert not database.is_blocked("https://clean.com", None, gateway_wide=True)

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
            assert database.is_blocked("https://evil.com", None, gateway_wide=True)
            row = conn.execute("SELECT qagent_assessment FROM detections").fetchone()
            assert row["qagent_assessment"] is not None


@pytest.fixture
def db() -> Iterator[sqlite3.Connection]:
    conn = _fresh_db()
    database._migrate(conn)
    with (
        patch.object(database, "_db", conn),
        patch.object(database, "get_db", return_value=conn),
    ):
        yield conn


def _block(source: str, profile: str | None) -> None:
    database.record_detection(
        source_type="url",
        source=source,
        domain=None,
        layer1_stats={},
        risk_level="high",
        profile=profile,
    )


class TestKeyedOnProfile:
    """#263: one profile's refusal is not another's."""

    def test_an_agent_sees_only_its_own_rows(self, db: sqlite3.Connection) -> None:
        _block("https://x.test/?slot=1", "alpha")
        assert database.is_blocked("https://x.test/?slot=1", "alpha")
        assert not database.is_blocked("https://x.test/?slot=1", "beta")

    def test_a_null_profile_row_is_operator_only(self, db: sqlite3.Connection) -> None:
        """Rows written before #263 carry no profile."""
        _block("https://legacy.test/", None)
        assert not database.is_blocked("https://legacy.test/", "alpha")
        assert database.is_blocked("https://legacy.test/", None, gateway_wide=True)

    def test_the_gateway_wide_view_sees_every_profile(self, db: sqlite3.Connection) -> None:
        _block("https://x.test/", "alpha")
        assert database.is_blocked("https://x.test/", "beta", gateway_wide=True)

    def test_no_profile_and_not_gateway_wide_sees_nothing(self, db: sqlite3.Connection) -> None:
        _block("https://x.test/", None)
        _block("https://x.test/", "alpha")
        assert not database.is_blocked("https://x.test/", None)

    def test_a_flag_observation_is_not_a_block(self, db: sqlite3.Connection) -> None:
        database.record_detection(
            source_type="url",
            source="https://x.test/",
            domain=None,
            layer1_stats={},
            risk_level="high",
            profile="alpha",
            blocked=False,
        )
        assert not database.is_blocked("https://x.test/", "alpha")


def _age(conn: sqlite3.Connection, days: int) -> None:
    then = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    conn.execute("UPDATE detections SET detected_at = ?", (then,))
    conn.commit()


class TestStatsScope:
    def test_each_view_counts_what_it_may_see(self, db: sqlite3.Connection) -> None:
        _block("https://a.test/", "alpha")
        _block("https://b.test/", "beta")
        _block("https://legacy.test/", None)
        _block("https://old.test/", "alpha")
        db.execute(
            "UPDATE detections SET detected_at = ? WHERE source = 'https://old.test/'",
            ((datetime.now(UTC) - timedelta(days=31)).isoformat(),),
        )
        db.commit()

        def sources(profile: str | None) -> set[str]:
            stats = database.get_blocklist_stats(profile)
            assert stats["total_blocked"] == len(stats["recent_detections"])
            return {r["source"] for r in stats["recent_detections"]}

        assert sources("alpha") == {"https://a.test/"}
        assert sources("beta") == {"https://b.test/"}
        assert sources(None) == {"https://a.test/", "https://b.test/", "https://legacy.test/"}


class TestTTL:
    def test_an_expired_row_does_not_count(
        self, db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from trentina import config as config_mod

        monkeypatch.setenv("TRENTINA_BLOCKLIST_TTL_DAYS", "7")
        config_mod._config = None
        _block("https://x.test/", "alpha")
        _age(db, 6)
        assert database.is_blocked("https://x.test/", "alpha")
        assert database.get_blocklist_stats("alpha")["total_blocked"] == 1
        _age(db, 8)
        assert not database.is_blocked("https://x.test/", "alpha")
        assert not database.is_blocked("https://x.test/", None, gateway_wide=True)
        assert database.get_blocklist_stats("alpha")["total_blocked"] == 0

    def test_the_sweep_deletes_expired_blocks_and_keeps_observations(
        self, db: sqlite3.Connection
    ) -> None:
        _block("https://old.test/", "alpha")
        database.record_detection(
            source_type="url",
            source="https://seen.test/",
            domain=None,
            layer1_stats={},
            risk_level="high",
            profile="alpha",
            blocked=False,
        )
        _age(db, 31)
        _block("https://new.test/", "alpha")
        assert database.sweep_expired_blocks(db) == 1
        left = {r["source"] for r in db.execute("SELECT source FROM detections")}
        assert left == {"https://seen.test/", "https://new.test/"}

    def test_the_default_is_thirty_days(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from trentina import config as config_mod

        monkeypatch.delenv("TRENTINA_BLOCKLIST_TTL_DAYS", raising=False)
        assert config_mod.Config().blocklist_ttl_days == 30


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
        audit = {r["name"] for r in conn.execute("PRAGMA table_info(gateway_calls)")}
        assert {"outcome", "bytes_arrived", "bytes_delivered", "normalized"} <= audit
        indexes = {r["name"] for r in conn.execute("PRAGMA index_list(detections)")}
        assert "idx_detections_profile_source" in indexes

    def test_an_old_database_file_still_opens(self, tmp_path: Path) -> None:
        """#263's index names a column older tables lack; get_db must not fail on one."""
        path = tmp_path / "old.db"
        old = sqlite3.connect(path)
        old.execute(
            "CREATE TABLE detections (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "source_type TEXT NOT NULL, source TEXT NOT NULL, domain TEXT, "
            "detected_at TEXT NOT NULL, layer1_stats TEXT NOT NULL, "
            "qagent_assessment TEXT, risk_level TEXT NOT NULL, blocked BOOLEAN DEFAULT 1)"
        )
        old.execute(
            "INSERT INTO detections (source_type, source, detected_at, layer1_stats, "
            "risk_level) VALUES ('url', 'https://legacy.test/', ?, '{}', 'high')",
            (datetime.now(UTC).isoformat(),),
        )
        old.commit()
        old.close()
        saved = database._db
        database._db = None
        try:
            conn = database.get_db(str(path))
            assert database.is_blocked("https://legacy.test/", None, gateway_wide=True)
            assert not database.is_blocked("https://legacy.test/", "alpha")
            conn.close()
        finally:
            database._db = saved

    def test_the_insert_names_the_verdict_columns_in_tuple_order(self) -> None:
        """Values are bound positionally from _VERDICT_COLUMNS; the INSERT must agree."""
        source = inspect.getsource(database.record_detection)
        names = ", ".join(column for column, _ in database._VERDICT_COLUMNS)
        assert f"{names})" in source
