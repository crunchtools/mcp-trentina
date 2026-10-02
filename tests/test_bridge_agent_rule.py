"""The bridge process's half of the agent rule (#264): whose invites it takes.

It accepts an invite only from ``BRIDGE_ALLOWED_INVITERS``, leaves and forgets
any joined room that fails that rule, reports every room's members to the
gateway, and leaves a room the gateway refuses. The gateway's half, and the
two wired together, are in ``test_matrix_bridge.py`` (``TestAgentRule``).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from mcp_trentina_crunchtools.bridge.client import ROOM_ANNOUNCE, ROOM_LEFT
from mcp_trentina_crunchtools.bridge.settings import BridgeSettings, SettingsError

from .test_bridge_process import ROOM as UPSTREAM_ROOM
from .test_bridge_process import SCOTT, _bridge, _sync, _text_event
from .test_bridge_process import USER as BRIDGE_USER
from .test_bridge_process import FakeNio as _FakeNio
from .test_bridge_process import TestSettings as _ProcessSettings

STRANGER = "@stranger:matrix.org"
NEW_ROOM = "!new:matrix.org"


def _gateway_log() -> tuple[list[dict[str, Any]], Any]:
    """A gateway that records every payload and takes it."""
    seen: list[dict[str, Any]] = []

    def gateway(request: httpx.Request) -> httpx.Response:
        seen.append(json.loads(request.content))
        return httpx.Response(200, json={"outcome": "mapped"})

    return seen, gateway


def _left_reports(seen: list[dict[str, Any]]) -> list[str]:
    """The rooms the gateway was told the bridge is leaving (#317)."""
    return [p["room_id"] for p in seen if p["type"] == ROOM_LEFT]


def _set_members(nio: _FakeNio, room_id: str, *members: str) -> None:
    nio.rooms[room_id].users = dict.fromkeys((BRIDGE_USER, *members))


def _started(store: Path, nio: _FakeNio, handler: Any = None) -> Any:
    """A bridge that has vetted and announced nothing yet: a fresh start."""
    bridge = _bridge(store, nio, handler)
    bridge._vetted.clear()
    bridge._announced.clear()
    return bridge


# ------------------------------------------------------------ bridge: invites


class TestInvites:
    async def test_a_strangers_invite_is_not_joined(self, tmp_path: Path) -> None:
        nio = _FakeNio()
        nio.invited_rooms[NEW_ROOM] = SimpleNamespace(inviter=STRANGER)
        seen, gateway = _gateway_log()
        await _bridge(tmp_path, nio, gateway).process(_sync(), first=False)
        assert nio.joined == []
        assert nio.left == [NEW_ROOM]
        assert nio.forgotten == [NEW_ROOM]
        assert seen == [], "a rejected invite has no mirror to retire"

    async def test_an_invite_that_names_no_inviter_is_not_joined(self, tmp_path: Path) -> None:
        nio = _FakeNio()
        nio.invited_rooms[NEW_ROOM] = SimpleNamespace(inviter=None)
        await _bridge(tmp_path, nio).process(_sync(), first=False)
        assert nio.joined == []
        assert nio.left == [NEW_ROOM]

    async def test_an_allowed_inviters_invite_is_joined_and_remembered(
        self, tmp_path: Path
    ) -> None:
        nio = _FakeNio()
        nio.invited_rooms[NEW_ROOM] = SimpleNamespace(inviter=SCOTT)
        await _bridge(tmp_path, nio).process(_sync(), first=False)
        assert nio.joined == [NEW_ROOM]
        assert nio.left == []
        record = tmp_path / "inviters.json"
        assert json.loads(record.read_text()) == {NEW_ROOM: SCOTT}
        assert record.stat().st_mode & 0o777 == 0o600

    async def test_an_empty_allowlist_refuses_everyone_and_says_so(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        nio = _FakeNio()
        nio.invited_rooms[NEW_ROOM] = SimpleNamespace(inviter=SCOTT)
        with caplog.at_level(logging.WARNING):
            bridge = _bridge(tmp_path, nio, inviters=frozenset())
            await bridge.process(_sync(), first=False)
        assert nio.joined == []
        assert nio.left == [NEW_ROOM]
        warnings = [r for r in caplog.records if "BRIDGE_ALLOWED_INVITERS is empty" in r.message]
        assert len(warnings) == 1

    async def test_rejected_invites_are_not_remembered(self, tmp_path: Path) -> None:
        nio = _FakeNio()
        bridge = _bridge(tmp_path, nio)
        for n in range(3):
            nio.invited_rooms[f"!spam{n}:matrix.org"] = SimpleNamespace(inviter=STRANGER)
            await bridge.process(_sync(next_batch=f"s{n}"), first=False)
        assert len(nio.left) == 3
        assert len(bridge._left) <= 1, "held only through the batch that left it"
        await bridge.process(_sync(next_batch="s9"), first=False)
        assert bridge._left == set(), "a spammer cannot grow the bridge's state"

    async def test_a_failed_rejection_is_tried_again(self, tmp_path: Path) -> None:
        tries: list[str] = []

        class Stubborn(_FakeNio):
            async def room_leave(self, room_id: str) -> Any:
                tries.append(room_id)
                if len(tries) == 1:
                    return SimpleNamespace()  # not a RoomLeaveResponse
                return await super().room_leave(room_id)

        nio = Stubborn()
        nio.invited_rooms[NEW_ROOM] = SimpleNamespace(inviter=STRANGER)
        bridge = _bridge(tmp_path, nio)
        await bridge.process(_sync(), first=False)
        await bridge.process(_sync(next_batch="s3"), first=False)
        assert tries == [NEW_ROOM, NEW_ROOM]
        assert nio.forgotten == [NEW_ROOM]


# ---------------------------------------------------- bridge: at startup


class TestStartupVetting:
    async def test_a_room_a_stranger_invited_is_left(self, tmp_path: Path) -> None:
        (tmp_path / "inviters.json").write_text(json.dumps({UPSTREAM_ROOM: STRANGER}))
        nio = _FakeNio()
        seen, gateway = _gateway_log()
        await _started(tmp_path, nio, gateway).process(_sync(), first=True)
        assert nio.left == [UPSTREAM_ROOM]
        assert nio.forgotten == [UPSTREAM_ROOM]
        assert _left_reports(seen) == [UPSTREAM_ROOM], "only its leaving is reported"
        assert len(seen) == 1, "a room that fails the rule is not announced"
        assert json.loads((tmp_path / "inviters.json").read_text()) == {}

    async def test_a_room_an_allowed_inviter_opened_stays(self, tmp_path: Path) -> None:
        (tmp_path / "inviters.json").write_text(json.dumps({UPSTREAM_ROOM: SCOTT}))
        nio = _FakeNio()
        _set_members(nio, UPSTREAM_ROOM, SCOTT, "@friend:matrix.org")
        seen, gateway = _gateway_log()
        await _started(tmp_path, nio, gateway).process(_sync(), first=True)
        assert nio.left == []
        [announced] = seen
        assert announced["room"]["members"] == [SCOTT, "@friend:matrix.org"]

    async def test_an_unrecorded_room_of_allowed_users_stays(self, tmp_path: Path) -> None:
        nio = _FakeNio()  # members: the bridge and Scott, no inviter on record
        await _started(tmp_path, nio).process(_sync(), first=True)
        assert nio.left == []

    async def test_an_unrecorded_room_with_anyone_else_is_left(self, tmp_path: Path) -> None:
        nio = _FakeNio()
        _set_members(nio, UPSTREAM_ROOM, SCOTT, STRANGER)
        await _started(tmp_path, nio).process(_sync(), first=True)
        assert nio.left == [UPSTREAM_ROOM]

    async def test_an_unrecorded_room_is_vetted_again_when_its_members_change(
        self, tmp_path: Path
    ) -> None:
        """#296: the audience rule held at the first sync, not for good."""
        nio = _FakeNio()  # members: the bridge and Scott, no inviter on record
        seen, gateway = _gateway_log()
        bridge = _started(tmp_path, nio, gateway)
        await bridge.process(_sync(), first=True)
        assert nio.left == []
        announced = len(seen)
        _set_members(nio, UPSTREAM_ROOM, SCOTT, STRANGER)
        await bridge.process(_sync(_text_event(), next_batch="s3"), first=False)
        assert nio.left == [UPSTREAM_ROOM]
        assert _left_reports(seen[announced:]) == [UPSTREAM_ROOM]
        assert len(seen) == announced + 1, "nothing from it but its leaving is forwarded"

    async def test_a_room_with_a_recorded_inviter_is_not_left_for_a_new_member(
        self, tmp_path: Path
    ) -> None:
        """The inviter rule does not change with the audience; the gateway's
        agent rule is what reads the members of such a room."""
        (tmp_path / "inviters.json").write_text(json.dumps({UPSTREAM_ROOM: SCOTT}))
        nio = _FakeNio()
        bridge = _started(tmp_path, nio)
        await bridge.process(_sync(), first=True)
        _set_members(nio, UPSTREAM_ROOM, SCOTT, STRANGER)
        await bridge.process(_sync(next_batch="s3"), first=False)
        assert nio.left == []

    async def test_a_failed_forget_still_leaves_the_room_left(self, tmp_path: Path) -> None:
        (tmp_path / "inviters.json").write_text(json.dumps({UPSTREAM_ROOM: STRANGER}))

        class Unforgetting(_FakeNio):
            async def room_forget(self, room_id: str) -> Any:
                self.forgotten.append(room_id)
                return SimpleNamespace()  # not a RoomForgetResponse

        nio = Unforgetting()
        seen, gateway = _gateway_log()
        bridge = _started(tmp_path, nio, gateway)
        await bridge.process(_sync(), first=True)
        await bridge.process(_sync(_text_event(), next_batch="s3"), first=False)
        assert nio.left == [UPSTREAM_ROOM], "left once, not again every sync"
        assert _left_reports(seen) == [UPSTREAM_ROOM]
        assert len(seen) == 1, "and nothing from it is forwarded"

    async def test_nothing_is_forwarded_from_a_room_being_left(self, tmp_path: Path) -> None:
        (tmp_path / "inviters.json").write_text(json.dumps({UPSTREAM_ROOM: STRANGER}))

        class Stuck(_FakeNio):
            async def room_leave(self, room_id: str) -> Any:
                return SimpleNamespace()

        nio = Stuck()
        seen, gateway = _gateway_log()
        bridge = _started(tmp_path, nio, gateway)
        await bridge.process(_sync(_text_event()), first=False)
        await bridge.process(_sync(_text_event(), next_batch="s3"), first=False)
        assert _left_reports(seen) == [UPSTREAM_ROOM], "a stuck leave is reported once"
        assert len(seen) == 1

    async def test_no_matrix_id_reaches_the_log(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        (tmp_path / "inviters.json").write_text(json.dumps({UPSTREAM_ROOM: STRANGER}))
        nio = _FakeNio()
        nio.invited_rooms[NEW_ROOM] = SimpleNamespace(inviter=STRANGER)
        with caplog.at_level(logging.DEBUG):
            await _started(tmp_path, nio).process(_sync(), first=True)
        assert nio.left == [NEW_ROOM, UPSTREAM_ROOM]
        for secret in (STRANGER, NEW_ROOM, UPSTREAM_ROOM, "stranger"):
            assert secret not in caplog.text


class TestMembershipReports:
    async def test_a_membership_change_is_announced_again(self, tmp_path: Path) -> None:
        nio = _FakeNio()
        seen, gateway = _gateway_log()
        bridge = _bridge(tmp_path, nio, gateway)
        await bridge.process(_sync(), first=False)
        assert seen == []
        _set_members(nio, UPSTREAM_ROOM, SCOTT, "@friend:matrix.org")
        await bridge.process(_sync(next_batch="s3"), first=False)
        await bridge.process(_sync(next_batch="s4"), first=False)
        [again] = seen
        assert again["type"] == ROOM_ANNOUNCE
        assert again["room"]["members"] == [SCOTT, "@friend:matrix.org"]

    async def test_a_report_the_gateway_did_not_take_is_sent_again(self, tmp_path: Path) -> None:
        answers = iter([httpx.Response(400), httpx.Response(200, json={"outcome": "mapped"})])
        seen: list[dict[str, Any]] = []

        def gateway(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return next(answers)

        nio = _FakeNio()
        bridge = _bridge(tmp_path, nio, gateway)
        _set_members(nio, UPSTREAM_ROOM, SCOTT, "@quiet-agent:matrix.org")
        await bridge.process(_sync(), first=False)
        await bridge.process(_sync(next_batch="s3"), first=False)
        await bridge.process(_sync(next_batch="s4"), first=False)
        assert len(seen) == 2, "retried once after the drop, then remembered"
        assert seen[0]["event_id"] == seen[1]["event_id"]

    async def test_a_room_the_gateway_refuses_is_left(self, tmp_path: Path) -> None:
        def gateway(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"outcome": "refused"})

        nio = _FakeNio()
        bridge = _bridge(tmp_path, nio, gateway)
        bridge._announced.clear()
        await bridge.process(_sync(_text_event()), first=False)
        assert nio.left == [UPSTREAM_ROOM]
        assert nio.forgotten == [UPSTREAM_ROOM]

    async def test_the_gateway_hears_before_the_room_is_left(self, tmp_path: Path) -> None:
        """#317: told after, a crash in between loses the report for good."""
        order: list[str] = []

        class Recording(_FakeNio):
            async def room_leave(self, room_id: str) -> Any:
                order.append("leave")
                return await super().room_leave(room_id)

        def gateway(request: httpx.Request) -> httpx.Response:
            payload = json.loads(request.content)
            order.append(payload["type"])
            outcome = "refused" if payload["type"] == ROOM_ANNOUNCE else "retired"
            return httpx.Response(200, json={"outcome": outcome})

        nio = Recording()
        bridge = _bridge(tmp_path, nio, gateway)
        bridge._announced.clear()
        await bridge.process(_sync(), first=False)
        assert order == [ROOM_ANNOUNCE, ROOM_LEFT, "leave"]


class TestInviterSettings:
    def test_unset_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _ProcessSettings()._env(monkeypatch)
        monkeypatch.delenv("BRIDGE_ALLOWED_INVITERS", raising=False)
        monkeypatch.delenv("BRIDGE_ALLOWED_INVITERS_FILE", raising=False)
        assert BridgeSettings.from_env().allowed_inviters == frozenset()

    def test_a_list_is_parsed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _ProcessSettings()._env(monkeypatch, BRIDGE_ALLOWED_INVITERS=f" {SCOTT}, @b:x.org ,,")
        assert BridgeSettings.from_env().allowed_inviters == {SCOTT, "@b:x.org"}

    def test_it_can_come_from_a_file(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        path = tmp_path / "inviters"
        path.write_text(f"{SCOTT}\n")
        path.chmod(0o600)
        _ProcessSettings()._env(monkeypatch, BRIDGE_ALLOWED_INVITERS_FILE=str(path))
        assert BridgeSettings.from_env().allowed_inviters == {SCOTT}

    def test_a_malformed_entry_is_fatal_and_not_echoed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _ProcessSettings()._env(monkeypatch, BRIDGE_ALLOWED_INVITERS=f"{SCOTT},scott-no-at")
        with pytest.raises(SettingsError, match="1 entries") as err:
            BridgeSettings.from_env()
        assert "scott-no-at" not in str(err.value)
