"""read_tool and dir_tool do their filesystem work off the event loop (#267).

Both ran synchronous I/O on the loop, so one slow disk or one enormous
directory stalled every other request, ``/health`` included. The work now
runs in a worker thread, and the confinement checks (#261) run in the SAME
thread as the open they guard: splitting them across threads would not break
the fd-based checks, but keeping the whole sequence in one call is what makes
that obvious to the next reader.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from mcp_trentina_crunchtools import config as config_mod
from mcp_trentina_crunchtools.l1.shadows import detect_module_shadows
from mcp_trentina_crunchtools.modes import Mode
from mcp_trentina_crunchtools.tools import confine
from mcp_trentina_crunchtools.tools import dir as dir_mod
from mcp_trentina_crunchtools.tools import read as read_mod


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    inside = tmp_path / "root"
    inside.mkdir()
    (inside / "notes.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setenv("TRENTINA_READ_ROOTS", str(inside))
    config_mod._config = None
    return inside


@pytest.fixture
def threads(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    """Record which thread opened the path and which verified the descriptor."""
    seen: dict[str, int] = {}
    real_open = confine.open_confined
    real_verify = confine._verify_opened

    def open_confined(path: str, extra_flags: int = 0) -> Any:
        seen["open"] = threading.get_ident()
        return real_open(path, extra_flags)

    def verify(fd: int, checked: os.stat_result) -> os.stat_result:
        seen["verify"] = threading.get_ident()
        return real_verify(fd, checked)

    monkeypatch.setattr(read_mod, "open_confined", open_confined)
    monkeypatch.setattr(dir_mod, "open_confined", open_confined)
    monkeypatch.setattr(confine, "_verify_opened", verify)
    return seen


async def _delivered(content: str, **_kwargs: Any) -> dict[str, Any]:
    return {"content": content}


class TestOffTheLoop:
    async def test_read_opens_and_verifies_in_one_worker_thread(
        self, root: Path, threads: dict[str, int], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def prepare(content: str, **_kwargs: Any) -> Any:
            return SimpleNamespace(
                content=content, provenance=None, pipeline=None, briefing=None, extras=None
            )

        monkeypatch.setattr(read_mod, "prepare", prepare)
        monkeypatch.setattr(read_mod, "judge_and_deliver", _delivered)
        monkeypatch.setattr(read_mod, "check_blocklist", lambda _p, _m: False)

        result = await read_mod.read_file(str(root / "notes.txt"), Mode.FLAG)

        assert result == {"content": "hello\n"}
        loop_thread = threading.get_ident()
        assert threads["open"] == threads["verify"]
        assert threads["open"] != loop_thread

    async def test_dir_lists_in_one_worker_thread(
        self, root: Path, threads: dict[str, int], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(dir_mod, "judge_and_deliver", _delivered)
        monkeypatch.setattr(dir_mod, "check_blocklist", lambda _p, _m: False)
        scanned: dict[str, Any] = {}
        real_detect = dir_mod.detect_module_shadows

        def detect(directory: str, **kwargs: Any) -> Any:
            scanned["thread"] = threading.get_ident()
            scanned["kwargs"] = kwargs
            return real_detect(directory, **kwargs)

        monkeypatch.setattr(dir_mod, "detect_module_shadows", detect)

        result = await dir_mod.list_dir(str(root), Mode.FLAG)

        assert "notes.txt" in result["content"]
        loop_thread = threading.get_ident()
        assert threads["open"] == threads["verify"] == scanned["thread"]
        assert threads["open"] != loop_thread
        assert scanned["kwargs"] == {"max_entries": dir_mod.MAX_DIR_ENTRIES + 1}


class TestShadowScanIsBounded:
    async def test_a_scan_cut_short_fails_closed(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The listing saw few entries but the re-scan by path hit the bound:
        the directory changed, and a partial scan could have missed a shadow.
        Delivered as a confinement refusal (#278), with no alternatives."""
        from mcp_trentina_crunchtools.errors import BlockedSourceError
        from mcp_trentina_crunchtools.l1.shadows import ShadowScanResult

        swapped = ShadowScanResult(directory=str(root), entries_read=dir_mod.MAX_DIR_ENTRIES + 1)
        monkeypatch.setattr(dir_mod, "detect_module_shadows", lambda _d, **_k: swapped)

        with pytest.raises(BlockedSourceError) as caught:
            await dir_mod.list_dir(str(root), Mode.FLAG)
        assert caught.value.refusal["reason"] == "confinement refused (changed_during_read)"
        assert caught.value.refusal["alternatives"] == []

    def test_it_stops_at_max_entries(self, tmp_path: Path) -> None:
        for name in ("json", "struct", "socket", "ssl", "types", "abc", "enum", "re"):
            (tmp_path / f"{name}.py").write_text("x = 1\n", encoding="utf-8")

        assert detect_module_shadows(str(tmp_path)).files_scanned == 8
        assert detect_module_shadows(str(tmp_path), max_entries=3).files_scanned == 3

    def test_it_reads_the_directory_lazily(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No ``list(os.scandir())``: entries past the bound are never pulled."""
        for i in range(50):
            (tmp_path / f"f{i}.txt").write_text("", encoding="utf-8")
        pulled: list[str] = []
        real_scandir = os.scandir

        class Counting:
            def __init__(self, path: str) -> None:
                self._it = real_scandir(path)

            def __enter__(self) -> Counting:
                return self

            def __exit__(self, *_exc: object) -> None:
                self._it.close()

            def __iter__(self) -> Counting:
                return self

            def __next__(self) -> os.DirEntry[str]:
                entry = next(self._it)
                pulled.append(entry.name)
                return entry

        monkeypatch.setattr("mcp_trentina_crunchtools.l1.shadows.os.scandir", Counting)
        detect_module_shadows(str(tmp_path), max_entries=5)
        assert len(pulled) == 5
