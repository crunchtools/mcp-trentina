"""dir_tool's shadow scan and the confined open stay inside what was checked (#287).

The shadow scan re-listed the directory by path and opened each shadow by
path, following symlinks, so ``json.py -> /anywhere`` was read past the read
roots and the denylist. It now reads the descriptor confinement checked and
never follows a link. The rest are the same class found auditing read, dir
and confine for it: an open that relied on ``/proc`` to catch a swapped
directory, a FIFO opened before its type was checked, a hard link into
Trentina's own state, and two quadratic regexes over a shadow's text.
"""

from __future__ import annotations

import builtins
import os
import time
from pathlib import Path
from typing import Any

import pytest

from mcp_trentina_crunchtools import config as config_mod
from mcp_trentina_crunchtools.errors import FileReadError
from mcp_trentina_crunchtools.l1 import shadows as shadows_mod
from mcp_trentina_crunchtools.l1.shadows import _scan_for_obfuscation, detect_module_shadows
from mcp_trentina_crunchtools.modes import Mode
from mcp_trentina_crunchtools.tools import confine
from mcp_trentina_crunchtools.tools import dir as dir_mod
from mcp_trentina_crunchtools.tools.read import _read_confined

PAYLOAD = "exec(bytes.fromhex('6f73'))\n"


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    inside = tmp_path / "root"
    inside.mkdir()
    (inside / "notes.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setenv("TRENTINA_READ_ROOTS", str(inside))
    config_mod._config = None
    return inside


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    elsewhere = tmp_path / "outside"
    elsewhere.mkdir()
    return elsewhere


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every path opened by name through ``open`` or ``os.open``, resolved."""
    seen: list[str] = []
    real_open, real_os_open = builtins.open, os.open

    def record(target: Any, dir_fd: int | None) -> None:
        if isinstance(target, (str, Path)) and dir_fd is None:
            seen.append(os.path.realpath(target))

    def recording_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        record(file, None)
        return real_open(file, *args, **kwargs)

    def recording_os_open(path: Any, flags: int, mode: int = 0o600, *, dir_fd: Any = None) -> int:
        record(path, dir_fd)
        return real_os_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(builtins, "open", recording_open)
    monkeypatch.setattr(os, "open", recording_os_open)
    return seen


async def _listed(path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    async def delivered(_content: str, **kwargs: Any) -> dict[str, Any]:
        return dict(kwargs["extras"], l1=kwargs["precomputed_l1"])

    monkeypatch.setattr(dir_mod, "judge_and_deliver", delivered)
    monkeypatch.setattr(dir_mod, "check_blocklist", lambda _p, _m: False)
    return await dir_mod.list_dir(str(path), Mode.FLAG)


class TestShadowScanThroughTheDescriptor:
    async def test_a_symlinked_shadow_is_reported_and_its_target_never_opened(
        self,
        root: Path,
        outside: Path,
        opened: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        target = outside / "secret.py"
        target.write_text(PAYLOAD, encoding="utf-8")
        (root / "json.py").symlink_to(target)

        result = await _listed(root, monkeypatch)

        assert str(target) not in opened
        assert [s["shadows_module"] for s in result["shadows"]] == ["json"]
        assert result["l1"].stats.shadows.files == 1
        found = detect_module_shadows(str(root)).shadows_found[0]
        assert [i.category for i in found.obfuscation_indicators] == ["symlink"]

    async def test_a_symlinked_package_is_reported_without_reading_through_it(
        self,
        root: Path,
        outside: Path,
        opened: list[str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        (outside / "__init__.py").write_text(PAYLOAD, encoding="utf-8")
        (root / "json").symlink_to(outside)

        result = await _listed(root, monkeypatch)

        assert str(outside / "__init__.py") not in opened
        assert [s["shadows_module"] for s in result["shadows"]] == ["json"]
        found = detect_module_shadows(str(root)).shadows_found[0]
        assert [i.category for i in found.obfuscation_indicators] == ["symlink"]

    def test_a_real_shadow_is_still_read(self, root: Path) -> None:
        (root / "struct.py").write_text(PAYLOAD, encoding="utf-8")
        pkg = root / "json"
        pkg.mkdir()
        (pkg / "__init__.py").write_text(PAYLOAD, encoding="utf-8")
        found = {f.shadows_module: f for f in detect_module_shadows(str(root)).shadows_found}
        for module in ("struct", "json"):
            categories = {i.category for i in found[module].obfuscation_indicators}
            assert "code_execution" in categories

    def test_a_hard_linked_shadow_is_reported_not_read(
        self, root: Path, outside: Path, opened: list[str]
    ) -> None:
        """A hard link passes every check on its directory; its bytes may be Trentina's."""
        state = outside / "trentina.db"
        state.write_text(PAYLOAD * 50_000, encoding="utf-8")
        os.link(state, root / "json.py")
        found = detect_module_shadows(str(root)).shadows_found[0]
        assert [i.category for i in found.obfuscation_indicators] == ["linked"]

    def test_a_binary_shadow_is_reported_not_decoded(self, root: Path) -> None:
        (root / "struct.py").write_bytes(b"\x00exec(" + b"\xff" * 16)
        found = detect_module_shadows(str(root)).shadows_found[0]
        assert [i.category for i in found.obfuscation_indicators] == ["binary"]

    def test_a_fifo_named_like_a_module_is_no_shadow(self, root: Path) -> None:
        """Python would not import it, and opening it would hang a blocking read."""
        os.mkfifo(root / "struct.py")
        assert not detect_module_shadows(str(root)).has_shadows


class TestShadowScanCost:
    @pytest.mark.parametrize("unit", ["join([ ", "getattr(x "])
    def test_obfuscation_regexes_are_linear(self, unit: str) -> None:
        """140 KB of either took 28-40 s before the gaps were bounded."""
        start = time.perf_counter()
        _scan_for_obfuscation(unit * 20_000)
        assert time.perf_counter() - start < 2.0

    def test_the_bounded_gap_still_matches(self) -> None:
        categories = {i.category for i in _scan_for_obfuscation("''.join([chr(1)])\n")}
        assert "obfuscation" in categories
        line = "getattr(obj, '__class__')\n"
        assert "obfuscation" in {i.category for i in _scan_for_obfuscation(line)}

    def test_past_the_read_budget_a_shadow_is_reported_unscanned(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(shadows_mod, "MAX_SCAN_BYTES", len(PAYLOAD) + 1)
        for name in ("json", "struct"):
            (root / f"{name}.py").write_text(PAYLOAD, encoding="utf-8")
        found = detect_module_shadows(str(root)).shadows_found
        categories = sorted(i.category for f in found for i in f.obfuscation_indicators)
        assert len(found) == 2
        assert "unscanned" in categories
        assert "code_execution" in categories


class TestConfinedOpen:
    def test_a_fifo_is_refused_before_it_is_opened(
        self, root: Path, opened: list[str], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fifo = root / "pipe.txt"
        os.mkfifo(fifo)
        walked: list[str] = []
        real_os_open = os.open

        def recording(path: Any, flags: int, mode: int = 0o600, *, dir_fd: Any = None) -> int:
            walked.append(str(path))
            return real_os_open(path, flags, mode, dir_fd=dir_fd)

        monkeypatch.setattr(confine.os, "open", recording)
        with pytest.raises(FileReadError) as caught:
            _read_confined(str(fifo))
        assert caught.value.reason == "not_a_file"
        assert not [p for p in walked if p.endswith("pipe.txt")]

    def test_a_directory_swapped_before_the_stat_is_caught_without_proc(
        self, root: Path, outside: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Swapped before the stat, the inode compare agrees with the swap;
        only the kernel name caught it, and that needs /proc. The walk does not."""
        sub = root / "sub"
        sub.mkdir()
        (sub / "notes.txt").write_text("inside\n", encoding="utf-8")
        (outside / "notes.txt").write_text("outside\n", encoding="utf-8")
        real_stat = os.stat

        def swap_then_stat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if Path(path) == sub / "notes.txt" and not sub.is_symlink():
                sub.rename(root.parent / "moved")
                sub.symlink_to(outside)
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(confine.os, "stat", swap_then_stat)
        monkeypatch.setattr(confine, "_opened_path", lambda _fd: None)
        with pytest.raises(FileReadError) as caught:
            _read_confined(str(sub / "notes.txt"))
        assert caught.value.reason == "changed_during_read"

    def test_a_hard_link_to_trentinas_own_state_is_denied(
        self, tmp_path: Path, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = tmp_path / "state"
        state.mkdir()
        db = state / "trentina.db"
        db.write_text("every profile's blocklist\n", encoding="utf-8")
        monkeypatch.setenv("QUARANTINE_DB", str(db))
        config_mod._config = None
        os.link(db, root / "copy.txt")
        with pytest.raises(FileReadError) as caught:
            _read_confined(str(root / "copy.txt"))
        assert caught.value.reason == "denied_path"

    def test_an_ordinary_hard_link_inside_the_root_still_reads(self, root: Path) -> None:
        os.link(root / "notes.txt", root / "twin.txt")
        assert _read_confined(str(root / "twin.txt"))[0] == "hello\n"
