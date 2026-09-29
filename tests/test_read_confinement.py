"""read_tool and dir_tool reach only what confinement admits (#261).

The incident path was ``read_tool /config/profiles.yaml``: every profile's
topology and two credentials, delivered. These tests pin the rule that
closed it: roots when configured, refuse-all behind a live gateway without
them, a denylist no root overrides, and an open that refuses a path swapped
between the check and the read.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mcp_trentina_crunchtools import config as config_mod
from mcp_trentina_crunchtools.errors import ConfigError, FileReadError
from mcp_trentina_crunchtools.gateway.loader import load_profiles, register_active_config
from mcp_trentina_crunchtools.modes import Mode
from mcp_trentina_crunchtools.tools import confine
from mcp_trentina_crunchtools.tools import read as read_mod
from mcp_trentina_crunchtools.tools.dir import MAX_DIR_ENTRIES, list_dir
from mcp_trentina_crunchtools.tools.read import MAX_FILE_SIZE, _read_confined

GATEWAY_YAML = """\
profiles:
  alpha:
    auth:
      bearer_token_env: TEST_ALPHA_TOKEN
    backends: {}
"""


def _set_roots(monkeypatch: pytest.MonkeyPatch, *roots: Path | str) -> None:
    if roots:
        monkeypatch.setenv("TRENTINA_READ_ROOTS", os.pathsep.join(str(r) for r in roots))
    else:
        monkeypatch.delenv("TRENTINA_READ_ROOTS", raising=False)
    config_mod._config = None


def _refusal(path: str | Path) -> FileReadError:
    with pytest.raises(FileReadError) as caught:
        _read_confined(str(path))
    return caught.value


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """One read root holding one readable file, with a sibling outside it."""
    inside = tmp_path / "root"
    inside.mkdir()
    (inside / "notes.txt").write_text("inside the root\n", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside the root\n", encoding="utf-8")
    _set_roots(monkeypatch, inside)
    return inside


@pytest.fixture
def live_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A registered gateway config, the way a running gateway has one."""
    monkeypatch.setenv("TEST_ALPHA_TOKEN", "alpha-secret")
    gw = tmp_path / "gw"
    gw.mkdir()
    path = gw / "profiles.yaml"
    path.write_text(GATEWAY_YAML, encoding="utf-8")
    register_active_config(path, load_profiles(path), {})
    return path


class TestRoots:
    def test_file_in_root_is_read(self, root: Path) -> None:
        content, resolved = _read_confined(str(root / "notes.txt"))
        assert content == "inside the root\n"
        assert resolved == str(root / "notes.txt")

    def test_dotdot_escape_is_refused(self, root: Path) -> None:
        assert _refusal(root / ".." / "outside.txt").reason == "outside_read_roots"

    def test_symlink_out_of_root_is_refused(self, root: Path) -> None:
        (root / "link.txt").symlink_to(root.parent / "outside.txt")
        assert _refusal(root / "link.txt").reason == "outside_read_roots"

    def test_symlink_to_proc_environ_is_denied(self, root: Path) -> None:
        (root / "env.txt").symlink_to("/proc/self/environ")
        assert _refusal(root / "env.txt").reason == "denied_path"

    def test_non_absolute_root_fails_startup(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("TRENTINA_READ_ROOTS", "relative/dir")
        with pytest.raises(ConfigError):
            config_mod.Config()


class TestDenylist:
    def test_proc_self_environ_is_denied_even_under_root_slash(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch, "/")
        assert _refusal("/proc/self/environ").reason == "denied_path"

    @pytest.mark.parametrize(
        "path",
        ["/config/profiles.yaml", "/config/mcp-trentina-trust.json", "/data/quarantine.db"],
    )
    def test_gateway_config_and_state_are_denied_under_root_slash(
        self, path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # check() is the rule applied to a resolved path; these need not exist here.
        _set_roots(monkeypatch, "/")
        with pytest.raises(FileReadError) as caught:
            confine.check(Path(path))
        assert caught.value.reason == "denied_path"

    def test_trentina_state_dir_is_denied_inside_a_root(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        state = tmp_path / "state"
        state.mkdir()
        (state / "profiles.yaml").write_text("secret: x\n", encoding="utf-8")
        monkeypatch.setenv("QUARANTINE_DB", str(state / "trentina.db"))
        _set_roots(monkeypatch, tmp_path)
        assert _refusal(state / "profiles.yaml").reason == "denied_path"

    @pytest.mark.parametrize(
        ("env_name", "filename"),
        [("TRENTINA_PERIMETER_DB", "perimeter.db"), ("QUARANTINE_TRUST_CONFIG", "trust.json")],
    )
    def test_each_state_path_denies_its_own_dir(
        self, env_name: str, filename: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        own = tmp_path / env_name.lower()
        own.mkdir()
        (own / "secret.txt").write_text("secret\n", encoding="utf-8")
        monkeypatch.setenv(env_name, str(own / filename))
        _set_roots(monkeypatch, tmp_path)
        assert _refusal(own / "secret.txt").reason == "denied_path"

    def test_live_profiles_dir_is_denied_inside_a_root(
        self, tmp_path: Path, live_gateway: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch, tmp_path)
        assert _refusal(live_gateway).reason == "denied_path"

    def test_refusal_names_no_path(self, root: Path) -> None:
        err = _refusal(root / ".." / "outside.txt")
        assert err.reason == "outside_read_roots"
        assert str(root.parent) not in str(err)
        assert "outside.txt" not in str(err)


class TestGatewayMode:
    def test_live_gateway_without_roots_refuses_everything(
        self, tmp_path: Path, live_gateway: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch)
        target = tmp_path / "plain.txt"
        target.write_text("anything\n", encoding="utf-8")
        assert _refusal(target).reason == "outside_read_roots"

    def test_live_gateway_with_roots_reads_inside_them(
        self, root: Path, live_gateway: Path
    ) -> None:
        assert _read_confined(str(root / "notes.txt"))[0] == "inside the root\n"

    async def test_dir_refused_behind_live_gateway_without_roots(
        self, tmp_path: Path, live_gateway: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch)
        with pytest.raises(FileReadError) as caught:
            await list_dir(str(tmp_path), Mode.FLAG)
        assert caught.value.reason == "outside_read_roots"


class TestStandalone:
    def test_no_roots_reads_a_tmp_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_roots(monkeypatch)
        target = tmp_path / "plain.txt"
        target.write_text("standalone\n", encoding="utf-8")
        assert _read_confined(str(target))[0] == "standalone\n"

    def test_no_roots_still_denies_proc(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_roots(monkeypatch)
        assert _refusal("/proc/self/environ").reason == "denied_path"


def _swap_before_open(monkeypatch: pytest.MonkeyPatch, swap: Callable[[], None]) -> None:
    """Run ``swap`` after the check and the stat, immediately before the open."""
    real_open = os.open

    def racing_open(path: Any, flags: int, *args: Any) -> int:
        swap()
        monkeypatch.setattr(confine.os, "open", real_open)
        return real_open(path, flags, *args)

    monkeypatch.setattr(confine.os, "open", racing_open)


class TestSwapAfterCheck:
    def test_final_component_swapped_for_symlink(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "notes.txt"

        def swap() -> None:
            target.unlink()
            target.symlink_to("/proc/self/environ")

        _swap_before_open(monkeypatch, swap)
        assert _refusal(target).reason == "changed_during_read"

    def test_file_replaced_by_another(self, root: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        target = root / "notes.txt"

        def swap() -> None:
            # Created while the original still holds its inode, then renamed
            # over it: unlink-then-create can reuse the same inode number.
            replacement = root / "replacement.txt"
            replacement.write_text("a different inode\n", encoding="utf-8")
            os.replace(replacement, target)

        _swap_before_open(monkeypatch, swap)
        assert _refusal(target).reason == "changed_during_read"

    def test_intermediate_directory_swapped_for_symlink(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sub = root / "sub"
        sub.mkdir()
        (sub / "notes.txt").write_text("inside\n", encoding="utf-8")
        elsewhere = root.parent / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "notes.txt").write_text("outside\n", encoding="utf-8")

        def swap() -> None:
            sub.rename(root.parent / "moved")
            sub.symlink_to(elsewhere)

        _swap_before_open(monkeypatch, swap)
        assert _refusal(sub / "notes.txt").reason == "changed_during_read"

    def test_kernel_name_of_the_opened_fd_is_checked(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The post-open check stands on its own, whatever the inode compare saw."""
        monkeypatch.setattr(confine, "_opened_path", lambda fd: Path("/proc/self/environ"))
        assert _refusal(root / "notes.txt").reason == "denied_path"


class TestFileGrowth:
    def test_file_grown_past_cap_after_fstat_is_refused(
        self, root: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = root / "notes.txt"
        real_open_confined = read_mod.open_confined

        def open_then_grow(path: str) -> Any:
            opened = real_open_confined(path)
            with target.open("ab") as fh:
                fh.write(b"x" * (MAX_FILE_SIZE + 1))
            return opened

        monkeypatch.setattr(read_mod, "open_confined", open_then_grow)
        assert _refusal(target).reason == "too_large"


class TestDirListing:
    async def test_too_many_entries_is_refused_without_listing_them_all(self, root: Path) -> None:
        big = root / "big"
        big.mkdir()
        for i in range(MAX_DIR_ENTRIES + 1):
            (big / f"f{i}.txt").touch()
        with pytest.raises(FileReadError) as caught:
            await list_dir(str(big), Mode.FLAG)
        assert caught.value.reason == "too_many_entries"

    async def test_dir_symlink_out_of_root_is_refused(self, root: Path) -> None:
        (root / "out").symlink_to(root.parent)
        with pytest.raises(FileReadError) as caught:
            await list_dir(str(root / "out"), Mode.FLAG)
        assert caught.value.reason == "outside_read_roots"

    async def test_file_is_not_a_directory(self, root: Path) -> None:
        with pytest.raises(FileReadError) as caught:
            await list_dir(str(root / "notes.txt"), Mode.FLAG)
        assert caught.value.reason == "not_a_directory"
