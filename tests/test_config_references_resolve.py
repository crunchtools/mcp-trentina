"""Two classes of reference that break silently when a file moves.

Neither is caught by ruff, mypy or the type checker, because neither is an
import. Both are strings that name something in the tree, and a string that
stops naming anything keeps working right up until it matters:

* **`gourmand-exceptions.toml` is path-keyed.** Move a file and its lint
  suppression silently lapses — the finding comes back, and it comes back
  attributed to whoever happens to touch that file next rather than to the
  move. #167 moved fourteen files; that is how the problem was noticed.

* **`patch("dotted.path")` in tests.** `unittest.mock` resolves the string at
  call time and raises only if the *attribute* is missing. A patch target
  whose module moved raises loudly, but one whose module still exists and
  whose attribute merely moved elsewhere can silently patch nothing, and the
  test then asserts against un-patched behaviour and passes.

Twenty lines each, and they convert both from "discovered at 3am" into a
failing test on the commit that caused them.
"""

from __future__ import annotations

import ast
import importlib
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _exception_paths() -> list[tuple[int, str]]:
    raw = (REPO / "gourmand-exceptions.toml").read_bytes()
    data = tomllib.loads(raw.decode("utf-8"))
    return [
        (i, entry["path"])
        for i, entry in enumerate(data.get("exceptions", []))
        if "path" in entry
    ]


def _patch_targets() -> list[tuple[Path, int, str]]:
    """Every string literal passed positionally to patch() or patch.object()."""
    out: list[tuple[Path, int, str]] = []
    for path in sorted(REPO.joinpath("tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else func.id
                if isinstance(func, ast.Name)
                else ""
            )
            if name not in ("patch", "setattr", "setitem"):
                continue
            first = node.args[0]
            if (
                isinstance(first, ast.Constant)
                and isinstance(first.value, str)
                and first.value.startswith("mcp_trentina_crunchtools.")
            ):
                out.append((path, node.lineno, first.value))
    return out


class TestGourmandExceptionPathsExist:
    def test_there_are_exceptions_to_check(self) -> None:
        """A parse that silently found nothing would pass the test below."""
        assert len(_exception_paths()) > 10

    @pytest.mark.parametrize(
        ("index", "rel"), _exception_paths(), ids=str
    )
    def test_the_file_still_exists(self, index: int, rel: str) -> None:
        """A lint suppression that names no file suppresses nothing.

        It also lies: the entry reads as a considered decision about a real
        file, and the justification beside it goes on describing code that
        moved somewhere else.
        """
        # gourmand accepts globs, and a glob that matches nothing is exactly
        # as lapsed as a literal path that does not exist.
        if "*" in rel:
            assert next(REPO.glob(rel), None) is not None, (
                f"gourmand-exceptions.toml entry {index} has pattern {rel!r}, "
                f"which matches no file."
            )
            return
        assert (REPO / rel).exists(), (
            f"gourmand-exceptions.toml entry {index} names {rel!r}, which does "
            f"not exist. If the file moved, re-path the entry in the same "
            f"commit and check its justification still describes the code."
        )


class TestPatchTargetsResolve:
    def test_there_are_targets_to_check(self) -> None:
        assert len(_patch_targets()) > 10

    @pytest.mark.parametrize(
        ("path", "lineno", "target"),
        _patch_targets(),
        ids=lambda v: str(v) if not isinstance(v, Path) else v.name,
    )
    def test_the_dotted_path_resolves(
        self, path: Path, lineno: int, target: str
    ) -> None:
        """Walk the dotted path the way mock will, and fail here instead."""
        parts = target.split(".")
        module = None
        for split in range(len(parts), 0, -1):
            try:
                module = importlib.import_module(".".join(parts[:split]))
            except ImportError:
                continue
            remainder = parts[split:]
            break
        else:  # pragma: no cover - the loop always breaks or exhausts
            remainder = []

        assert module is not None, (
            f"{path.name}:{lineno}: no importable module in {target!r}"
        )
        obj = module
        for attr in remainder:
            assert hasattr(obj, attr), (
                f"{path.name}:{lineno}: patch target {target!r} does not "
                f"resolve — {attr!r} is missing. mock resolves this string at "
                f"call time, so nothing else tells you."
            )
            obj = getattr(obj, attr)


class TestContainerfileAgreesWithPyproject:
    """The petit package name is written in two files and must match.

    `pyproject.toml` declares the dependency; the Containerfile holds it out
    of the hashed export by name (`--no-emit-package`) and installs it
    separately from a hashed source archive, because pip refuses a VCS
    requirement under hash checking.

    A stale name in the Containerfile does not warn. `--no-emit-package`
    silently matches nothing, the package lands in the hashed export as a git
    URL, and the build dies with *"can't verify hashes for version control
    repositories"* — an error about hashing that says nothing about the name.
    That happened in 0.22.0, when the distribution turned out to have been
    renamed from `petit-log` to `petit-log-crunchtools`.

    Offline on purpose. The SHA pin also has to stay in step with the tag in
    `[tool.uv.sources]`, but checking that needs the network, and a test that
    reaches GitHub is a test that fails on a train.
    """

    @staticmethod
    def _petit_requirement() -> str:
        data = tomllib.loads(
            (REPO / "pyproject.toml").read_text(encoding="utf-8")
        )
        for dep in data["project"]["dependencies"]:
            if "petit" in dep:
                # Strip the version specifier: "petit-log-x>=3.2.0" -> name.
                return dep.split(">")[0].split("=")[0].split("<")[0].strip()
        raise AssertionError("no petit dependency found in pyproject.toml")

    def test_the_containerfile_holds_out_the_right_package(self) -> None:
        name = self._petit_requirement()
        containerfile = (REPO / "Containerfile").read_text(encoding="utf-8")
        assert f"--no-emit-package {name} " in containerfile, (
            f"pyproject.toml depends on {name!r} but the Containerfile does "
            f"not hold that name out of the hashed export. The build will "
            f"fail with a hashing error that does not mention the name."
        )

    def test_the_containerfile_installs_the_right_package(self) -> None:
        name = self._petit_requirement()
        containerfile = (REPO / "Containerfile").read_text(encoding="utf-8")
        assert f'"{name} @ https://' in containerfile, (
            f"the Containerfile's separate hashed install does not name "
            f"{name!r}, so pip would install nothing under that requirement."
        )

    def test_the_uv_source_names_the_same_package(self) -> None:
        name = self._petit_requirement()
        data = tomllib.loads(
            (REPO / "pyproject.toml").read_text(encoding="utf-8")
        )
        sources = data.get("tool", {}).get("uv", {}).get("sources", {})
        assert name in sources, (
            f"[tool.uv.sources] does not pin {name!r}; a key under the old "
            f"name resolves nothing and uv falls back to PyPI."
        )
