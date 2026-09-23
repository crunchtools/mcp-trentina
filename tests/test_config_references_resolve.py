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
