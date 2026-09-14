"""Architectural contract: there is ONE defense pipeline, and it lives in defense.py.

The L1 -> L2 -> L3 sequence was hand-rolled in eight places before the
extraction. Nobody set out to write eight; each was added by someone reasonable
who needed the layers and wrote the obvious four lines. That is how it happens,
and it is why "we'll keep it unified" is not a plan.

So this test enforces it. Any module that reaches past `defend()` to call a
detector directly is starting copy nine, and CI says so.

The rule is deliberately about the DETECTORS, not about every name in those
packages. Three categories are allowed through, each for a stated reason:

* Status probes (`is_classifier_available`, `classifier_status`) — these report
  whether a layer is loaded. /health and the stats tool need them and they
  cannot begin a pipeline.
* Types (`ClassifierResult`) — annotations, no behaviour.
* `quarantine_extract` — L3 doing the tool's job rather than guarding the door.
  quarantine_* tools spend the Q-Agent on extraction; that is the product, not
  a gate. It is listed explicitly so the distinction stays a decision rather
  than an oversight.

If you are here because this test failed: you probably want `defend()`,
`advise()`, or `defend_json()` from mcp_trentina_crunchtools.defense.
"""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "mcp_trentina_crunchtools"

# Modules whose names may not be imported outside the pipeline.
GUARDED_MODULES = ("quarantine.classifier", "quarantine.agent", "sanitize.pipeline")

# The detectors themselves. Importing one of these outside defense.py means a
# second pipeline is being born.
DETECTORS = frozenset(
    {
        "classify",
        "classify_async",
        "classify_guarded",
        "quarantine_detect",
    }
)

# Files allowed to import detectors, with the reason.
EXEMPT = {
    "defense.py": "the pipeline itself",
    # The Q-Agent re-reads its own extraction output before returning it. That
    # is a layer defending itself, one level below the pipeline, and routing it
    # through defend() would be circular.
    "quarantine/agent.py": "Q-Agent verifying its own output",
    # A package re-exporting its own members is not a pipeline. Listed
    # rather than pattern-skipped so the exemption stays visible.
    "quarantine/__init__.py": "package re-export of its own API",
}


def _resolve(path: Path, node: ast.ImportFrom) -> str:
    """Resolve a relative import to a package-absolute dotted name.

    Needed because `from .classifier import ...` inside quarantine/ and
    `from ..quarantine.classifier import ...` inside tools/ name the same
    module. Matching on the written text alone would miss the first form —
    which is exactly the hole that let the one real exemption look clean.
    """
    module = node.module or ""
    if not node.level:
        return module
    pkg = list(path.relative_to(SRC).parent.parts)
    base = pkg[: len(pkg) - (node.level - 1)]
    return ".".join([*base, module]) if module else ".".join(base)


def _guarded_imports(path: Path) -> list[tuple[str, str]]:
    """Return (module, name) pairs this file imports from a guarded module."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # `import mcp_trentina_crunchtools.quarantine.classifier as c`
            # reaches every detector via attribute access; flag the module
            # itself so the hole ImportFrom-only scanning left is closed.
            for alias in node.names:
                if any(alias.name.endswith(m) for m in GUARDED_MODULES):
                    found.append((alias.name, "<module import>"))
            continue
        if not isinstance(node, ast.ImportFrom):
            continue
        resolved = _resolve(path, node)
        if not any(resolved.endswith(m) for m in GUARDED_MODULES):
            continue
        for alias in node.names:
            found.append((resolved, alias.name))
    return found


class TestOnePipeline:
    def test_no_module_outside_defense_imports_a_detector(self) -> None:
        offenders: dict[str, list[str]] = {}

        src_files = sorted(p for p in SRC.rglob("*.py") if "__pycache__" not in p.parts)
        for path in src_files:
            key = path.relative_to(SRC).as_posix()
            if key in EXEMPT:
                continue
            bad = [
                name
                for _mod, name in _guarded_imports(path)
                if name in DETECTORS or name == "<module import>"
            ]
            if bad:
                offenders[key] = sorted(set(bad))

        assert not offenders, (
            "These modules call a detector directly instead of going through "
            "the defense pipeline, which means a second pipeline is forming:\n"
            + "\n".join(f"  {mod}: {', '.join(names)}" for mod, names in offenders.items())
            + "\n\nUse defend(), advise(), or defend_json() from "
            "mcp_trentina_crunchtools.defense. If this import genuinely is not "
            "part of a defense decision, add it to EXEMPT with the reason."
        )

    def test_the_exemptions_are_still_real(self) -> None:
        """An exemption for a file that no longer needs one is a lie.

        Stale allowlist entries are how a contract rots into decoration — the
        same failure mode as `classify: true` sitting in a config nobody reads.
        """
        for key in EXEMPT:
            path = SRC / key
            assert path.exists(), f"EXEMPT names a file that no longer exists: {key}"
            names = [n for _m, n in _guarded_imports(path)]
            assert any(n in DETECTORS for n in names), (
                f"{key} is exempted from the one-pipeline rule but no longer "
                f"imports any detector. Remove it from EXEMPT."
            )

    def test_defense_module_exposes_the_three_postures(self) -> None:
        """Callers should never need a detector; these are the ways in."""
        from mcp_trentina_crunchtools import defense

        for name in ("defend", "advise", "defend_json", "enforce_block"):
            assert hasattr(defense, name), f"defense.{name} is the documented entry point"
