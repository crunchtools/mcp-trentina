"""What L1 counts in text nobody attacked: the false-positive side of a stage.

A new L1 stage is measured here before it joins
``PipelineStats.suspicious_detections`` (#363). Each file, or each
``--chunk`` lines of one, is scanned as one payload, the way a tool response
arrives. The report is, per counter, how many payloads it fired on and how
many it raised to a risk level L1 alone refuses (high or critical).

    uv run python benchmarks/l1_false_positives.py docs src README.md
    journalctl -n 30000 | uv run python benchmarks/l1_false_positives.py --chunk 200 -

No model and no key: L1 only.
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mcp_trentina_crunchtools.l1.pipeline import FINDING_NAMES, run_l1

_REFUSES = ("high", "critical")
_TEXT = {".md", ".py", ".txt", ".yaml", ".yml", ".toml", ".json", ".html", ".log", ".cfg", ""}


def _payloads(paths: list[str], chunk: int) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for raw in paths:
        if raw == "-":
            files = [("<stdin>", sys.stdin.read())]
        else:
            root = Path(raw)
            members = sorted(root.rglob("*")) if root.is_dir() else [root]
            files = [
                (str(p), p.read_text(errors="replace"))
                for p in members
                if p.is_file()
                and p.suffix in _TEXT
                and not any(part.startswith(".") for part in p.relative_to(root).parts)
            ]
        for name, text in files:
            if not chunk:
                found.append((name, text))
                continue
            lines = text.split("\n")
            found += [
                (f"{name}:{i + 1}", "\n".join(lines[i : i + chunk]))
                for i in range(0, len(lines), chunk)
            ]
    return found


def _non_negative(raw: str) -> int:
    value = int(raw)
    if value < 0:
        raise argparse.ArgumentTypeError("must be zero (a whole file) or more")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", help="files, directories, or - for stdin")
    parser.add_argument(
        "--chunk", type=_non_negative, default=0, help="lines per payload (default: a file)"
    )
    parser.add_argument("--show", type=int, default=3, help="payloads named per counter")
    args = parser.parse_args(argv)

    payloads = _payloads(args.paths, args.chunk)
    fired = Counter[str]()
    total = Counter[str]()
    where: dict[str, list[str]] = {}
    refused: list[str] = []
    for name, text in payloads:
        stats = run_l1(text).stats
        for key, n in stats.to_flat_dict().items():
            if n:
                fired[key] += 1
                total[key] += n
                where.setdefault(key, []).append(f"{name} ({n})")
        if stats.total_detections() and stats.risk_level() in _REFUSES:
            refused.append(name)

    print(f"{len(payloads)} payloads; L1 alone refuses {len(refused)}")
    print("| counter | payloads | count | examples |")
    print("|---|---|---|---|")
    for key in FINDING_NAMES:
        if fired[key]:
            examples = "; ".join(where[key][: args.show])
            print(f"| {key} | {fired[key]} | {total[key]} | {examples} |")
    for name in refused[: args.show * 4]:
        print(f"refused: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
