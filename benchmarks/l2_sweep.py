"""Offline L2 threshold sweep (issue #86).

The L2 model emits a continuous malicious score; its threshold is a
cutoff applied to it afterwards. So one scoring pass over a labeled corpus
answers the question for every threshold at once: this module takes the
stored scores and sweeps the cutoff over them, with no inference.

Pure functions only, so the arithmetic is tested without the model.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

DEFAULT_GRID = tuple(round(0.05 * i, 2) for i in range(1, 20))
"""0.05 .. 0.95. The report's table; the best point is searched over the
observed scores, not this grid."""

MIN_BENIGN_FOR_FP = 30
"""Below this many benign cases one false positive moves the FP rate by more
than 3 points: the report says so and withholds the best-separation line,
which on a handful of benign cases picks a cutoff no one should ship."""


@dataclass(frozen=True)
class SweepPoint:
    """Confusion counts at one cutoff. Flagged means ``score >= threshold``."""

    threshold: float
    tp: int
    fn: int
    fp: int
    tn: int

    @property
    def detection(self) -> float:
        """Share of attacks flagged (recall). 0.0 with no attacks."""
        attacks = self.tp + self.fn
        return self.tp / attacks if attacks else 0.0

    @property
    def fp_rate(self) -> float:
        """Share of benign cases flagged. 0.0 with no benign cases."""
        benign = self.fp + self.tn
        return self.fp / benign if benign else 0.0

    @property
    def precision(self) -> float:
        """Share of flagged cases that are attacks. 0.0 when nothing is flagged."""
        flagged = self.tp + self.fp
        return self.tp / flagged if flagged else 0.0

    @property
    def youden_j(self) -> float:
        """Detection minus FP rate: 0 is chance, 1 is perfect separation."""
        return self.detection - self.fp_rate


def point(scored: list[tuple[float, bool]], threshold: float) -> SweepPoint:
    """Confusion counts for ``(score, is_attack)`` pairs at one cutoff."""
    tp = fn = fp = tn = 0
    for score, is_attack in scored:
        flagged = score >= threshold
        if is_attack:
            tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
    return SweepPoint(threshold, tp, fn, fp, tn)


def sweep(
    scored: list[tuple[float, bool]], thresholds: tuple[float, ...] = DEFAULT_GRID
) -> list[SweepPoint]:
    """One ``SweepPoint`` per threshold, in the order given."""
    return [point(scored, t) for t in thresholds]


def best(scored: list[tuple[float, bool]]) -> SweepPoint | None:
    """The cutoff with the highest Youden's J, searched over observed scores.

    Only an observed score can change a count, so those are the only
    candidates worth trying, plus one just above the highest, which flags
    nothing. Ties go to the HIGHER cutoff: same separation, fewer flags.
    None without at least one attack and one benign case, where J is
    undefined.
    """
    if not any(a for _, a in scored) or all(a for _, a in scored):
        return None
    observed = sorted({s for s, _ in scored}, reverse=True)
    candidates = [math.nextafter(observed[0], math.inf), *observed]
    return max((point(scored, t) for t in candidates), key=lambda p: p.youden_j)


def render_markdown(
    scored: list[tuple[float, bool]], current: float, unscored: int = 0, corpus: str = ""
) -> str:
    """The report section: the grid, the current setting, and the best cutoff.

    ``corpus`` names the corpus in the heading; empty keeps the plain one.
    """
    n_attacks = sum(1 for _, a in scored if a)
    n_benign = len(scored) - n_attacks
    out = [
        f"## L2 threshold sweep: {corpus} corpus" if corpus else "## L2 threshold sweep",
        "",
        (
            f"L2 scores for {n_attacks} attacks and {n_benign} benign "
            "cases, cut offline at each threshold. Flagged means score >= threshold. "
            f"Threshold in force: {current}."
        ),
        "",
    ]
    if unscored:
        out += [
            (
                f"{unscored} case(s) had no score (model not loaded, or the scan failed) "
                "and are excluded."
            ),
            "",
        ]
    if not scored:
        out += ["No scores were produced; the run's warnings say why.", ""]
        return "\n".join(out)
    if n_benign < MIN_BENIGN_FOR_FP:
        step = f"moves in steps of {1 / n_benign:.0%}" if n_benign else "is undefined"
        out += [
            (
                f"**Low resolution:** with {n_benign} benign cases the FP rate {step}. "
                "Do not pick a production threshold from this table."
            ),
            "",
        ]
    out += [
        "| Threshold | Detection | FP rate | Precision | TP | FN | FP | TN |",
        "|-----------|-----------|---------|-----------|----|----|----|----|",
    ]
    rows = sweep(scored)
    if all(abs(p.threshold - current) > 1e-9 for p in rows):
        rows = sorted([*rows, point(scored, current)], key=lambda p: p.threshold)
    for p in rows:
        mark = "**" if abs(p.threshold - current) <= 1e-9 else ""
        label = f"{mark}{p.threshold:.2f}{mark}"
        out.append(
            f"| {label} | {p.detection:.0%} | {p.fp_rate:.0%} | {p.precision:.0%} | "
            f"{p.tp} | {p.fn} | {p.fp} | {p.tn} |"
        )
    out.append("")
    top = best(scored) if n_benign >= MIN_BENIGN_FOR_FP else None
    if top is not None:
        out += [
            (
                f"Best separation (max detection - FP rate) at **{top.threshold:.4f}**: "
                f"detection {top.detection:.0%}, FP rate {top.fp_rate:.0%}, "
                f"J = {top.youden_j:.2f}."
            ),
            "",
        ]
    return "\n".join(out)
