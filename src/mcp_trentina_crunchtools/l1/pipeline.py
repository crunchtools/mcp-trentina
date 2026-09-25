"""L1: the deterministic pipeline, and the one that builds the L2 input.

FORMAT-AGNOSTIC since 0.28.0. There is one entry point and it scans what it
is handed. The ``looks_like_html`` dispatch that used to choose between an
HTML pipeline and a text pipeline is gone: it matched a leading ``<!DOCTYPE``
or ``<html>``, so an HTML FRAGMENT took the text path, and identical bytes
received two different security behaviours depending on their first few
characters. Conversion now belongs to ``preprocess/html.py``, which declines
on what it cannot parse instead of asking whether anything "is HTML", and
hidden-markup fingerprints are counted by an ordinary stage that runs on
every payload. See ``l1/hidden.py`` for the two tiers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .delimiters import DelimiterStats, normalize_delimiters
from .directives import DirectiveStats, strip_directives
from .encoded import EncodedStats, normalize_encoded
from .exfiltration import ExfiltrationStats, strip_exfiltration
from .hidden import HiddenStats, detect_hidden_markup
from .shadows import ShadowStats
from .unicode import UnicodeStats, normalize_unicode


@dataclass
class PipelineStats:
    """Combined statistics from all L1 stages."""

    hidden: HiddenStats = field(default_factory=HiddenStats)
    unicode: UnicodeStats = field(default_factory=UnicodeStats)
    encoded: EncodedStats = field(default_factory=EncodedStats)
    exfiltration: ExfiltrationStats = field(default_factory=ExfiltrationStats)
    delimiters: DelimiterStats = field(default_factory=DelimiterStats)
    directives: DirectiveStats = field(default_factory=DirectiveStats)
    shadows: ShadowStats = field(default_factory=ShadowStats)

    def to_flat_dict(self) -> dict[str, int]:
        """Flatten all stats into a single dict for serialization."""
        flat: dict[str, int] = {}
        named_sections = [
            ("hidden", asdict(self.hidden)),
            ("unicode", asdict(self.unicode)),
            ("encoded", asdict(self.encoded)),
            ("exfiltration", asdict(self.exfiltration)),
            ("delimiters", asdict(self.delimiters)),
            ("directives", asdict(self.directives)),
            ("shadows", asdict(self.shadows)),
        ]
        for section_name, section_dict in named_sections:
            for key, value in section_dict.items():
                flat[f"{section_name}_{key}"] = value
        return flat

    def normalized(self) -> bool:
        """Whether L1's copy for L2 differs from the arrived text by construction.

        These are the stages that REWRITE the L2 copy to undo obfuscation.
        When any fired, L2 reads both texts: the raw one because it is what
        arrived, the normalized one because three zero-width characters are
        enough to split Prompt Guard's tokens while L1 rates them only medium.
        """
        return bool(
            sum(asdict(self.unicode).values())
            + sum(asdict(self.encoded).values())
            + sum(asdict(self.delimiters).values())
        )

    def total_detections(self) -> int:
        """Total detections across all stages (informational).

        Most stages excise what they detect; the directives stage only
        counts. Either way a detection is a detection for risk purposes.
        """
        return sum(self.to_flat_dict().values())

    def suspicious_detections(self) -> int:
        """Count only genuinely suspicious detections for risk scoring.

        Only categories that signal an actual attack vector count: hidden
        elements, off-screen positioning, same-color text, unicode
        manipulation, encoded payloads, exfiltration URLs, LLM delimiters and
        directive injection.

        Normal HTML hygiene (comments, scripts, styles, meta, noscript) is
        expected on any website and never counted here. Those counters left
        ``PipelineStats`` entirely in 0.28.0 and live in the converter's
        sidecar, which is the only place that still strips them.
        """
        return int(
            self.hidden.elements
            + self.hidden.off_screen
            + self.hidden.same_color
            + sum(asdict(self.unicode).values())
            + sum(asdict(self.encoded).values())
            + sum(asdict(self.exfiltration).values())
            + sum(asdict(self.delimiters).values())
            + sum(asdict(self.directives).values())
            + self.shadows.files
            + self.shadows.obfuscated
        )

    def risk_level(self) -> str:
        """Classify risk based on suspicious detection counts.

        A stdlib shadow is critical on its own; see ``ShadowStats``.
        """
        if self.shadows.files:
            return "critical"
        return risk_level_for_count(self.suspicious_detections())


def risk_level_for_count(suspicious: int) -> str:
    """Classify risk from a raw suspicious-detection count.

    Shared with callers that aggregate detections across multiple
    ``PipelineStats`` instances (e.g. alert ingress scanning several JSON
    fields) and can't hand back a single ``PipelineStats`` to call
    ``risk_level()`` on.
    """
    if suspicious == 0:
        return "low"
    if suspicious <= 3:
        return "medium"
    if suspicious <= 10:
        return "high"
    return "critical"


@dataclass
class PipelineResult:
    """Result from the L1 pipeline: two views of one payload.

    ``content`` is WHAT THE AGENT RECEIVES — the caller's text, unmodified. L1
    never strips: excising lines or tokens destroyed exactly the content an
    ops agent exists to read (a CVE ticket discusses attacks in the words
    attacks use), and it destroyed the evidence before the smarter layers
    could judge it. Disposition belongs to the profile's enforcement mode
    and the Q-Agent, not to a regex.

    ``l2_input`` is L1's NORMALIZED COPY — the same text with obfuscation
    undone: zero-width characters removed, encoded blobs replaced, delimiter
    tokens dropped. L2 reads it as well as ``content`` whenever a normalizing
    stage fired, so the very tricks L1 counts cannot blind the classifier;
    redact's extraction turn reads it too. It is never delivered.

    The owner's rule (2026-09-13): what the agent receives is byte-identical
    to what entered the perimeter, or nothing at all.
    """

    content: str
    l2_input: str
    stats: PipelineStats
    input_size: int
    output_size: int


def _run_stages(content: str, stats: PipelineStats) -> PipelineResult:
    """Apply every stage and assemble the result.

    There is ONE path now. It used to be two — one entered after HTML had
    been converted to Markdown, one for everything else — and keeping them
    from drifting was a standing chore. The dispatch that chose between them
    was also wrong often enough to matter (see the module docstring), so the
    fix was to delete the fork rather than to guard it.

    The delivery text passes through untouched; every stage transforms only
    the L2 input, except ``detect_hidden_markup``, which transforms nothing
    and counts. It runs FIRST, because it is the only stage that reads markup
    and the later stages rewrite the very characters it looks for.
    """
    l2_input = content
    l2_input, stats.hidden = detect_hidden_markup(l2_input)
    l2_input, stats.unicode = normalize_unicode(l2_input)
    l2_input, stats.encoded = normalize_encoded(l2_input)
    l2_input, stats.exfiltration = strip_exfiltration(l2_input)
    l2_input, stats.delimiters = normalize_delimiters(l2_input)
    l2_input, stats.directives = strip_directives(l2_input)

    size = len(content.encode("utf-8"))
    return PipelineResult(
        content=content,
        l2_input=l2_input,
        stats=stats,
        input_size=size,
        output_size=size,
    )


def run_l1(text: str) -> PipelineResult:
    """Run the pipeline on whatever the caller was handed.

    The only entry point. It makes no judgement about the payload's format:
    a stage that cares about markup looks for markup, and finds none in text
    that has none.
    """
    return _run_stages(text, PipelineStats())
