"""Petit — FREE log reduction: remove certainty, leave uncertainty.

Repetitive machine output (a syslog tail, a CI log, a Nagios burst) is
mostly the same line wearing different timestamps. Fingerprint each line by
normalizing its volatile tokens, group identical fingerprints, keep the
first few real samples of each group, and account for the rest.

Grouping is done by petit itself — the ``petit-log`` package, from
https://github.com/crunchtools/petit — rather than by a second
implementation living here. What this module owns is the part that is
Trentina's business and not a log tool's: the normalization POLICY, the
thresholds, the decline behaviour, and the shape of the artifact that
crosses the perimeter.

The load-bearing rule: **normalize only tokens that cannot carry meaning to
a model** — digits, hex runs, IPs, UUIDs, timestamps. Never words. Two lines
that differ in a single word have different fingerprints and both survive,
so a semantic payload buried in 10,000 lines of boilerplate cannot be
normalized into the boilerplate's group: it stays its own line and reaches
the perimeter scan. Conversely, an attacker who crafts a payload to collide
with a boilerplate group achieves only its deletion — dropped lines are
never delivered, and a line that is never delivered injects nothing.

That rule is why the library is called the way it is:

* ``driver="RawEntry"`` pins the structural driver and declines petit's
  per-format vocabulary. ``SecureLogHash`` knows sshd's phrases and
  collapses everything after one of them, so "Invalid user <anything>"
  becomes a single group — semantic, word-level, and exactly what the rule
  above forbids. Detection would select it on any sshd-shaped payload.
* ``stopwords=VOLATILE`` replaces petit's packaged ``hash.stopwords``,
  which is tuned for system logs and more aggressive than its name: its
  ``[a-f]+#`` rule eats the letters next to a scrubbed number, so "bob0"
  and "boa0" share a fingerprint. Right for finding a flapping daemon,
  wrong for us. These are our own patterns, unchanged from the hand-rolled
  implementation this replaced.

Known limitation (adversarial review, 2026-09-13): an attacker who can
WRITE to a shared log ahead of time can pre-seed sample slots — three lines
matching a predicted alert's fingerprint mean the real fourth line is
counted but not shown, and the samples the agent reads carry the attacker's
values. "Collision achieves only deletion" therefore holds against payload
SMUGGLING, not against suppression of a victim line by an attacker with
prior write access to the same stream. The group count still shows the line
existed, and the [petit] summary prefix is in-band (spoofable) — consumers
must treat petit output as untrusted, which the perimeter already assumes.

Honest scope (from the plan, deliberately): petit reduces log-shaped
content. It does ~nothing for prose, minified JS, base64 blobs, or extracted
PDF text, and it declines (applied=False) rather than pretend.

Hostile-input hardening, kept on this side of the boundary regardless of
what the library promises: every regex here is linear-time (character
classes and bounded repetition, no nested quantifiers), and only the first
``_FINGERPRINT_MAX_CHARS`` of a line are handed to the library, so one
enormous line costs O(cap) not O(line). Samples are then read back from the
ORIGINAL lines by index, so capping the fingerprint never truncates what is
delivered. The library is synchronous, so it runs on a worker thread —
a large payload must not stall the gateway's event loop.
"""

from __future__ import annotations

import asyncio

from petit import PetitError, analyze_text

from ..channels import Channel, Kind
from .base import Cost, PreProcessContext, PreProcessResult
from .volatile import VOLATILE

_FINGERPRINT_MAX_CHARS = 400

# Below this many lines there is nothing worth grouping.
_MIN_LINES = 20

# Keep this many real sample lines per group.
_SAMPLES_PER_GROUP = 3

# There is no minimum saving. A reducer that declines a 5% win throws
# away 5%, and across a swarm of agents even 1% compounds. What remains
# is arithmetic rather than policy: the rewrite appends a summary block,
# so content with nothing to collapse can come out no smaller than it
# went in, and delivering that would cost bytes for nothing.


class PetitProcessor:
    """FREE. Collapses repetitive lines, keeps samples, accounts for the rest."""

    name = "petit"
    cost = Cost.FREE
    channels = frozenset({Channel.TOOL})
    kind = Kind.TEXT

    async def run(self, payload: str, _ctx: PreProcessContext) -> PreProcessResult:
        # petit reduces by line structure alone; it reads no job context.
        bytes_in = len(payload.encode("utf-8"))
        lines = payload.split("\n")

        if len(lines) < _MIN_LINES:
            # Named for the condition, not for the size. A 1.6 MB payload of
            # single-line JSON lands here, and calling that "too few lines"
            # reads as "too small" — which sent an earlier analysis of the
            # production sidecar looking for short responses that were not
            # there. The counts say which it actually was.
            return PreProcessResult.declined(
                self.name, self.cost, payload, reason="not_line_structured",
                details={"lines_in": len(lines), "bytes_in": bytes_in},
            )

        # Only the head of each line is fingerprinted, so a single enormous
        # line cannot buy unbounded work. Samples come back by line number
        # and are read from `lines`, so the cap never reaches the output.
        capped = "\n".join(line[:_FINGERPRINT_MAX_CHARS] for line in lines)

        try:
            analysis = await asyncio.to_thread(
                analyze_text,
                capped,
                driver="RawEntry",
                stopwords=VOLATILE,
                max_samples=_SAMPLES_PER_GROUP,
                source_name="trentina",
            )
        except PetitError as exc:
            # The library raises rather than exits, and a reducer that
            # cannot reduce must still hand back the payload.
            return PreProcessResult.declined(
                self.name, self.cost, payload,
                reason="petit_error", details={"error": type(exc).__name__},
            )

        collapsed = [g for g in analysis.groups if g.count > _SAMPLES_PER_GROUP]
        if not collapsed:
            return PreProcessResult.declined(
                self.name, self.cost, payload, reason="nothing_repetitive",
            )

        # Emit samples in the order they were written, not the order their
        # groups happened to sort. The artifact should read like the log it
        # came from.
        kept = sorted(
            number
            for group in analysis.groups
            for number in group.sample_lines
            if 0 <= number < len(lines)
        )
        out_lines = [lines[number] for number in kept]

        summary = [
            "",
            (
                f"[petit] {len(lines)} lines reduced to {len(out_lines)}; "
                f"{len(collapsed)} repetitive group(s) collapsed "
                f"(showing first {_SAMPLES_PER_GROUP} of each):"
            ),
        ]
        summary.extend(f"[petit]   {g.count}x: {g.pattern}" for g in collapsed)

        reduced = "\n".join(out_lines + summary)
        bytes_out = len(reduced.encode("utf-8"))

        if bytes_in > 0 and bytes_out >= bytes_in:
            # The work is already done and measured; report what it achieved.
            # Without this the log says 100% either way, so "missed the bar by
            # a hair" and "saved nothing at all" are the same word — and the
            # first means the floor is costing real savings while the second
            # means the data simply does not compress.
            return PreProcessResult.declined(
                self.name, self.cost, payload, reason="not_smaller",
                details={
                    "would_be_bytes": bytes_out,
                    "would_be_ratio": round(bytes_out / bytes_in, 4),
                },
            )

        return PreProcessResult(
            name=self.name,
            cost=self.cost,
            content=reduced,
            applied=True,
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            details={
                "lines_in": len(lines),
                "lines_out": len(out_lines),
                "groups_collapsed": len(collapsed),
                # Lines petit scrubbed away to nothing (blanks, bare
                # markers) are counted by neither group nor sample. Say so
                # rather than let the arithmetic look wrong.
                "lines_dropped": max(0, analysis.lines_in - analysis.lines_grouped),
            },
        )
