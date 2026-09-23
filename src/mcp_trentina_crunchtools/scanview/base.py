"""Scan-view extraction — a GUARD choosing what it reads.

Trentina has two driver roles (``channels.py``): guards decide admission,
pre-processors transform outside the perimeter. This package is neither a
third role nor a sibling of ``preprocess/``. It is guard machinery — the
content guard's read policy, the part of the scanner that decides which
strings it puts in front of L1/L2/L3.

That classification is the answer to the one question the two-role model has
to settle: **how is a driver that scans less than it delivers expressed?**
It is expressed here, on the guard side, and it is FORBIDDEN on the other.

The reasoning is a safety property, not taste. A pre-processor transforms a
payload that is then scanned AND delivered -- invariant 2 over there -- so
whatever it drops never reaches the agent either, which is what makes
fingerprint-collision games pointless. An extractor is the inverse: the FULL
original is delivered while only a subset is scanned, so colliding into a
skipped bucket delivers your payload unscanned. Those are opposite security
readings of the same verb, and the earlier design mistake was to give the
second one its own driver framework as if the two were peers.

They are not peers. Deciding how thoroughly to judge is a judgement, which
makes it the guard's to make and the guard's to confess. So:

  A pre-processor may never open a gap between what is scanned and what is
  delivered. Only a guard may, only about its own reading, and only while
  accounting for every byte it declined (S3).

Everything a guard's read policy selects goes to L1/L2/L3. Everything it
declines is counted and reported but never judged.

Why this exists at all: a measured Matrix initial sync was 68,092 characters
reaching the classifier, of which 45,552 were Megolm ciphertext, 13,352 were
JSON key names, 7,617 were key-backup material, and 245 were human-readable
prose. The scan took 46 seconds to read base64 it could not decrypt. Reading
less is not a shortcut here; it is the difference between a perimeter that
runs and one that times out and is skipped entirely.

Five invariants, none negotiable:

S1 -- DELIVERY IS UNTOUCHED. An extractor never influences the bytes forwarded
   to the client. Its output reaches the wire through exactly one channel,
   the ``_trentina_warning`` key. This is the inverse of a pre-processor,
   which owns delivery and owes nothing to the scan view; between them the
   two roles cover both halves without either one holding both.

S2 -- SKIPPING IS STRUCTURAL, NEVER SEMANTIC. A string may be skipped only on
   a property of its own shape: charset, length, absence of whitespace, a
   match against an identifier grammar. Never on its meaning, its sender, its
   room, or a classifier's opinion of it. The predicate is a pure function of
   the string. There is no trusted-sender list and there never will be, because
   the sender is the thing an attacker controls most cheaply.

S3 -- SKIPPING IS ACCOUNTED, AND LOW COVERAGE IS ITSELF A FINDING. Every
   skipped byte is counted by reason. The histogram rides into the audit
   record and into L3's briefing, because "this is the 4% that survived
   selection" is context a judge should have. A scan that read 2% of a
   document must not look like a scan that read all of it.

S4 -- DECRYPTION IS READ-ONLY, ADDITIVE AND EPHEMERAL. Plaintext an extractor
   recovers exists only in the scan view: never forwarded, never written to
   disk, never logged in full.

   S4 is what makes the Matrix extractor a guard rather than a pre-processor,
   and it is the one invariant here that is contingent rather than permanent.
   A Matrix BRIDGE -- terminating E2EE and delivering the plaintext -- would
   scan exactly what it delivers, which is the pre-processor contract, and it
   would belong in ``preprocess/`` with no extractor involved. Trentina does
   not do that today (see ``.specify/specs/013-matrix-scan-view/spec.md``,
   "Encryption posture": ciphertext is forwarded untouched so the homeserver
   never sees plaintext). Until that product decision changes, decryption
   here is read-only and this extractor stays on the guard side.

S5 -- FAIL OPEN TO MORE SCANNING, NEVER LESS. Any extractor error, timeout or
   missing dependency falls back to ``full`` -- scan every leaf, the behaviour
   that shipped before any of this -- and marks the result degraded. No failure
   mode may result in "scanned nothing, looked clean".

   Note the asymmetry with pre-processing, which fails open to DELIVERING the
   original. Both mean "on failure, do the thing that hides nothing", and they
   point in opposite directions because the roles do.

Extractors parse hostile bytes. Predicates here must be linear-time: an
attacker choosing the input must not be able to buy quadratic work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Mapping

    from ..channels import Channel


class SkipReason(str, Enum):
    """Why a string was not scanned. One entry per structural rule.

    These are reported, so they double as the vocabulary an operator reads in
    an audit row. Keep them specific: "opaque" tells you a blob was skipped,
    "skipped" would tell you nothing.
    """

    EMPTY = "empty"
    NUMERIC = "numeric"
    IDENTIFIER = "identifier"
    OPAQUE = "opaque"
    ENUM_CONSTANT = "enum_constant"
    DUPLICATE = "duplicate"
    CIPHERTEXT_UNDECRYPTABLE = "ciphertext_undecryptable"


@dataclass(frozen=True)
class UndecryptableEvent:
    """An encrypted event the extractor could not read.

    Identity only — never ciphertext, never partial plaintext. This is what
    makes the coverage gap countable instead of assumed (S3).
    """

    event_id: str
    room_id: str
    session_id: str
    reason: str


@dataclass(frozen=True)
class ScanViewContext:
    """What an extractor may know about the job. Not a policy channel."""

    source: str = ""
    profile_name: str = ""
    path: str = ""


@dataclass(frozen=True)
class ScanView:
    """What the pipeline will read, and an account of what it will not.

    ``segments`` are RAW strings. Normalisation is ``sanitize_text``'s job and
    happens once, in the defense layer, so that the delivery view and the
    judgement view keep being derived in exactly one place.
    """

    extractor: str
    segments: tuple[str, ...] = ()
    chars_total: int = 0
    chars_scanned: int = 0
    skipped_chars: Mapping[SkipReason, int] = field(default_factory=dict)
    encrypted_events: int = 0
    decrypted_events: int = 0
    undecryptable: tuple[UndecryptableEvent, ...] = ()
    degraded: bool = False
    details: Mapping[str, int | float | str] = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        """Fraction of characters actually handed to the pipeline."""
        if self.chars_total <= 0:
            return 1.0
        return self.chars_scanned / self.chars_total

    def accounts(self) -> bool:
        """S3: scanned plus skipped must equal the total, exactly.

        Asserted in tests rather than at runtime. A drift here means an
        extractor dropped content without recording it, which is the one bug
        class this whole design exists to make impossible.
        """
        return self.chars_scanned + sum(self.skipped_chars.values()) == self.chars_total


@runtime_checkable
class ScanViewExtractor(Protocol):
    """The shape of an extractor.

    Implementations are constructed per profile (the Matrix one owns a key
    cache) but hold no per-request state.
    """

    name: str
    channels: frozenset[Channel]

    async def extract(self, payload: Any, ctx: ScanViewContext) -> ScanView:
        """Select what the pipeline should read.

        Must not raise on content it cannot handle: return a view covering
        everything (``degraded=True``) rather than letting the caller decide
        what an exception means (S5).
        """
        ...
