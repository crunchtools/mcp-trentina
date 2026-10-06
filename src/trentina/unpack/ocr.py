"""The text drawn in images, read in a child process (#370).

``read_images`` hands a payload's images to ``ocr_worker`` in one request
and checks the answer. One process for all of them, because starting the
models costs about a second and each image two more: a page with six
images is one start, not six. The worker's docstring says what is read
and what an OCR-level guarantee leaves out.
"""

from __future__ import annotations

import base64
import json
import logging
import threading
from dataclasses import dataclass, field

from .child import ask

logger = logging.getLogger(__name__)

WORKER = "trentina.unpack.ocr_worker"
MALFORMED = "answer malformed"

MAX_IMAGES = 6
"""Images read for one payload. The rest stay unread: at two passes and a
second or two each, more would not fit inside a tool call."""

MAX_IMAGE_BYTES = 6 * 1024 * 1024
"""Bytes of one image sent to the worker."""

BUDGET = 40.0
"""Seconds the worker may spend reading. It checks before each image and
leaves the rest unread, so one slow image costs the others, not the call."""

GRACE = 20.0
"""Seconds past the budget before the worker is killed: its start-up, and the
image it was in the middle of."""

MAX_OUTPUT = 4 * 1024 * 1024

_slot = threading.BoundedSemaphore(1)


@dataclass
class ImageText:
    """What one image says.

    Attributes:
        text: Lines read from the image as it is.
        faint: Lines found only once its contrast was stretched: text a
            person looking at the picture would not see.
    """

    text: list[str] = field(default_factory=list)
    faint: list[str] = field(default_factory=list)


def read_images(images: list[bytes]) -> list[ImageText | None]:
    """OCR ``images`` in one worker. None for each image that stays unread.

    Every answer is None when the worker failed, ran out of time, or found
    its slot busy; an image past ``MAX_IMAGES`` or ``MAX_IMAGE_BYTES`` is
    None without being sent.
    """
    # TRUST: decoding and reading images nobody has judged yet
    #   untrusted: every image, and therefore everything the worker prints
    #   judged-by: nothing here; every line returned is read by the layers
    #   on-failure: fail-closed: None, and the caller counts the image unread
    #   owner: unpack.ocr.read_images
    #   evidence: T1 child.ask: a child with RLIMIT_CPU, RLIMIT_AS, a wall-clock
    #     kill and no secret in its environment; T1 _checked() accepts only its
    #     shapes; T4 tests/test_unpack_ocr.py
    unread: list[ImageText | None] = [None] * len(images)
    sent = [i for i, image in enumerate(images) if len(image) <= MAX_IMAGE_BYTES][:MAX_IMAGES]
    if not sent:
        return unread
    request = {
        "images": [base64.b64encode(images[i]).decode("ascii") for i in sent],
        "seconds": BUDGET,
    }
    answer = ask(
        WORKER,
        json.dumps(request).encode(),
        slots=_slot,
        deadline=BUDGET + GRACE,
        max_output=MAX_OUTPUT,
    )
    try:
        answers = _checked(json.loads(answer), len(sent)) if isinstance(answer, bytes) else None
    except (ValueError, TypeError, KeyError, RecursionError):
        answers, answer = None, MALFORMED
    if answers is None:
        # `answer` is one of child.py's phrases or ours, never an image's text.
        logger.warning("ocr: %d image(s) unread, %s", len(sent), answer)
        return unread
    for index, read in zip(sent, answers, strict=True):
        unread[index] = read
    return unread


def _strings(value: object) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError("not a list of strings")
    return value


def _checked(raw: object, expected: int) -> list[ImageText | None]:
    """The worker's JSON as ``ImageText`` rows. Raises on any other shape."""
    if not isinstance(raw, dict) or not isinstance(raw["images"], list):
        raise TypeError("not an answer")
    if len(raw["images"]) != expected:
        raise ValueError("an answer for a different request")
    return [
        None if entry is None else ImageText(_strings(entry["text"]), _strings(entry["faint"]))
        for entry in raw["images"]
    ]
