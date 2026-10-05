"""Small images with text drawn in them, built in memory with Pillow."""

from __future__ import annotations

import hashlib
import io
import textwrap

from PIL import Image, ImageDraw, ImageFont

BANNER = (900, 300)
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
NEAR_WHITE = (250, 250, 250)
"""Five grey levels off white: on a white page, nobody sees it."""
CLEAR = (0, 0, 0, 0)
FACE = 28
"""Pixels tall the default face is drawn at."""
EDGE = 20
LINE = 40
"""Pixels from the edge to the first line, and from one line to the next."""
WRAP = 64
PAGE_WIDTH = 1100
"""Characters to a line in ``page``."""


def picture(
    text: str,
    *,
    ink: tuple[int, ...] = BLACK,
    paper: tuple[int, ...] = WHITE,
    kind: str = "PNG",
    size: tuple[int, int] = BANNER,
) -> bytes:
    """An image of ``text``, one line per line, in the default face at 28 px."""
    image = Image.new("RGBA" if len(paper) == len(CLEAR) else "RGB", size, paper)
    pen = ImageDraw.Draw(image)
    face = ImageFont.load_default(size=FACE)
    for row, line in enumerate(text.split("\n")):
        pen.text((EDGE, EDGE + LINE * row), line, fill=ink, font=face)
    packed = io.BytesIO()
    image.save(packed, kind)
    return packed.getvalue()


def page(text: str) -> bytes:
    """A picture of ``text`` in Latin-1, wrapped at ``WRAP``, as tall as it needs."""
    lines = [
        wrapped.encode("latin-1", "replace").decode("latin-1")
        for line in text.splitlines()
        for wrapped in textwrap.wrap(line, WRAP) or [""]
    ]
    return picture("\n".join(lines), size=(PAGE_WIDTH, LINE * len(lines) + LINE))


def noise(size: tuple[int, int] = (400, 300)) -> bytes:
    """A PNG of incompressible pixels: large for its dimensions, and no text."""
    count = size[0] * size[1] * 3
    blocks = (hashlib.sha256(index.to_bytes(4)).digest() for index in range(count // 32 + 1))
    image = Image.frombytes("RGB", size, b"".join(blocks)[:count])
    packed = io.BytesIO()
    image.save(packed, "PNG")
    return packed.getvalue()
