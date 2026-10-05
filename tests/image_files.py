"""Small images with text drawn in them, built in memory with Pillow."""

from __future__ import annotations

import io

from PIL import Image, ImageDraw, ImageFont

BANNER = (900, 300)
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
NEAR_WHITE = (250, 250, 250)
"""Five grey levels off white: on a white page, nobody sees it."""
CLEAR = (0, 0, 0, 0)


def picture(
    text: str,
    *,
    ink: tuple[int, ...] = BLACK,
    paper: tuple[int, ...] = WHITE,
    kind: str = "PNG",
    size: tuple[int, int] = BANNER,
) -> bytes:
    """An image of ``text``, one line per line, in the default face at 28 px."""
    image = Image.new("RGBA" if len(paper) == 4 else "RGB", size, paper)
    pen = ImageDraw.Draw(image)
    face = ImageFont.load_default(size=28)
    for row, line in enumerate(text.split("\n")):
        pen.text((20, 20 + 40 * row), line, fill=ink, font=face)
    packed = io.BytesIO()
    image.save(packed, kind)
    return packed.getvalue()


def noise(size: tuple[int, int] = (400, 300)) -> bytes:
    """A PNG of incompressible pixels: large for its dimensions, and no text."""
    image = Image.frombytes("RGB", size, _bytes(size[0] * size[1] * 3))
    packed = io.BytesIO()
    image.save(packed, "PNG")
    return packed.getvalue()


def _bytes(count: int) -> bytes:
    import hashlib

    blocks = (hashlib.sha256(index.to_bytes(4)).digest() for index in range(count // 32 + 1))
    return b"".join(blocks)[:count]
