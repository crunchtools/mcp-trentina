"""Run one of the unpack stage's parsers as a child process (#369, #370).

PDFs and images are parsed by libraries this gateway does not trust with
its own process: a pure-Python PDF parser with a history of inputs that
loop, and three native libraries decoding hostile images. A thread cannot
be stopped; a process can. Each worker module limits its own CPU and
address space; this side gives it an environment with no credential, bounds
how many run at once, and kills it at a wall-clock deadline.

Waiting for a worker is a thread's job, so everything that can reach one
runs in ``run_unpacking``'s threads, never in the pool ``asyncio.to_thread``
shares between L1, the tokenizer and every other profile's request (#383).

``ask`` returns the worker's output, or a phrase saying why there is none.
The phrases are this module's own, so they are safe to log.
"""

from __future__ import annotations

import asyncio
import contextvars
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import threading
    from collections.abc import Callable

SLOT_WAIT = 5.0
"""Seconds a request waits for a free slot before it is given up as unread.
A burst of PDFs past ``UNPACK_THREADS`` holds every unpack thread for this
long, and text waits behind it, so the wait is short."""

UNPACK_THREADS = 32
"""Threads that unpack. A thread holds its place while a worker runs (up to a
minute for a page of images) or while it waits ``SLOT_WAIT`` for one, and
plain text needs a free thread for its milliseconds; three workers run at
once, so this is ten requests waiting per worker."""

_POOL = ThreadPoolExecutor(max_workers=UNPACK_THREADS, thread_name_prefix="unpack")

NO_SLOT = "no slot free"
DEADLINE = "deadline"
NOT_STARTED = "could not start"
FAILED = "worker failed"
TOO_LARGE = "answer too large"


def environment() -> dict[str, str]:
    """What a worker starts with: the import path, and no credential."""
    return {
        "PYTHONPATH": os.pathsep.join(p for p in sys.path if p),
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


async def run_unpacking(reader: Callable[..., Any], *args: Any) -> Any:
    """Run a function that may reach a worker, off the loop and off the shared pool.

    The caller's context goes with it, as ``asyncio.to_thread`` would take it.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_POOL, contextvars.copy_context().run, reader, *args)


def ask(
    module: str,
    request: bytes,
    *,
    slots: threading.BoundedSemaphore,
    deadline: float,
    max_output: int,
) -> bytes | str:
    """Run ``module`` with ``request`` on its stdin and return what it prints.

    Args:
        module: A worker module of this package, run with ``python -m``.
            Always a constant of the caller's, never anything from a payload.
        request: The worker's whole input. The payload travels here and
            nowhere else: it is never part of a command line.
        slots: How many of this worker may run at once.
        deadline: Wall-clock seconds before the worker is killed.
        max_output: Bytes of output accepted.

    Returns:
        The worker's stdout, or one of this module's phrases when it found
        no slot, could not start, ran past the deadline, exited non-zero or
        printed too much.
    """
    if not slots.acquire(timeout=SLOT_WAIT):
        return NO_SLOT
    try:
        done = subprocess.run(
            [sys.executable, "-m", module],
            input=request,
            capture_output=True,
            timeout=deadline,
            env=environment(),
            cwd="/",
            check=False,
        )
    except subprocess.TimeoutExpired:
        return DEADLINE
    except OSError:
        return NOT_STARTED
    finally:
        slots.release()
    if done.returncode != 0:
        return FAILED
    return done.stdout if len(done.stdout) <= max_output else TOO_LARGE
