"""Where read_tool and dir_tool may look (#261).

Both tools take a path from the agent, and until #261 neither asked where it
pointed: ``read_tool /config/profiles.yaml`` delivered every profile's
topology and the credentials inside backend URLs. The rule here is default
deny behind a gateway:

- ``TRENTINA_READ_ROOTS`` lists the directories a path may resolve into.
  A live gateway with none configured refuses every path — production leaves
  it unset on purpose, since the gateway container has no agent workspace.
  A standalone server with none keeps its old reach: one operator, their
  own files.
- ``HARD_DENIED`` and Trentina's own state and config directories are
  refused even when a root would admit them. A root of ``/`` does not
  open ``/proc/self/environ``.

Checking a path and then opening it is a race: swap a component for a
symlink in between and the open lands somewhere the check never saw.
``open_confined`` closes it three ways. ``O_NOFOLLOW`` refuses a symlink in
the final component; ``fstat`` must match the inode stat'd at check time;
and the kernel's own name for the opened descriptor is checked again, which
catches a swapped INTERMEDIATE directory that the other two follow.

Refusals carry a reason code and never the path (see ``FileReadError``).
"""

from __future__ import annotations

import errno
import os
from pathlib import Path

from ..config import get_config
from ..errors import FileReadError
from ..gateway.loader import get_active_config

HARD_DENIED = ("/config", "/data", "/proc", "/sys", "/run", "/dev")
_FD_DIR = Path("/proc/self/fd")


def denied_dirs() -> list[Path]:
    """Directories no root can admit: the kernel's, and Trentina's own state and config."""
    config = get_config()
    own = [config.db_path, config.perimeter_db_path, config.trust_config_path]
    active = get_active_config()
    if active is not None:
        own.append(str(active.path))
    dirs = [Path(d).resolve() for d in HARD_DENIED]
    dirs += [Path(p).resolve().parent for p in own]
    return dirs


def check(resolved: Path) -> None:
    """Refuse a fully resolved path that is denied or outside every root."""
    if any(resolved.is_relative_to(d) for d in denied_dirs()):
        raise FileReadError("denied_path")
    roots = get_config().read_roots
    if roots:
        if not any(resolved.is_relative_to(r) for r in roots):
            raise FileReadError("outside_read_roots")
    elif get_active_config() is not None:
        raise FileReadError("outside_read_roots")


def confine(path: str) -> Path:
    """Resolve ``path`` (it must exist) and refuse it unless ``check`` admits it."""
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError):
        raise FileReadError("not_found") from None
    check(resolved)
    return resolved


def _opened_path(fd: int) -> Path | None:
    """The kernel's name for an open descriptor, or None where /proc is absent."""
    try:
        return Path(os.readlink(_FD_DIR / str(fd)))
    except OSError:
        return None


def _verify_opened(fd: int, checked: os.stat_result) -> os.stat_result:
    """Refuse an fd that is not the inode checked, or whose real path is not admitted."""
    opened = os.fstat(fd)
    if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
        raise FileReadError("changed_during_read")
    actual = _opened_path(fd)
    if actual is not None:
        check(actual)
    return opened


def open_confined(path: str, extra_flags: int = 0) -> tuple[int, os.stat_result, Path]:
    """Open ``path`` read-only if confinement admits it; the caller closes the fd.

    Returns the descriptor, its ``fstat`` and the resolved path. ``O_NONBLOCK``
    keeps a FIFO swapped in after the check from hanging the open; callers
    still require the file type they expect from the returned stat.
    """
    resolved = confine(path)
    try:
        checked = os.stat(resolved)
    except OSError:
        raise FileReadError("not_found") from None
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | extra_flags
    try:
        fd = os.open(resolved, flags)
    except NotADirectoryError:
        raise FileReadError("not_a_directory") from None
    except OSError as exc:
        # ELOOP is O_NOFOLLOW meeting a symlink that was not there at check time.
        swapped = exc.errno == errno.ELOOP
        raise FileReadError("changed_during_read" if swapped else "not_found") from None
    try:
        opened = _verify_opened(fd, checked)
    except BaseException:
        os.close(fd)
        raise
    return fd, opened, resolved
