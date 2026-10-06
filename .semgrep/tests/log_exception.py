# Fixture for trentina-log-exception-text.
import logging

from trentina.logsafe import exc_kind, exc_where, redact_source

log = logging.getLogger(__name__)
logger = logging.getLogger("x")


def fetch(url):
    try:
        return get(url)
    except OSError as exc:
        # ruleid: trentina-log-exception-text
        log.warning("fetch failed: %s", exc)
        raise


def fetch_str(url):
    try:
        return get(url)
    except OSError as exc:
        # ruleid: trentina-log-exception-text
        logger.error("fetch failed: %s", str(exc))
        raise


def fetch_fstring(url):
    try:
        return get(url)
    except OSError as err:
        # ruleid: trentina-log-exception-text
        log.info(f"fetch failed: {err}")
        raise


def fetch_trace(url):
    try:
        return get(url)
    except OSError:
        # ruleid: trentina-log-exception-text
        log.exception("fetch failed")
        raise


def fetch_exc_info(url):
    try:
        return get(url)
    except OSError:
        # ruleid: trentina-log-exception-text
        log.warning("fetch failed", exc_info=True)
        raise


def fetch_safe(url):
    try:
        return get(url)
    except OSError as exc:
        # ok: trentina-log-exception-text
        log.warning("fetch %s failed: %s at %s", redact_source(url), exc_kind(exc), exc_where(exc))
        raise


def startup():
    try:
        return load()
    except OSError:
        # ok: trentina-log-exception-text
        log.exception("load failed")  # nosemgrep: trentina-log-exception-text -- logsafe: ours
        raise
