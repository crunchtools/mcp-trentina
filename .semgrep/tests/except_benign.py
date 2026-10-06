# Fixture for trentina-except-returns-benign.
import logging

from trentina.errors import BlockedSourceError

log = logging.getLogger(__name__)
BENIGN = object()


def classify_or_benign(session, text):
    try:
        return session.run(text)
    except Exception:
        log.warning("classifier unavailable")
        # ruleid: trentina-except-returns-benign
        return BENIGN


def judge(text):
    try:
        return run_l3(text)
    except TimeoutError as exc:
        # ruleid: trentina-except-returns-benign
        return {"injection_detected": False, "risk": "low"}


def check_guard(value):
    try:
        return match(value)
    except ValueError:
        # ruleid: trentina-except-returns-benign
        return True


def classify_label(text):
    try:
        return model(text)
    except:
        # ruleid: trentina-except-returns-benign
        return ClassifierResult(label="BENIGN", score=0.0)


def judge_closed(text, source):
    try:
        return run_l3(text)
    except Exception as exc:
        # ok: trentina-except-returns-benign
        raise BlockedSourceError(source, "l3_unavailable") from exc


def lookup(key):
    try:
        return table[key]
    except KeyError:
        # ok: trentina-except-returns-benign
        return None


def verify(text):
    try:
        return run_l3(text)
    except TimeoutError:
        # ok: trentina-except-returns-benign
        return {"injection_detected": False, "l3_unavailable": True}


def is_unavailable(text):
    try:
        return scan(text).flagged
    except Exception:
        # ok: trentina-except-returns-benign
        return "unavailable"
