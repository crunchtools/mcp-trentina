"""Pre-processors: payload transformation outside the security perimeter.

See ``base.py`` for the three invariants. The short version: this package may
subtract but never absolve — it drops, collapses, normalizes and restructures,
and everything it emits is exactly as untrusted as what went in and crosses
the defense pipeline on the way.
"""

from .base import Cost, PreProcessContext, PreProcessor, PreProcessResult
from .compose import PreProcessOutcome, Strategy, run_preprocessors
from .email import EmailProcessor
from .petit import PetitProcessor
from .structured import StructuredProcessor
from .summarize import SummarizeProcessor

__all__ = [
    "Cost",
    "EmailProcessor",
    "PetitProcessor",
    "PreProcessContext",
    "PreProcessOutcome",
    "PreProcessResult",
    "PreProcessor",
    "Strategy",
    "StructuredProcessor",
    "SummarizeProcessor",
    "run_preprocessors",
]
