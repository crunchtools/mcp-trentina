"""Pre-processors: token reduction outside the security perimeter.

See ``base.py`` for the three invariants. The short version: this package
makes payloads smaller, never safer — everything it emits is untrusted and
crosses the defense pipeline on the way in.
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
