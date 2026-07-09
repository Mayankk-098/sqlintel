from .base import BaseDetector
from .error_based import ErrorBasedDetector
from .boolean_based import BooleanBasedDetector
from .time_based import TimeBasedDetector

# Order matters: cheapest / most reliable signal first.
ALL_DETECTORS = [ErrorBasedDetector, BooleanBasedDetector, TimeBasedDetector]

__all__ = [
    "BaseDetector",
    "ErrorBasedDetector",
    "BooleanBasedDetector",
    "TimeBasedDetector",
    "ALL_DETECTORS",
]
