from .base import BaseDetector
from .error_based import ErrorBasedDetector
from .boolean_based import BooleanBasedDetector
from .union_based import UnionBasedDetector
from .time_based import TimeBasedDetector

# Order matters: cheapest / most reliable signal first. UNION runs after the cheap
# error/boolean checks (it can cost several requests) but before the slow time-based one.
ALL_DETECTORS = [
    ErrorBasedDetector,
    BooleanBasedDetector,
    UnionBasedDetector,
    TimeBasedDetector,
]

__all__ = [
    "BaseDetector",
    "ErrorBasedDetector",
    "BooleanBasedDetector",
    "UnionBasedDetector",
    "TimeBasedDetector",
    "ALL_DETECTORS",
]
