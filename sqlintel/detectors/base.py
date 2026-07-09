"""Detector interface. Each technique is a self-contained detector so the engine can
run, extend, or (later) let the ML layer weight them independently."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..core.http_client import HttpClient, Response
from ..core.target import Finding, InjectionPoint, Request


class BaseDetector(ABC):
    #: Human-readable technique name, also stored on the Finding.
    name: str = "base"

    def __init__(self, client: HttpClient, baseline: Response) -> None:
        self.client = client
        self.baseline = baseline

    @abstractmethod
    def test(self, req: Request, point: InjectionPoint) -> Optional[Finding]:
        """Return a Finding if this technique detects injection at `point`, else None."""
        raise NotImplementedError

    def _mutate_value(self, point: InjectionPoint, payload: str) -> str:
        """Append a payload to the parameter's baseline value (the common case)."""
        return f"{point.value}{payload}"
