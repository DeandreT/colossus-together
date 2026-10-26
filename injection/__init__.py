"""Offline, project-owned EE telemetry helpers; deliberately no installer."""

from .generator import Config, build, guard_expectations, render, validate_prologues
from .records import RingReader, TelemetryLoss, initial_state

__all__ = [
    "Config",
    "RingReader",
    "TelemetryLoss",
    "build",
    "guard_expectations",
    "initial_state",
    "render",
    "validate_prologues",
]
