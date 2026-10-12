"""Correlation engine package for Security Log Correlation Engine."""

from log_corr.engine.correlator import CorrelationEngine
from log_corr.engine.window_buffer import SlidingWindowBuffer

__all__ = [
    "CorrelationEngine",
    "SlidingWindowBuffer",
]
