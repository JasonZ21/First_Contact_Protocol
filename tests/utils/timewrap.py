"""
A tiny context manager to monkeypatch datetime.now()/time.time() used by cert validation
or the code under test. Tests can use it to simulate clocks for expiry tests.
"""

import contextlib
import time
from datetime import datetime, timezone

@contextlib.contextmanager
def timewarp(iso_timestamp: str):
    """
    e.g. with timewarp("2025-11-01T00:00:00Z"):
        # inside context, calls to time.time() or datetime.now(timezone.utc) should
        # reflect the target timestamp.
    Implementation note: Keep this small and patch only the places your code uses.
    """
    # Minimal no-op implementation: tests can opt into using this context manager
    # as a marker; if richer behaviour is required we can monkeypatch time/datetime
    # here in a future change.
    yield