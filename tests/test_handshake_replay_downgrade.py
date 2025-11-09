import pytest

# Replay/downgrade tests need a full handshake+transport harness. Point to the
# new `app` package and skip until we implement an in-process test harness.
from app import handshake, channel


def test_replay_m2_fails():
    pytest.skip("Replay/downgrade tests not migrated to `app` API yet")