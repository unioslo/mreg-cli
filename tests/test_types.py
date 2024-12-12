from __future__ import annotations

from inline_snapshot import snapshot

from mreg_cli.types import LogLevel


def test_loglevel_as_int() -> None:
    """Test that all LogLevel members have an integer representation."""
    for level in list(LogLevel):
        # If it doesn't implement as_int, this will raise a KeyError
        assert level.as_int() is not None

    # Snapshot so we can see if any values are changed
    assert [lvl.as_int() for lvl in list(LogLevel)] == snapshot([10, 20, 30, 40, 50])
