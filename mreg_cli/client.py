"""Global MregClient accessor for mreg-cli.

The client is constructed once in main() and stored here via set_client().
All other modules retrieve it via get_client() instead of instantiating MregClient directly.
"""

from __future__ import annotations

from mreg_api import MregClient

_client: MregClient | None = None


def set_client(client: MregClient | None) -> None:
    """Store the global client instance (pass None to reset, e.g. in tests)."""
    global _client
    _client = client


def get_client() -> MregClient:
    """Return the global client instance.

    :raises RuntimeError: If set_client() has not been called yet.
    """
    if _client is None:
        raise RuntimeError("MregClient not initialized — call set_client() first.")
    return _client
