"""Global MregClient accessor for mreg-cli.

The client is constructed once in main() and stored here via set_client().
All other modules retrieve it via get_client() instead of instantiating MregClient directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mreg_api import MregClient
from mreg_api.cache import CacheConfig

from mreg_cli.__about__ import __version__

if TYPE_CHECKING:
    from mreg_cli.config import MregCliConfig

_client: MregClient | None = None


def init_client(config: MregCliConfig) -> MregClient:
    """Initialize the global client instance given the config."""
    global _client
    if _client is None:
        _client = MregClient(
            url=config.url,
            domain=config.domain,
            timeout=config.http_timeout,
            user_agent=f"mreg-cli/{__version__}",
            cache=CacheConfig(
                enable=config.cache,
                ttl=config.cache_ttl,
                # other cache settings from config should go here
            ),
        )
    return _client


# NOTE: maybe add some protection here to prevent calling this in the main loop
# some sort of global state that only allows this to be called in tests?
# That begs the question why we even have this function.
def _reset_client() -> None:  # pyright: ignore[reportUnusedFunction] # in tests
    """Reset the global client instance (for testing)."""
    global _client
    _client = None


def get_client() -> MregClient:
    """Return the global client instance.

    :raises RuntimeError: If init_client() has not been called yet.
    """
    if _client is None:
        raise RuntimeError("MregClient not initialized — call init_client() first.")
    return _client
