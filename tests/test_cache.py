from __future__ import annotations

from collections.abc import Iterator
from unittest.mock import MagicMock, patch

import diskcache
import pytest
from inline_snapshot import snapshot

import mreg_cli.cache
from mreg_cli.cache import (
    CacheLike,
    MregCliCache,
    NullCache,
    _create_cache,
    configure,
    get_cache,
)
from mreg_cli.config import MregCliConfig


@pytest.fixture()
def mock_cache_config() -> MregCliConfig:
    """Create a mock MregCliConfig for testing."""
    c = MagicMock(spec=MregCliConfig)
    c.get_cache_enabled.return_value = True
    c.get_cache_ttl.return_value = 300
    return c


@pytest.fixture(autouse=True)
def configure_cache(mock_cache_config: MregCliConfig) -> Iterator[None]:
    """Configure the global cache for testing."""
    try:
        configure(mock_cache_config)
        yield
    finally:
        # Clear the cache and delete the global cache object
        cache = get_cache()
        cache.clear()
        mreg_cli.cache._CACHE = None


def test_mreg_cli_cache_is_diskcache_cache(mock_cache_config: MregCliConfig) -> None:
    """Ensure that create_cache returns a diskcache.Cache object."""
    c = _create_cache(mock_cache_config)
    assert isinstance(c, diskcache.Cache)


def test_diskcache_cache_is_cachelike() -> None:
    """Test that the diskcache.Cache class conforms to the CacheLike protocol."""
    # Create a new cache
    c = diskcache.Cache(name="diskcache_cache_is_cachelike")
    assert isinstance(c, CacheLike)


def test_diskcache_cache_init_error(mock_cache_config: MregCliConfig) -> None:
    """Test that a diskcache.Cache() init error returns a NullCache."""
    with patch("mreg_cli.cache.Cache") as mock_cache:
        # Make Cache() raise an exception during initialization
        mock_cache.side_effect = Exception("Disk cache initialization failed")
        # Verify that the result is an instance of NullCache
        result = _create_cache(mock_cache_config)
        assert isinstance(result, NullCache)


def test_nullcache_memoize() -> None:
    """Test that NullCache.memoize() returns the original function."""
    cache = NullCache()

    def sample_function(x: int) -> int:
        return x * 2

    memoized_function = cache.memoize()(sample_function)
    assert memoized_function is sample_function


def test_nullcache_methods() -> None:
    """Test that NullCache methods work as expected."""
    cache = NullCache()
    assert cache.evict(tag="test", retry=True) == 0
    assert cache.clear(retry=True) == 0
    assert cache.delete("key") is True
    assert cache.delete("key", retry=True) is True
    assert cache.get("key") is None
    assert cache.get("key", default="default") == "default"
    assert cache.set("key", "value") is True
    assert cache.set("key", "value", expire=60, read=True, tag="test", retry=True) is True
    assert cache.touch("key") is True
    assert cache.touch("key", expire=60) is True
    assert cache.volume() == 0


def test_get_cache_not_configured(mock_cache_config: MagicMock) -> None:
    """Test that get_cache() returns a NullCache when caching is disabled."""
    # Reset global cache and disable caching in config
    mock_cache_config.get_cache_enabled.return_value = False
    mreg_cli.cache._CACHE = None

    configure(mock_cache_config)
    cache = get_cache()
    assert isinstance(cache.cache, NullCache)


def test_get_cache_info_noarg() -> None:
    """Test MregCliCache.get_cache_info() with the default cache."""
    # Clear cache first

    cache = get_cache()

    cache.clear()
    assert isinstance(cache.cache, diskcache.Cache)

    info = cache.get_info()
    # Mock the directory property (non-deterministic)
    info.directory = "mocked_directory"

    assert info.model_dump(mode="json") == snapshot(
        {
            "items": 0,
            "size": "32.0KiB",
            "hits": 0,
            "misses": 0,
            "ttl": 300,
            "directory": "mocked_directory",
        }
    )


def test_get_cache_info_nullcache() -> None:
    """Test get_cache_info() with a NullCache cache."""
    c = NullCache()
    cache = MregCliCache(c)
    info = cache.get_info()
    assert info.model_dump(mode="json") == snapshot(
        {
            "items": 0,
            "size": "0B",
            "hits": 0,
            "misses": 0,
            "ttl": 300,
            "directory": "",
        }
    )
