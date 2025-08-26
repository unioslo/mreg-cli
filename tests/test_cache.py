from __future__ import annotations

from unittest.mock import patch

import diskcache
from inline_snapshot import snapshot

from mreg_cli.cache import CacheLike, NullCache, create_cache, get_cache_info


def test_mreg_cli_cache_is_diskcache_cache() -> None:
    """Ensure that create_cache returns a diskcache.Cache object."""
    c = create_cache()
    assert isinstance(c, diskcache.Cache)


def test_diskcache_cache_is_cachelike() -> None:
    """Test that the diskcache.Cache class conforms to the CacheLike protocol."""
    # Create a new cache
    c = diskcache.Cache(name="diskcache_cache_is_cachelike")
    assert isinstance(c, CacheLike)


def test_diskcache_cache_init_error() -> None:
    """Test that a diskcache.Cache() init error returns a NullCache."""
    with patch("mreg_cli.cache.Cache") as mock_cache:
        # Make Cache() raise an exception during initialization
        mock_cache.side_effect = Exception("Disk cache initialization failed")
        # Verify that the result is an instance of NullCache
        result = create_cache()
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


def test_get_cache_info_noarg() -> None:
    """Test that get_cache_info() returns the expected CacheInfo given no arguments."""
    # Clear cache first
    from mreg_cli.cache import cache

    cache.clear()

    info = get_cache_info()
    # Mock the directory property (non-deterministic)
    info.directory = "mocked_directory"

    assert info.model_dump(mode="json") == snapshot(
        {"items": 0, "size": "32.0KiB", "hits": 0, "misses": 0, "directory": "mocked_directory"}
    )


def test_get_cache_info_diskcache_cache() -> None:
    """Test get_cache_info() with a diskcache.Cache argument."""
    c = diskcache.Cache()
    info = get_cache_info(c)
    # Mock directory
    info.directory = "mocked_directory"
    assert info.model_dump(mode="json") == snapshot(
        {"items": 0, "size": "32.0KiB", "hits": 0, "misses": 0, "directory": "mocked_directory"}
    )
