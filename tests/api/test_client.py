from __future__ import annotations

from unittest.mock import patch

from mreg_api import CacheConfig, MregClient

from mreg_cli.config import MregCliConfig


def test_client_cache_readonly_fs_dir() -> None:
    """Test that client caching handles read-only filesystem gracefully (with directory arg)."""
    with patch("os.makedirs") as mock_makedirs:
        mock_makedirs.side_effect = PermissionError("Read-only directory")
        client = MregClient(cache=CacheConfig(enable=True, directory="/readonly/path"))
    assert not client.cache.is_enabled
    assert client.cache._cache is None  # pyright: ignore[reportPrivateUsage]


def test_client_cache_readonly_fs_no_dir() -> None:
    """Test that client caching handles read-only filesystem gracefully."""
    with patch("tempfile.mkdtemp") as mock_mkdtemp:
        mock_mkdtemp.side_effect = PermissionError("Read-only directory")
        client = MregClient(cache=CacheConfig(enable=True))
    assert not client.cache.is_enabled
    assert client.cache._cache is None  # pyright: ignore[reportPrivateUsage]


def test_client_cache_default_enabled() -> None:
    """Test that client caching is enabled by default."""
    cliconf = MregCliConfig()
    client = MregClient(cache=CacheConfig(enable=cliconf.cache))
    assert client.cache.is_enabled
    assert client.cache._cache is not None  # pyright: ignore[reportPrivateUsage
