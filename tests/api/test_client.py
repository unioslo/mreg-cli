from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from mreg_api import CacheConfig
from mreg_api.endpoints import Endpoint
from pytest_httpserver import HTTPServer

from mreg_cli.client import MregCliClient
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import TooManyResults


def test_client_cache_readonly_fs_dir() -> None:
    """Test that client caching handles read-only filesystem gracefully (with directory arg)."""
    with patch("os.makedirs") as mock_makedirs:
        mock_makedirs.side_effect = PermissionError("Read-only directory")
        client = MregCliClient(
            url="https://mreg.example.com",
            cache=CacheConfig(enable=True, directory="/readonly/path"),
        )
    assert not client.cache.is_enabled
    assert client.cache._cache is None  # pyright: ignore[reportPrivateUsage]


def test_client_cache_readonly_fs_no_dir() -> None:
    """Test that client caching handles read-only filesystem gracefully."""
    with patch("tempfile.mkdtemp") as mock_mkdtemp:
        mock_mkdtemp.side_effect = PermissionError("Read-only directory")
        client = MregCliClient(url="https://mreg.example.com", cache=CacheConfig(enable=True))
    assert not client.cache.is_enabled
    assert client.cache._cache is None  # pyright: ignore[reportPrivateUsage]


def test_client_cache_default_enabled() -> None:
    """Test that client caching is enabled by default."""
    cliconf = MregCliConfig()
    client = MregCliClient(url="https://mreg.example.com", cache=CacheConfig(enable=cliconf.cache))
    assert client.cache.is_enabled
    assert client.cache._cache is not None  # pyright: ignore[reportPrivateUsage


@pytest.mark.parametrize("paginated_response", [True, False])
def test_client_limit(httpserver: HTTPServer, paginated_response: bool) -> None:
    """Test that exceeding the limit raises TooManyResults, and that the limit is respected."""
    client = MregCliClient(url=httpserver.url_for("/"), cache=False)

    resp: list[dict[str, Any]] | dict[str, Any] = [
        {
            "id": 1,
            "name": "host1",
            "comment": "",
            "ipaddresses": [],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        },
        {
            "id": 2,
            "name": "host2",
            "comment": "",
            "ipaddresses": [],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        },
        {
            "id": 3,
            "name": "host3",
            "comment": "",
            "ipaddresses": [],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        },
        {
            "id": 4,
            "name": "host4",
            "comment": "",
            "ipaddresses": [],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        },
        {
            "id": 5,
            "name": "host5",
            "comment": "",
            "ipaddresses": [],
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-01T00:00:00Z",
        },
    ]
    if paginated_response:
        resp = {
            "results": resp,
            "next": None,
            "previous": None,
            "count": 5,
        }
    httpserver.expect_request(Endpoint.Hosts).respond_with_json(resp)

    # This fails
    with pytest.raises(TooManyResults) as excinfo:
        client.host.list(limit=4)
    assert "Refine your search" in str(excinfo.value)

    # This succeeds
    hosts = client.host.list(limit=5)  # truncates without raising
    assert len(hosts) == 5
