from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any

import pytest

from mreg_cli.api.models import IPNetMode, NetworkOrIP
from mreg_cli.exceptions import (
    InvalidIPAddress,
    InvalidIPv4Address,
    InvalidIPv6Address,
    InvalidNetwork,
)


@pytest.mark.parametrize(
    "inp, mode, expect",
    [
        # Basic tests for each type
        ("192.168.0.1", IPNetMode.IP, IPv4Address("192.168.0.1")),
        ("192.168.0.1", IPNetMode.IPv4, IPv4Address("192.168.0.1")),
        ("192.168.0.0/24", IPNetMode.NETWORK, IPv4Network("192.168.0.0/24")),
        ("2001:db8::1", IPNetMode.IP, IPv6Address("2001:db8::1")),
        ("2001:db8::1", IPNetMode.IPv6, IPv6Address("2001:db8::1")),
        ("2001:db8::/64", IPNetMode.NETWORK, IPv6Network("2001:db8::/64")),
        # No mode (auto-detect) tests for each type
        ("192.168.0.1", None, IPv4Address("192.168.0.1")),
        ("192.168.0.0/24", None, IPv4Network("192.168.0.0/24")),
        ("2001:db8::1", None, IPv6Address("2001:db8::1")),
        ("2001:db8::/64", None, IPv6Network("2001:db8::/64")),
        # Invalid input (wrong mode)
        pytest.param(
            "192.168.0.1",
            IPNetMode.IPv6,
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv6Address, strict=True),
        ),
        pytest.param(
            "192.168.0.1",
            IPNetMode.NETWORK,
            None,
            marks=pytest.mark.xfail(raises=InvalidNetwork, strict=True),
        ),
        pytest.param(
            "192.168.0.0/24",
            IPNetMode.IPv4,
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv4Address, strict=True),
        ),
        pytest.param(
            "192.168.0.0/24",
            IPNetMode.IP,
            None,
            marks=pytest.mark.xfail(raises=InvalidIPAddress, strict=True),
        ),
        pytest.param(
            "2001:db8::1",
            IPNetMode.IPv4,
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv4Address, strict=True),
        ),
        pytest.param(
            "2001:db8::1",
            IPNetMode.NETWORK,
            None,
            marks=pytest.mark.xfail(raises=InvalidNetwork, strict=True),
        ),
        pytest.param(
            "2001:db8::/64",
            IPNetMode.IPv6,
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv6Address, strict=True),
        ),
    ],
)
def test_network_or_ip_from_string(inp: str, mode: IPNetMode, expect: Any) -> None:
    """Test the network or IP address from string."""
    res = NetworkOrIP.from_string(inp, mode)
    assert res == expect
