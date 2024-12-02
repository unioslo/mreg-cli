from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Callable

import pytest

from mreg_cli.api.models import IPNetMode, Network, NetworkOrIP
from mreg_cli.exceptions import (
    InputFailure,
    InvalidIPAddress,
    InvalidIPv4Address,
    InvalidIPv6Address,
    InvalidNetwork,
)
from mreg_cli.types import IP_NetworkT


@pytest.mark.parametrize(
    "inp, mode, expect",
    [
        # Basic tests for each type
        ("192.168.0.1", "ip", IPv4Address("192.168.0.1")),
        ("192.168.0.1", "ipv4", IPv4Address("192.168.0.1")),
        ("192.168.0.0/24", "network", IPv4Network("192.168.0.0/24")),
        ("192.168.0.0/24", "networkv4", IPv4Network("192.168.0.0/24")),
        ("2001:db8::1", "ip", IPv6Address("2001:db8::1")),
        ("2001:db8::1", "ipv6", IPv6Address("2001:db8::1")),
        ("2001:db8::/64", "network", IPv6Network("2001:db8::/64")),
        ("2001:db8::/64", "networkv6", IPv6Network("2001:db8::/64")),
        # No mode (auto-detect) tests for each type
        ("192.168.0.1", None, IPv4Address("192.168.0.1")),
        ("192.168.0.0/24", None, IPv4Network("192.168.0.0/24")),
        ("2001:db8::1", None, IPv6Address("2001:db8::1")),
        ("2001:db8::/64", None, IPv6Network("2001:db8::/64")),
        # Invalid input (wrong mode)
        pytest.param(
            "192.168.0.1",
            "ipv6",
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv6Address, strict=True),
        ),
        pytest.param(
            "192.168.0.1",
            "network",
            None,
            marks=pytest.mark.xfail(raises=InvalidNetwork, strict=True),
        ),
        pytest.param(
            "192.168.0.0/24",
            "ipv4",
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv4Address, strict=True),
        ),
        pytest.param(
            "192.168.0.0/24",
            "ip",
            None,
            marks=pytest.mark.xfail(raises=InvalidIPAddress, strict=True),
        ),
        pytest.param(
            "2001:db8::1",
            "ipv4",
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv4Address, strict=True),
        ),
        pytest.param(
            "2001:db8::1",
            "network",
            None,
            marks=pytest.mark.xfail(raises=InvalidNetwork, strict=True),
        ),
        pytest.param(
            "2001:db8::/64",
            "ipv6",
            None,
            marks=pytest.mark.xfail(raises=InvalidIPv6Address, strict=True),
        ),
    ],
)
def test_network_or_ip_parse(inp: str, mode: IPNetMode, expect: Any) -> None:
    """Test the network or IP address from string."""
    res = NetworkOrIP.parse_or_raise(inp, mode)
    assert res == expect


@pytest.mark.parametrize(
    "inp, expect_type_call",
    [
        ("192.168.0.1", NetworkOrIP.is_ipv4),
        ("192.168.0.0/24", NetworkOrIP.is_ipv4_network),
        ("2001:db8::1", NetworkOrIP.is_ipv6),
        ("2001:db8::/64", NetworkOrIP.is_ipv6_network),
        ("2001:db8::/", NetworkOrIP.is_ipv6),  # valid address because validator removes suffix
        pytest.param(
            "192.168.0.0/33", None, marks=pytest.mark.xfail(raises=InputFailure, strict=True)
        ),
        pytest.param(
            "2001:db8::/129", None, marks=pytest.mark.xfail(raises=InputFailure, strict=True)
        ),
    ],
)
def test_network_or_ip_validate(inp: Any, expect_type_call: Callable[[NetworkOrIP], bool]) -> None:
    """Test the validation of network or IP address."""
    res = NetworkOrIP.validate(inp)
    # Ensure it's validated as the correct type
    assert expect_type_call(res)


@pytest.mark.parametrize(
    "inp, expect",
    [
        ("192.168.0.0/24", IPv4Network("192.168.0.0/24")),
        ("2001:db8::/64", IPv6Network("2001:db8::/64")),
    ],
)
def test_network_ip_network(inp: str, expect: IP_NetworkT) -> None:
    """Test usage of `Network.ip_network` and related properties."""
    network = Network(
        id=123,
        excluded_ranges=[],
        network=inp,
        description="testnet",
        vlan=123,
        dns_delegated=False,
        category="test",
        location="testnet",
        frozen=False,
        reserved=0,
        created_at=datetime.now(),
        updated_at=datetime.now(),
    )

    assert network.ip_network == expect
    assert network.broadcast_address == expect.broadcast_address
    assert network.network_address == expect.network_address
