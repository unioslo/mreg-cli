from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Any, Callable

import pytest

from mreg_cli.api.models import IPAddress, IPNetMode, Network, NetworkOrIP
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


@pytest.mark.parametrize(
    "inp",
    [
        "192.168.0.1",
        "0.0.0.0",
        "10.0.0.1",
    ],
)
def test_network_dummy_network_from_ip_v4(inp: str) -> None:
    """Test creating a dummy network from an IPv4 address."""
    _test_network_dummy_network(IPv4Address(inp), expected_version=4)


@pytest.mark.parametrize(
    "inp",
    [
        "2001:db8::1",
        "::1",
        "fe80::1",
    ],
)
def test_network_dummy_network_from_ip_v6(inp: str) -> None:
    """Test creating a dummy network from an IPv6 address."""
    _test_network_dummy_network(IPv6Address(inp), expected_version=6)


def _test_network_dummy_network(inp: IPv4Address | IPv6Address, expected_version: int) -> None:
    """Helper function to test creating a dummy network from an IP address."""  # noqa: D401
    ip = _get_mreg_ipaddress(inp)
    network = Network.dummy_network_from_ip(ip)
    assert isinstance(network, Network)
    assert network.ip_network.version == expected_version

    # Ensure all dummy networks for the given IP type are hashed
    # the same and equal to each other, so that all dummy networks
    # of a given IP version are considered the same.
    network2 = Network.dummy_network_from_ip(ip)
    assert network == network2
    assert hash(network) == hash(network2)


def _get_mreg_ipaddress(ip: IPv4Address | IPv6Address) -> IPAddress:
    """Construct an mreg IPAddress object from an IP."""
    return IPAddress(
        id=0,
        host=0,
        created_at=datetime.now(),
        updated_at=datetime.now(),
        ipaddress=ip,
        # no mac
    )


def test_network_dummy_network_from_ip_identity() -> None:
    """Test hashing of dummy networks from identical and differenet IP versions."""
    ipv4_1 = _get_mreg_ipaddress(IPv4Address("192.168.0.1"))
    ipv4_2 = _get_mreg_ipaddress(IPv4Address("192.168.0.2"))
    ipv6_1 = _get_mreg_ipaddress(IPv6Address("2001:db8::1"))
    ipv6_2 = _get_mreg_ipaddress(IPv6Address("2001:db8::2"))

    network_v4_1 = Network.dummy_network_from_ip(ipv4_1)
    network_v4_2 = Network.dummy_network_from_ip(ipv4_2)
    network_v6_1 = Network.dummy_network_from_ip(ipv6_1)
    network_v6_2 = Network.dummy_network_from_ip(ipv6_2)

    assert network_v4_1 == network_v4_2
    assert hash(network_v4_1) == hash(network_v4_2)

    assert network_v6_1 == network_v6_2
    assert hash(network_v6_1) == hash(network_v6_2)

    assert network_v4_1 != network_v6_1
    assert hash(network_v4_1) != hash(network_v6_1)

    # Usage in dicts
    d = {network_v4_1: "foo", network_v6_1: "bar"}
    # Use the other two network objects to access the existing entries
    assert d[network_v4_2] == "foo"
    assert d[network_v6_2] == "bar"
