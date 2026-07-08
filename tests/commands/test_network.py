from __future__ import annotations

import datetime
from ipaddress import IPv4Address

import pytest
from mreg_api.models import Community, Host, HostCommunity, IPAddress
from mreg_api.models.fields import HostName

from mreg_cli.commands.network import _get_host_community_and_ip_to_remove

DT = datetime.datetime(2026, 1, 1)


def make_community(id_: int, name: str) -> Community:
    """Build a Community for testing."""
    return Community(
        id=id_,
        name=name,
        description="",
        network=1,
        created_at=DT,
        updated_at=DT,
    )


def make_ip(id_: int, ipaddress: str, host: int = 123) -> IPAddress:
    """Build an IPAddress for testing."""
    return IPAddress(
        id=id_,
        ipaddress=IPv4Address(ipaddress),
        host=host,
        created_at=DT,
        updated_at=DT,
    )


def make_host(ipaddresses: list[IPAddress], communities: list[HostCommunity]) -> Host:
    """Build a Host for testing."""
    return Host(
        id=123,
        name=HostName("testhost.example.com"),
        comment="",
        ipaddresses=ipaddresses,
        communities=communities,
        created_at=DT,
        updated_at=DT,
    )


# Shared fixtures for the parametrized cases
IP1 = make_ip(1, "10.0.0.1")
IP2 = make_ip(2, "10.0.0.2")
RED = make_community(1, "red")
BLUE = make_community(2, "blue")


@pytest.mark.parametrize(
    "communities,ipaddresses,community_name,ip,expected_ip_id",
    [
        # Single association, no IP arg -> OK, returns that association
        pytest.param(
            [HostCommunity(ipaddress=1, community=RED)],
            [IP1, IP2],
            "red",
            None,
            1,
            id="single-assoc-no-ip",
        ),
        # Single association, correct IP arg -> OK
        pytest.param(
            [HostCommunity(ipaddress=1, community=RED)],
            [IP1, IP2],
            "red",
            "10.0.0.1",
            1,
            id="single-assoc-with-ip",
        ),
        # Community name match is case-insensitive
        pytest.param(
            [HostCommunity(ipaddress=1, community=RED)],
            [IP1, IP2],
            "RED",
            None,
            1,
            id="single-assoc-casefold",
        ),
        # Multiple associations, IP arg disambiguates -> OK
        pytest.param(
            [
                HostCommunity(ipaddress=1, community=RED),
                HostCommunity(ipaddress=2, community=RED),
            ],
            [IP1, IP2],
            "red",
            "10.0.0.2",
            2,
            id="multi-assoc-with-ip",
        ),
        # Zero associations (host not in community) -> EntityNotFound
        pytest.param(
            [HostCommunity(ipaddress=1, community=BLUE)],
            [IP1, IP2],
            "red",
            None,
            None,
            id="zero-assoc",
            marks=pytest.mark.xfail(strict=True, reason="EntityNotFound: not in community"),
        ),
        # Multiple associations, no IP arg -> InputFailure (ambiguous)
        pytest.param(
            [
                HostCommunity(ipaddress=1, community=RED),
                HostCommunity(ipaddress=2, community=RED),
            ],
            [IP1, IP2],
            "red",
            None,
            None,
            id="multi-assoc-no-ip",
            marks=pytest.mark.xfail(strict=True, reason="InputFailure: must specify IP"),
        ),
        # Multiple associations, IP arg not on host at all -> EntityNotFound (from _get_host_ip)
        pytest.param(
            [
                HostCommunity(ipaddress=1, community=RED),
                HostCommunity(ipaddress=2, community=RED),
            ],
            [IP1, IP2],
            "red",
            "10.0.0.99",
            None,
            id="multi-assoc-ip-not-on-host",
            marks=pytest.mark.xfail(strict=True, reason="EntityNotFound: IP not on host"),
        ),
        # Multiple associations, IP arg on host but not in this community -> EntityNotFound
        pytest.param(
            [
                HostCommunity(ipaddress=1, community=RED),
            ],
            [IP1, IP2],
            "red",
            "10.0.0.2",
            None,
            id="ip-on-host-not-in-community",
            marks=pytest.mark.xfail(strict=True, reason="EntityNotFound: IP not in community"),
        ),
    ],
)
def test_get_host_community_and_ip_to_remove(
    communities: list[HostCommunity],
    ipaddresses: list[IPAddress],
    community_name: str,
    ip: str | None,
    expected_ip_id: int | None,
) -> None:
    host = make_host(ipaddresses=ipaddresses, communities=communities)

    community, ipaddr = _get_host_community_and_ip_to_remove(host, community_name, ip)

    assert community.name.casefold() == community_name.casefold()
    assert ipaddr.id == expected_ip_id
