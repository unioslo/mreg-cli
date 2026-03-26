from __future__ import annotations

import datetime
from ipaddress import IPv4Address, IPv6Address

import pytest
from inline_snapshot import snapshot
from mreg_api.models import NAPTR, PTR_override, Srv

from mreg_cli.commands.host_submodules.core import Override, get_record_identifier
from mreg_cli.exceptions import InputFailure


def test_override_members_are_strings() -> None:
    """Ensure Override values are evaluated as strings, and can be compared with strings."""
    for member in Override:
        assert isinstance(member, str)
        assert isinstance(member.value, str)
        assert member == member.value


def test_override_as_list() -> None:
    """Test comparison when turned into a list."""
    members = list(Override)
    # String literals, members and values are all comparable to list items
    assert "cname" in members
    assert Override.CNAME in members
    assert Override.CNAME.value in members


def test_override_values() -> None:
    """Test that values from Override.values() are strings and valid Override members."""
    for val in Override.values():
        assert isinstance(val, str)
        assert Override(val) == val  # str comparison
        assert Override(val) == Override.from_string(val)  # alternate constructor


def test_override_values_str() -> None:
    """Snapshot test for Override.values_str()."""
    assert Override.values_str() == snapshot("'cname', 'ipaddress', 'mx', 'srv', 'ptr', 'naptr'")


def test_override_from_string() -> None:
    """Ensure Override can be created from strings."""
    for override in list(Override):
        o = Override.from_string(override.value)
        assert o == override

        # Case insensitive
        o_upper = Override.from_string(override.value.upper())
        assert o_upper == override
        o_lower = Override.from_string(override.value.lower())
        assert o_lower == override

        # Whitespace is stripped
        o_whitespace = Override.from_string(f"  {override.value}  ")
        assert o_whitespace == override

    # Invalid values raise InputFailure
    invalid_strings = ["invalid", "CNAME_", "ip", "", " "]
    for invalid in invalid_strings:
        with pytest.raises(InputFailure) as exc_info:
            Override.from_string(invalid)
        assert "Invalid override" in str(exc_info.value)


@pytest.mark.parametrize(
    "record,expected",
    [
        (
            NAPTR(
                host=123,
                created_at=datetime.datetime(2026, 1, 1),
                updated_at=datetime.datetime(2026, 1, 1),
                id=1,
                preference=1,
                order=1,
                replacement="naptr.example.com",
            ),
            "naptr.example.com",
        ),
        pytest.param(
            PTR_override(
                host=123,
                created_at=datetime.datetime(2026, 1, 1),
                updated_at=datetime.datetime(2026, 1, 1),
                id=1,
                ipaddress=IPv4Address("192.168.0.1"),
            ),
            "192.168.0.1",
            id="PTR_override (IPv4)",
        ),
        pytest.param(
            PTR_override(
                host=123,
                created_at=datetime.datetime(2026, 1, 1),
                updated_at=datetime.datetime(2026, 1, 1),
                id=1,
                ipaddress=IPv6Address("2001:db8::1"),
            ),
            "2001:db8::1",
            id="PTR_override (IPv6)",
        ),
        pytest.param(
            Srv(
                zone=1,
                host=123,
                created_at=datetime.datetime(2026, 1, 1),
                updated_at=datetime.datetime(2026, 1, 1),
                id=1,
                name="srv.example.com",
                priority=1,
                weight=1,
                port=80,
                ttl=3600,
            ),
            "srv.example.com",
        ),
    ],
)
def test_get_record_identifier(record: NAPTR | PTR_override | Srv, expected: str) -> None:
    """Test get_record_identifier with different record types."""
    assert get_record_identifier(record) == expected
