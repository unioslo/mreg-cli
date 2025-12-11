from __future__ import annotations

import pytest
from inline_snapshot import snapshot

from mreg_cli.commands.host_submodules.core import Override
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
