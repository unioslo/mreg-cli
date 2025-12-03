import pytest

from mreg_cli.commands.host_submodules.core import Override
from mreg_cli.exceptions import InputFailure


def test_override_members_are_strings() -> None:
    """Ensure Override values are evaluated as strings, and can be compared with strings."""
    for member in Override:
        assert isinstance(member, str)
        assert isinstance(member.value, str)
        assert member == member.value


def test_override_values() -> None:
    """Ensure Override values are evaluated as strings, and can be compared with strings."""
    values = Override.values()
    for value in values:
        assert isinstance(value, str)

    # String literals, members and values are all comparable
    assert "cname" in values
    assert Override.CNAME in values
    assert Override.CNAME.value in values


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
        with pytest.raises(InputFailure):
            Override.from_string(invalid)
