from mreg_cli.commands.host_submodules.core import Override


def test_override_members_are_strings() -> None:
    """Ensure values are evaluated as strings, and can be compared with strings."""
    for member in Override:
        assert isinstance(member, str)
        assert isinstance(member.value, str)
        assert member == member.value


def test_override_values() -> None:
    """Ensure values are evaluated as strings, and can be compared with strings."""
    values = Override.values()
    for value in values:
        assert isinstance(value, str)

    # String literals, members and values are all comparable
    assert "cname" in values
    assert Override.CNAME in values
    assert Override.CNAME.value in values
