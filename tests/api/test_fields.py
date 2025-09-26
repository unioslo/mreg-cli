from __future__ import annotations

import pytest
from inline_snapshot import snapshot
from pydantic import BaseModel, ValidationError

from mreg_cli.api.fields import HostName, MacAddress, NameList
from mreg_cli.exceptions import InputFailure


@pytest.mark.parametrize(
    "hostname",
    [
        "example.com",
        "sub.domain.com",
        "localhost",
        "localhost.",
        "my-host-123.com",
        "123-start-with-number.com",
        "singlelabel",
        "sub.sub2.sub3.domain.com",
        "_underscore.hostname.com",
        "host-name-with-dashes.com",
        "multi.label.domain.co.uk",
        "*.example.com",
        "*.sub.domain.com",
        "*.localhost",
        "*.my-host-123.com",
        "*.123-start-with-number.com",
        "*.singlelabel",
        "*.sub.sub2.sub3.domain.com",
        "*.underscore.hostname.com",
        "*.host-name-with-dashes.com",
        "*.multi.label.domain.co.uk",
    ],
)
def test_valid_hostname(hostname: str) -> None:
    res = HostName.parse_or_raise(hostname)
    assert res

    # Narrow and broad type when validated directly
    assert isinstance(res, HostName)
    assert isinstance(res, str)

    # When used as a Pydantic field type, the field validates to str:
    class TestModel(BaseModel):
        name: HostName

    m = TestModel(name=hostname)
    assert m.name == res  # Identical value to standalone validation
    assert isinstance(m.name, str)
    assert not isinstance(m.name, HostName)  # Core schema coerces this to str
    assert type(m.name) != type(res)  # Different types


@pytest.mark.parametrize(
    "hostname",
    [
        "-example.com",
        "sub..domain.com",
        ".singlelabel",
        "multi..label.domain.co.uk",
        "*.sub.-domain.com",
        "localhost*",
        "host name with spaces.com",
        "example.com/net",
        "*.sub..domain.com",
        "host>name.com",
        "example.com#section",
        "123&456.com",
        # TODO: Make these invalid names fail validation:
        pytest.param(
            "example-.com",
            marks=pytest.mark.xfail(
                reason="ends with '-'",
                strict=True,
            ),
        ),
        pytest.param(
            "*.example-.com",
            marks=pytest.mark.xfail(
                reason="ends with '-'",
                strict=True,
            ),
        ),
        pytest.param(
            "host--name-with-dashes.com",
            marks=pytest.mark.xfail(
                reason="double '-'",
                strict=True,
            ),
        ),
        pytest.param(
            "_underscore_.hostname.com",
            marks=pytest.mark.xfail(
                reason="Ends with '_'",
                strict=True,
            ),
        ),
        pytest.param(
            "my_host_123.com",
            marks=pytest.mark.xfail(
                reason="Underscores between words",
                strict=True,
            ),
        ),
        pytest.param(
            "123.start-with-number.com",
            marks=pytest.mark.xfail(
                reason="Starts with number",
                strict=True,
            ),
        ),
    ],
)
def test_invalid_hostname(hostname: str) -> None:
    with pytest.raises(InputFailure):
        HostName.parse_or_raise(hostname)

    assert HostName.parse(hostname) is None


MacAddressValidationFailure = pytest.mark.xfail(raises=InputFailure, strict=True)


@pytest.mark.parametrize(
    "inp, expect",
    [
        # 6-part colon-separated MAC addresses
        ("00:00:00:00:00:00", "00:00:00:00:00:00"),
        ("FF:FF:FF:FF:FF:FF", "ff:ff:ff:ff:ff:ff"),
        ("A1:B2:C3:D4:E5:F6", "a1:b2:c3:d4:e5:f6"),
        ("a1:b2:c3:d4:e5:f6", "a1:b2:c3:d4:e5:f6"),
        ("Ab:cD:eF:01:23:45", "ab:cd:ef:01:23:45"),
        # 6-part hyphen-separated MAC addresses
        ("00-00-00-00-00-00", "00:00:00:00:00:00"),
        ("FF-FF-FF-FF-FF-FF", "ff:ff:ff:ff:ff:ff"),
        ("A1-B2-C3-D4-E5-F6", "a1:b2:c3:d4:e5:f6"),
        ("a1-b2-c3-d4-e5-f6", "a1:b2:c3:d4:e5:f6"),
        ("Ab-cD-eF-01-23-45", "ab:cd:ef:01:23:45"),
        # 3-part dot-separated MAC addresses
        ("0000.0000.0000", "00:00:00:00:00:00"),
        ("FFFF.FFFF.FFFF", "ff:ff:ff:ff:ff:ff"),
        ("A1B2.C3D4.E5F6", "a1:b2:c3:d4:e5:f6"),
        ("a1b2.c3d4.e5f6", "a1:b2:c3:d4:e5:f6"),
        ("Ab12.cD34.eF56", "ab:12:cd:34:ef:56"),
        # Invalid mac addresses
        pytest.param("00:00:00:00:00:00:00", "", marks=MacAddressValidationFailure),
        pytest.param("00:00:00:00:00", "", marks=MacAddressValidationFailure),
        pytest.param("00:00:00:00:00:0", "", marks=MacAddressValidationFailure),
        pytest.param("00:00:00:00:00:0g", "", marks=MacAddressValidationFailure),
        pytest.param("00-00-00-00-00-00:00", "", marks=MacAddressValidationFailure),
        pytest.param("00-00-00-00-00", "", marks=MacAddressValidationFailure),
        pytest.param("00-00-00-00-00-0", "", marks=MacAddressValidationFailure),
        pytest.param("00-00-00-00-00-0g", "", marks=MacAddressValidationFailure),
        pytest.param("ab:cd:ef:12:34", "", marks=MacAddressValidationFailure),
        pytest.param("ab-cd-ef-12-34", "", marks=MacAddressValidationFailure),
        pytest.param("abcd.ef12.34", "", marks=MacAddressValidationFailure),
    ],
)
def test_mac_address_type(inp: str, expect: str) -> None:
    """Test the MAC address field."""
    res = MacAddress.parse_or_raise(inp)
    assert str(res) == expect
    # Narrow and broad type
    assert isinstance(res, MacAddress)
    assert isinstance(res, str)

    # When used as a Pydantic field type, the field validates to str
    class TestModel(BaseModel):
        mac: MacAddress

    m = TestModel(mac=inp)
    assert m.mac == expect
    assert isinstance(m.mac, str)
    assert not isinstance(m.mac, MacAddress)  # Core schema coerces this to str


def test_name_list_basic():
    """Test NameList field with basic input."""
    inp = {
        "hosts": [
            {"name": "test1", "value": 1},
            {"name": "test2"},
            {"name": "test3", "value": 3},
        ]
    }

    class TestModel(BaseModel):
        hosts: NameList

    m = TestModel.model_validate(inp)

    assert m.model_dump(mode="json") == snapshot({"hosts": ["test1", "test2", "test3"]})


def test_name_list_with_invalid_item(caplog: pytest.LogCaptureFixture):
    """Test NameList field with an item without a name.

    Should log an error and skip the item.
    """
    inp = {
        "hosts": [
            {"name": "test1", "value": 1},
            {"value": 2},
            {"name": "test3", "value": 3},
        ]
    }

    class TestModel(BaseModel):
        hosts: NameList

    m = TestModel.model_validate(inp)

    assert m.model_dump(mode="json") == snapshot({"hosts": ["test1", "test3"]})

    assert caplog.record_tuples == snapshot(
        [("mreg_cli.api.fields", 40, "No 'name' key in {'value': 2}")]
    )


def test_name_list_invalid_type():
    """Test NameList field with the wrong type (dict instead of list of dicts)."""
    # hosts is not a list
    inp = {"hosts": {"name": "test1", "value": 1}}

    class TestModel(BaseModel):
        hosts: NameList

    with pytest.raises(ValidationError) as exc_info:
        TestModel.model_validate(inp)

    assert exc_info.value.errors(include_url=False) == snapshot(
        [
            {
                "type": "list_type",
                "loc": ("hosts",),
                "msg": "Input should be a valid list",
                "input": {"name": "test1", "value": 1},
            }
        ]
    )


def test_name_list_with_list() -> None:
    """Test NameList field with a list of strings. Should return the same list."""
    inp = {"hosts": ["test1", "test2", "test3"]}

    class TestModel(BaseModel):
        hosts: NameList

    m = TestModel.model_validate(inp)

    assert m.model_dump(mode="json") == snapshot({"hosts": ["test1", "test2", "test3"]})


def test_name_list_with_empty_name() -> None:
    """Test NameList field with a list of strings, where one name is an empty string."""
    inp = {"hosts": ["test1", "test2", "", "test3"]}

    class TestModel(BaseModel):
        hosts: NameList

    m = TestModel.model_validate(inp)

    # NOTE: this is a special case where the empty string is removed,
    # just like with the list of dictionaries. Whether or not this is
    # desirable is up for debate.
    # This test ensures that any change to that behavior is caught.
    assert m.model_dump(mode="json") == snapshot({"hosts": ["test1", "test2", "test3"]})
