from __future__ import annotations

import pytest
from inline_snapshot import snapshot
from pydantic import BaseModel, ValidationError

from mreg_cli.api.fields import MACAddressField, NameList
from mreg_cli.exceptions import InputFailure

MacAddresValidationFailure = pytest.mark.xfail(raises=InputFailure, strict=True)


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
        pytest.param("00:00:00:00:00:00:00", "", marks=MacAddresValidationFailure),
        pytest.param("00:00:00:00:00", "", marks=MacAddresValidationFailure),
        pytest.param("00:00:00:00:00:0", "", marks=MacAddresValidationFailure),
        pytest.param("00:00:00:00:00:0g", "", marks=MacAddresValidationFailure),
        pytest.param("00-00-00-00-00-00:00", "", marks=MacAddresValidationFailure),
        pytest.param("00-00-00-00-00", "", marks=MacAddresValidationFailure),
        pytest.param("00-00-00-00-00-0", "", marks=MacAddresValidationFailure),
        pytest.param("00-00-00-00-00-0g", "", marks=MacAddresValidationFailure),
        pytest.param("ab:cd:ef:12:34", "", marks=MacAddresValidationFailure),
        pytest.param("ab-cd-ef-12-34", "", marks=MacAddresValidationFailure),
        pytest.param("abcd.ef12.34", "", marks=MacAddresValidationFailure),
    ],
)
def test_mac_address_field(inp: str, expect: str) -> None:
    """Test the MAC address field."""
    res = MACAddressField.validate(inp)
    assert str(res) == expect


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

    Should log an error and skip the item."""
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
