from __future__ import annotations

import pytest

from mreg_cli.api.fields import MACAddressField
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
