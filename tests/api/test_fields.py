from __future__ import annotations

import pytest

from mreg_cli.api.fields import MACAddressField


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
    ],
)
def test_mac_address_field(inp: str, expect: str) -> None:
    """Test the MAC address field."""
    res = MACAddressField.validate_mac(inp)
    assert str(res) == expect
