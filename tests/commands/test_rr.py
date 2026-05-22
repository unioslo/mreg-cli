from __future__ import annotations

import datetime

import pytest
from mreg_api.models import NAPTR

from mreg_cli.commands.host_submodules.rr import filter_naptrs

_created_at = datetime.datetime(2024, 1, 1, 0, 0, 0)
_updated_at = datetime.datetime(2025, 1, 1, 0, 0, 0)

# Overlap matrix (field -> ids sharing same value):
#   host:        123=[1,2,3]  456=[4,5]  789=[6]  999=[7,8,9,10]
#   preference:  10=[1,2,3]   20=[4,5]   30=[6]   40=[7,8,9,10]
#   order:       20=[1,2,5]   10=[4,6]   30=[3]   15=[7,8,9,10]
#   flag:        "U"=[1,2,4,7,9,10]  "S"=[3,5,8]  ""=[6]
#   service:     "SIP+D2U"=[1,2,5]  "E2U+SIP"=[3,4]  ""=[6]  "X"=[7,8,10]  "Y"=[9]
#   regex:       ""=[1,3,4,6]  "!^.*$!..."=[2,5]  "r1"=[7,8,9]  "r2"=[10]
#   replacement: "multi.example.com"=[7,8,9,10]
_naptr1 = NAPTR(
    id=1,
    host=123,
    preference=10,
    order=20,
    flag="U",
    service="SIP+D2U",
    regex="",
    replacement="naptr1.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr2 = NAPTR(
    id=2,
    host=123,
    preference=10,
    order=20,
    flag="U",
    service="SIP+D2U",
    regex="!^.*$!sip:info@example.com!",
    replacement="naptr2.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr3 = NAPTR(
    id=3,
    host=123,
    preference=10,
    order=30,
    flag="S",
    service="E2U+SIP",
    regex="",
    replacement="naptr3.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr4 = NAPTR(
    id=4,
    host=456,
    preference=20,
    order=10,
    flag="U",
    service="E2U+SIP",
    regex="",
    replacement="naptr4.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr5 = NAPTR(
    id=5,
    host=456,
    preference=20,
    order=20,
    flag="S",
    service="SIP+D2U",
    regex="!^.*$!sip:info@example.com!",
    replacement="naptr5.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr6 = NAPTR(
    id=6,
    host=789,
    preference=30,
    order=10,
    flag="",
    service="",
    regex="",
    replacement="naptr6.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)

# NAPTRs 7-10 share preference/order/replacement to exercise multi-match via optional fields.
# flag varies: 7,9,10="U"  8="S"
# service varies: 7,8,10="X"  9="Y"
# regex varies: 7,8,9="r1"  10="r2"
_naptr7 = NAPTR(
    id=7,
    host=999,
    preference=40,
    order=15,
    flag="U",
    service="X",
    regex="r1",
    replacement="multi.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr8 = NAPTR(
    id=8,
    host=999,
    preference=40,
    order=15,
    flag="S",
    service="X",
    regex="r1",
    replacement="multi.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr9 = NAPTR(
    id=9,
    host=999,
    preference=40,
    order=15,
    flag="U",
    service="Y",
    regex="r1",
    replacement="multi.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)
_naptr10 = NAPTR(
    id=10,
    host=999,
    preference=40,
    order=15,
    flag="U",
    service="X",
    regex="r2",
    replacement="multi.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)

naptrs = [
    _naptr1,
    _naptr2,
    _naptr3,
    _naptr4,
    _naptr5,
    _naptr6,
    _naptr7,
    _naptr8,
    _naptr9,
    _naptr10,
]


@pytest.mark.parametrize(
    "preference,order,flag,service,regex,replacement,expected",
    [
        (10, 20, "U", "SIP+D2U", "", "naptr1.example.com", [_naptr1]),
        (10, 20, "U", "SIP+D2U", "!^.*$!sip:info@example.com!", "naptr2.example.com", [_naptr2]),
        (10, 30, "S", "E2U+SIP", "", "naptr3.example.com", [_naptr3]),
        (20, 10, "U", "E2U+SIP", "", "naptr4.example.com", [_naptr4]),
        (20, 20, "S", "SIP+D2U", "!^.*$!sip:info@example.com!", "naptr5.example.com", [_naptr5]),
        (30, 10, "", "", "", "naptr6.example.com", [_naptr6]),
        (40, 15, "U", "X", "r1", "multi.example.com", [_naptr7]),
        (10, 20, "U", "SIP+D2U", "", "naptr-nonexistent.example.com", []),
        (99, 20, "U", "SIP+D2U", "", "naptr1.example.com", []),
    ],
)
def test_filter_naptrs_single(
    preference: int,
    order: int,
    flag: str | None,
    service: str | None,
    regex: str | None,
    replacement: str,
    expected: list[NAPTR],
) -> None:
    assert filter_naptrs(naptrs, preference, order, flag, service, regex, replacement) == expected


@pytest.mark.parametrize(
    "preference,order,flag,service,regex,replacement,expected",
    [
        (40, 15, None, "X", "r1", "multi.example.com", [_naptr7, _naptr8]),
        (40, 15, "U", None, "r1", "multi.example.com", [_naptr7, _naptr9]),
        (40, 15, "U", "X", None, "multi.example.com", [_naptr7, _naptr10]),
        (40, 15, None, None, None, "multi.example.com", [_naptr7, _naptr8, _naptr9, _naptr10]),
    ],
)
def test_filter_naptrs_multi(
    preference: int,
    order: int,
    flag: str | None,
    service: str | None,
    regex: str | None,
    replacement: str,
    expected: list[NAPTR],
) -> None:
    assert filter_naptrs(naptrs, preference, order, flag, service, regex, replacement) == expected
