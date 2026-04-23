import argparse
import datetime
from mreg_api.models import NAPTR
from mreg_cli.commands.host_submodules.rr import naptrs_from_args
import pytest

_created_at = datetime.datetime(2024, 1, 1, 0, 0, 0)
_updated_at = datetime.datetime(2025, 1, 1, 0, 0, 0)

# Overlap matrix (field -> ids sharing same value):
#   host:        123=[1,2,3]  456=[4,5]  789=[6]
#   preference:  10=[1,2,3]   20=[4,5]   30=[6]
#   order:       20=[1,2,5]   10=[4,6]   30=[3]
#   flag:        "U"=[1,2,4]  "S"=[3,5]  None=[6]
#   service:     "SIP+D2U"=[1,2,5]  "E2U+SIP"=[3,4]  None=[6]
#   regex:       ""=[1,3,4]   "!^.*$!..."=[2,5]  None=[6]
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
    flag=None,
    service=None,
    regex=None,
    replacement="naptr6.example.com",
    created_at=_created_at,
    updated_at=_updated_at,
)

naptrs = [_naptr1, _naptr2, _naptr3, _naptr4, _naptr5, _naptr6]


@pytest.mark.parametrize(
    "inp,expected",
    [
        (argparse.Namespace(preference=10), [_naptr1, _naptr2, _naptr3]),
        (argparse.Namespace(order=20), [_naptr1, _naptr2, _naptr5]),
        (argparse.Namespace(flag="U"), [_naptr1, _naptr2, _naptr4]),
        (argparse.Namespace(service="SIP+D2U"), [_naptr1, _naptr2, _naptr5]),
        (argparse.Namespace(regex=""), [_naptr1, _naptr3, _naptr4]),
        (argparse.Namespace(preference=10, order=20), [_naptr1, _naptr2]),
        (argparse.Namespace(flag="U", service="E2U+SIP"), [_naptr4]),
        (argparse.Namespace(regex="!^.*$!sip:info@example.com!"), [_naptr2, _naptr5]),
    ],
)
def test_naptrs_from_args(inp: argparse.Namespace, expected: list[NAPTR]) -> None:
    assert naptrs_from_args(naptrs, inp) == expected
