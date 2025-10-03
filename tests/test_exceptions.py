from __future__ import annotations

import pytest
from inline_snapshot import snapshot
from pydantic import ValidationError as PydanticValidationError
from pytest_httpserver import HTTPServer

from mreg_cli.api.models import Host
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import ValidationError
from mreg_cli.utilities.api import get


def test_validation_error_get_host(httpserver: HTTPServer) -> None:
    """Test a validation error stemming from a GET request."""
    MregCliConfig().url = httpserver.url_for("/")

    httpserver.expect_oneshot_request("/hosts/foobar").respond_with_json(
        {
            "created_at": "2022-06-16T09:15:40.775601+02:00",
            "updated_at": "2024-01-26T10:23:06.631486+01:00",
            "id": 76036,
            "name": "_.--host123_example.com",  # invalid name
            "ipaddresses": [
                {
                    "host": 76036,
                    "created_at": "2022-06-16T09:47:43.761478+02:00",
                    "updated_at": "2022-06-16T12:20:40.722808+02:00",
                    "id": 78492,
                    "macaddress": "e4:54:e8:80:73:73",
                    "ipaddress": "192.168.0.1",
                }
            ],
            "cnames": [],
            "mxs": [],
            "txts": [],
            "ptr_overrides": [],
            "hinfo": None,
            "loc": None,
            "bacnetid": None,
            "contact": "user@example.com",
            "ttl": None,
            "comment": "",
            "zone": 5,
        }
    )
    resp = get("/hosts/foobar")
    with pytest.raises(PydanticValidationError) as exc_info:
        Host.model_validate_json(resp.text)

    assert exc_info.value.error_count() == snapshot(1)
    assert [repr(err) for err in exc_info.value.errors(include_url=False)] == snapshot(
        [
            "{'type': 'value_error', 'loc': ('name',), 'msg': 'Value error, Invalid input for hostname: _.--host123_example.com', 'input': '_.--host123_example.com', 'ctx': {'error': InputFailure('Invalid input for hostname: _.--host123_example.com')}}"
        ]
    )

    validationerror = ValidationError.from_pydantic(exc_info.value)

    # port-number is non-determinstic, so we need to replace that before comparing
    err = validationerror.args[0].replace(f":{httpserver.port}", ":12345")
    assert err == snapshot(
        """\
Failed to validate Host response from GET http://localhost:12345/hosts/foobar
  Input: _.--host123_example.com
  Errors:
    Field: name
    Reason: Value error, Invalid input for hostname: _.--host123_example.com\
"""
    )


def test_validation_error_no_request(caplog, capsys) -> None:
    """Test a validation error that did not originate from an API request."""
    with pytest.raises(PydanticValidationError) as exc_info:
        Host.model_validate({"name": "test"})  # Missing required fields

    assert exc_info.value.error_count() == snapshot(6)
    assert [repr(err) for err in exc_info.value.errors(include_url=False)] == snapshot(
        [
            "{'type': 'missing', 'loc': ('created_at',), 'msg': 'Field required', 'input': {'name': 'test'}}",
            "{'type': 'missing', 'loc': ('updated_at',), 'msg': 'Field required', 'input': {'name': 'test'}}",
            "{'type': 'missing', 'loc': ('id',), 'msg': 'Field required', 'input': {'name': 'test'}}",
            "{'type': 'missing', 'loc': ('ipaddresses',), 'msg': 'Field required', 'input': {'name': 'test'}}",
            "{'type': 'missing', 'loc': ('contact',), 'msg': 'Field required', 'input': {'name': 'test'}}",
            "{'type': 'missing', 'loc': ('comment',), 'msg': 'Field required', 'input': {'name': 'test'}}",
        ]
    )

    validationerror = ValidationError.from_pydantic(exc_info.value)
    assert validationerror.args[0] == snapshot(
        """\
Failed to validate Host
  Input: {'name': 'test'}
  Errors:
    Field: created_at
    Reason: Field required

    Field: updated_at
    Reason: Field required

    Field: id
    Reason: Field required

    Field: ipaddresses
    Reason: Field required

    Field: contact
    Reason: Field required

    Field: comment
    Reason: Field required\
"""
    )

    # Call method and check output
    validationerror.print_and_log()

    assert caplog.record_tuples == snapshot(
        [
            (
                "mreg_cli.exceptions",
                40,
                """\
Failed to validate Host
  Input: {'name': 'test'}
  Errors:
    Field: created_at
    Reason: Field required

    Field: updated_at
    Reason: Field required

    Field: id
    Reason: Field required

    Field: ipaddresses
    Reason: Field required

    Field: contact
    Reason: Field required

    Field: comment
    Reason: Field required\
""",
            )
        ]
    )

    out, err = capsys.readouterr()
    assert out == snapshot(
        """\
ERROR: Failed to validate Host\r
  Input: {'name': 'test'}\r
  Errors:\r
    Field: created_at\r
    Reason: Field required\r
\r
    Field: updated_at\r
    Reason: Field required\r
\r
    Field: id\r
    Reason: Field required\r
\r
    Field: ipaddresses\r
    Reason: Field required\r
\r
    Field: contact\r
    Reason: Field required\r
\r
    Field: comment\r
    Reason: Field required\r
"""
    )
