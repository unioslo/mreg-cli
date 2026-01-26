from __future__ import annotations

import pytest
from inline_snapshot import snapshot
from mreg_api.models import Host
from pydantic import ValidationError as PydanticValidationError

from mreg_cli.exceptions import handle_exception


def test_handle_exception(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test handling of Pydantic ValidationError."""
    with pytest.raises(PydanticValidationError) as exc_info:
        Host.model_validate({"name": "test"})  # Missing required fields

    # Call function and check output
    handle_exception(exc_info.value)

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
    Field: comment\r
    Reason: Field required\r
"""
    )
    assert err == ""
