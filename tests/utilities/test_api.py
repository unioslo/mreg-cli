from __future__ import annotations

from typing import Any

import pytest
from inline_snapshot import snapshot
from pytest_httpserver import HTTPServer
from werkzeug import Response

from mreg_cli.exceptions import MultipleEntitiesFound, ValidationError
from mreg_cli.utilities.api import _strip_none, get_list, get_list_unique  # type: ignore


@pytest.mark.parametrize(
    "inp,expect",
    [
        # Empty dict
        ({}, {}),
        # Mixed values
        ({"foo": "a", "bar": None}, {"foo": "a"}),
        # Multiple keys with None values
        ({"foo": None, "bar": None}, {}),
        # Nested dicts
        ({"foo": {"bar": {"baz": None}}}, {}),
        (
            {"foo": {"bar": {"baz": None}}, "qux": {}, "quux": ["a", "b", "c"]},
            {"quux": ["a", "b", "c"]},
        ),
    ],
)
def test_strip_none(inp: dict[str, Any], expect: dict[str, Any]) -> None:
    assert _strip_none(inp) == expect


def test_get_list_paginated(httpserver: HTTPServer) -> None:
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [{"foo": "bar"}],
            "count": 1,
            "next": None,
            "previous": None,
        }
    )
    resp = get_list("/foobar")
    assert resp == snapshot([{"foo": "bar"}])


def test_get_list_paginated_empty(httpserver: HTTPServer) -> None:
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [],
            "count": 0,
            "next": None,
            "previous": None,
        }
    )
    resp = get_list("/foobar")
    assert resp == snapshot([])


def test_get_list_paginated_multiple_pages(httpserver: HTTPServer) -> None:
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [{"foo": "bar"}],
            "count": 1,
            "next": "/foobar?page=2",
            "previous": None,
        }
    )
    httpserver.expect_oneshot_request("/foobar", query_string="page=2").respond_with_json(
        {
            "results": [{"baz": "qux"}],
            "count": 1,
            "next": None,
            "previous": "/foobar",
        }
    )
    resp = get_list("/foobar")
    assert resp == snapshot([{"foo": "bar"}, {"baz": "qux"}])


def test_get_list_paginated_multiple_pages_ok404(httpserver: HTTPServer) -> None:
    """Paginated response with 404 on next page is ignored when `ok404=True`."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [{"foo": "bar"}],
            "count": 1,
            "next": "/foobar?page=2",
            "previous": None,
        }
    )
    httpserver.expect_oneshot_request("/foobar", query_string="page=2").respond_with_response(
        Response(status=404)
    )
    assert get_list("/foobar", ok404=True) == snapshot([{"foo": "bar"}])


def test_get_list_paginated_multiple_pages_inconsistent_count(httpserver: HTTPServer) -> None:
    """Inconsistent count in paginated response is ignored."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [{"foo": "bar"}, {"baz": "qux"}],
            "count": 1,  # wrong count
            "next": "/foobar?page=2",
            "previous": None,
        }
    )
    httpserver.expect_oneshot_request("/foobar", query_string="page=2").respond_with_json(
        {
            "results": [{"quux": "spam"}],
            "count": 2,  # wrong count
            "next": None,
            "previous": "/foobar",
        }
    )
    resp = get_list("/foobar")
    assert resp == snapshot([{"foo": "bar"}, {"baz": "qux"}, {"quux": "spam"}])


@pytest.mark.parametrize(
    "results",
    [
        '"foo"',  # Not a list
        "42",  # Not a list
        '{"foo": "bar"}',  # Not a list
        "{'foo': 'bar'}",  # Invalid JSON + not a list
        "[{'foo': 'bar'}]",  # Invalid JSON
    ],
)
def test_get_list_paginated_invalid(httpserver: HTTPServer, results: Any) -> None:
    """Invalid JSON or non-array response is an error."""
    httpserver.expect_oneshot_request("/foobar").respond_with_data(
        f"""{{
            "results": {results},
            "count": 1,
            "next": None,
            "previous": None,
            }}"""
    )
    with pytest.raises(ValidationError) as exc_info:
        get_list("/foobar")
    assert "did not return valid paginated JSON" in exc_info.exconly()


def test_get_list_non_paginated(httpserver: HTTPServer) -> None:
    """Inconsistent count in paginated response is ignored."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        [
            "foo",
            "bar",
            {"baz": "qux"},
        ]
    )
    resp = get_list("/foobar")
    assert resp == snapshot(["foo", "bar", {"baz": "qux"}])


def test_get_list_non_paginated_empty(httpserver: HTTPServer) -> None:
    """Inconsistent count in paginated response is ignored."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json([])
    resp = get_list("/foobar")
    assert resp == snapshot([])


def test_get_list_non_paginated_non_array(httpserver: HTTPServer) -> None:
    """Non-paginated non-array response is an error."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "not": "an array",
        }
    )
    with pytest.raises(ValidationError) as exc_info:
        get_list("/foobar")
    assert "did not return a valid JSON" in exc_info.exconly()


def test_get_list_non_paginated_invalid_json(httpserver: HTTPServer) -> None:
    """Non-paginated response with invalid JSON is an error."""
    httpserver.expect_oneshot_request("/foobar").respond_with_data(
        "[{'key': 'value'}, 'foo',]",  # strings must be double quoted
        content_type="application/json",
    )
    with pytest.raises(ValidationError) as exc_info:
        get_list("/foobar")
    assert "did not return a valid JSON" in exc_info.exconly()


def test_get_list_unique_paginated(httpserver: HTTPServer) -> None:
    """Non-paginated response with invalid JSON is an error."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [{"foo": "bar"}],
            "count": 1,
            "next": None,
            "previous": None,
        }
    )
    resp = get_list_unique("/foobar", params={})
    assert resp == snapshot({"foo": "bar"})


def test_get_list_unique_paginated_too_many_results(httpserver: HTTPServer) -> None:
    """get_list_unique with multiple unique results is an error."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [{"foo": "bar"}],
            "count": 1,
            "next": "/foobar?page=2",
            "previous": None,
        }
    )
    httpserver.expect_oneshot_request("/foobar", query_string="page=2").respond_with_json(
        {
            "results": [{"baz": "qux"}],
            "count": 1,
            "next": None,
            "previous": "/foobar",
        }
    )
    with pytest.raises(MultipleEntitiesFound) as exc_info:
        get_list_unique("/foobar", params={})
    assert exc_info.exconly() == snapshot(
        "mreg_cli.exceptions.MultipleEntitiesFound: Expected a unique result, got 2 distinct results."
    )


def test_get_list_unique_paginated_duplicate_result_ok(httpserver: HTTPServer) -> None:
    """get_list_unique with _only_ duplicate results is ok."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [{"foo": "bar"}],
            "count": 1,
            "next": "/foobar?page=2",
            "previous": None,
        }
    )
    httpserver.expect_oneshot_request("/foobar", query_string="page=2").respond_with_json(
        {
            "results": [{"foo": "bar"}],
            "count": 1,
            "next": None,
            "previous": "/foobar",
        }
    )
    resp = get_list_unique("/foobar", params={})
    assert resp == snapshot({"foo": "bar"})


def test_get_list_unique_paginated_no_result(httpserver: HTTPServer) -> None:
    """No result is None."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json(
        {
            "results": [],
            "count": 0,
            "next": None,
            "previous": None,
        }
    )
    resp = get_list_unique("/foobar", params={})
    assert resp is None


def test_get_list_unique_non_paginated_no_result(httpserver: HTTPServer) -> None:
    """No result is None."""
    httpserver.expect_oneshot_request("/foobar").respond_with_json([])
    resp = get_list_unique("/foobar", params={})
    assert resp is None
