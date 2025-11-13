"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

from __future__ import annotations

import logging
import os
import re
import sys
from contextvars import ContextVar
from functools import wraps
from typing import Any, Callable, Literal, NoReturn, ParamSpec, TypeVar, get_origin, overload
from urllib.parse import urljoin
from uuid import uuid4

import requests
from prompt_toolkit import prompt
from pydantic import BaseModel, TypeAdapter, field_validator
from requests import Response

from mreg_cli.__about__ import __version__
from mreg_cli.api.errors import parse_mreg_error
from mreg_cli.cache import get_cache
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import (
    APIError,
    CliError,
    LoginFailedError,
    MultipleEntitiesFound,
    TooManyResults,
    ValidationError,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.tokenfile import TokenFile
from mreg_cli.types import Json, JsonMapping, QueryParams, get_type_adapter

session = requests.Session()
session.headers.update({"User-Agent": f"mreg-cli-{__version__}"})

logger = logging.getLogger(__name__)


T = TypeVar("T")

JsonMappingValidator = TypeAdapter(JsonMapping)

# Thread-local context variables for storing the last request URL and method.
last_request_url: ContextVar[str | None] = ContextVar("last_request_url", default=None)
last_request_method: ContextVar[str | None] = ContextVar("last_request_method", default=None)


def error(msg: str | Exception, code: int = os.EX_UNAVAILABLE) -> NoReturn:
    """Print an error message and exits with the given code."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def create_and_set_corrolation_id(suffix: str) -> str:
    """Set currently active corrolation id.

    This will take a suffix and append it to a generated UUIDv4 and set it as the corrolation id.

    :param suffix: The suffix to use for the corrolation id.

    :returns: The generated corrolation id.
    """
    suffix = re.sub(r"\s+", "_", suffix)
    correlation_id = f"{uuid4()}-{suffix}"

    session.headers.update({"X-Correlation-ID": correlation_id})
    return correlation_id


def get_correlation_id() -> str:
    """Get the currently active corrolation id.

    :returns: The currently active corrolation id.
    """
    return str(session.headers.get("X-Correlation-ID"))


def set_session_token(token: str) -> None:
    """Update session headers with an authorization token.

    :param username: The username to use.
    :param url: The URL to use.
    """
    session.headers.update({"Authorization": f"Token {token}"})


def get_session_token() -> str | None:
    """Get the authorization token from an active session if it exists.

    :param username: The username to use.
    :param url: The URL to use.

    :returns: The token if it exists, otherwise None.
    """
    auth = str(session.headers.get("Authorization"))
    return auth.partition(" ")[2] or None


def try_token_or_login(user: str, url: str, fail_without_token: bool = False) -> None:
    """Check for a valid token or interactively log in to MREG.

    Exits on connection failure.

    :param user: Username to login with.
    :param url: URL to MREG.

    :raises LoginFailedError: If login fails.

    :returns: Nothing.
    """
    token = TokenFile.get_entry(user, url)
    if token:
        set_session_token(token.token)

    try:
        ret = session.get(
            urljoin(url, "/api/v1/hosts/"),
            params={"page_size": 1},
            timeout=5,
        )
    except requests.exceptions.ConnectionError as e:
        error(f"Could not connect to {url}: {e}")

    if ret.status_code == 401:
        if fail_without_token:
            raise SystemExit("Token only login failed.")
        prompt_for_password_and_login(user, url, catch_exception=False)


def prompt_for_password_and_login(user: str, url: str, catch_exception: bool = True) -> None:
    """Login to MREG.

    :param user: Username to login with.
    :param url: URL to MREG.
    :param catch_exception: If True, login errors are caught, otherwise they are passed on.

    :raises LoginFailedError: If login fails and catch_exception is False.

    :returns: Nothing.
    """
    print(f"Connecting to {url}")
    password = prompt(f"Password for {user}: ", is_password=True)
    try:
        auth_and_update_token(user, password)
    except CliError as e:
        if catch_exception:
            e.print_and_log()
        if isinstance(e, LoginFailedError):
            raise e
        else:
            raise LoginFailedError("Updating token failed.") from e


def logout() -> None:
    """Logout from MREG."""
    path = urljoin(MregCliConfig().url, "/api/token-logout/")
    # Try to logout, and ignore errors
    try:
        session.post(path)
    except requests.exceptions.ConnectionError as e:
        logger.warning("Failed to log out: %s", e)
        pass


def prompt_for_password_and_try_update_token() -> None:
    """Prompt for a password and try to update the token."""
    password = prompt("You need to re-authenticate\nEnter password: ", is_password=True)
    try:
        user = MregCliConfig().user
        if not user:
            raise LoginFailedError("Unable to determine username.")
        auth_and_update_token(user, password)
    except CliError as e:
        e.print_and_log()


def auth_and_update_token(username: str, password: str) -> None:
    """Perform the actual token update."""
    base_url = MregCliConfig().url
    tokenurl = urljoin(base_url, "/api/token-auth/")
    logger.info("Updating token for %s @ %s", username, tokenurl)
    try:
        result = requests.post(tokenurl, {"username": username, "password": password})
    except requests.exceptions.SSLError as e:
        error(e)
    except requests.exceptions.ConnectionError as e:
        error(e)
    if not result.ok:
        err = parse_mreg_error(result)
        if err:
            msg = err.as_str()
        else:
            msg = result.text
        raise LoginFailedError(msg)

    token = result.json()["token"]
    logger.info("Token updated for %s @ %s", username, tokenurl)
    set_session_token(token)
    TokenFile.set_entry(username, base_url, token)


def result_check(result: Response, operation_type: str, url: str) -> None:
    """Check the result of a request."""
    if not result.ok:
        if err := parse_mreg_error(result):
            res_text = err.as_json_str()  # NOTE: do we want to use as_str() instead?
        elif result.status_code == 404:
            endpoint = url.split("/api/v1/")[-1] if "/api/v1/" in url else url
            res_text = (
                f"Endpoint not found: '{endpoint}'\n"
                f"This may be because your CLI version ({__version__}) is:\n"
                f"  - Too old: The endpoint has been removed from the server\n"
                f"  - Too new: You're using a beta feature not yet available on the server\n"
                f"Try updating or downgrading your mreg-cli."
            )
        else:
            res_text = result.text
        message = f'{operation_type} "{url}": {result.status_code}: {result.reason}\n{res_text}'
        raise APIError(message, result)


def _strip_none(data: dict[str, Any]) -> dict[str, Any]:
    """Recursively strip None values from a dictionary."""
    new: dict[str, Any] = {}
    for key, value in data.items():
        if value is not None:
            if isinstance(value, dict):
                v = _strip_none(value)  # pyright: ignore[reportUnknownArgumentType]
                if v:
                    new[key] = v
            else:
                new[key] = value
    return new


def _request_wrapper(
    operation_type: Literal["get", "post", "patch", "delete"],
    path: str,
    params: QueryParams | None = None,
    ok404: bool = False,
    first: bool = True,
    **data: Any,
) -> Response | None:
    """Wrap request calls to MREG for logging and token management."""
    if params is None:
        params = {}
    url = urljoin(MregCliConfig().url, path)

    logurl = url
    if operation_type.upper() == "GET" and params:
        logurl = logurl + "?" + "&".join(f"{k}={v}" for k, v in params.items())

    logger.info("Request: %s %s [%s]", operation_type.upper(), logurl, get_correlation_id())

    if operation_type.upper() != "GET" and params:
        logger.debug("Params: %s", params)

    if data:
        logger.debug("Data: %s", data)

    # Strip None values from data
    if data and operation_type != "patch":
        data = _strip_none(data)

    if operation_type == "get":
        func = session.get
    elif operation_type == "post":
        func = session.post
    elif operation_type == "patch":
        func = session.patch
    elif operation_type == "delete":
        func = session.delete
    else:
        raise ValueError(f"Unknown operation type: {operation_type}")

    result = func(
        url,
        params=params,
        json=data or None,
        timeout=MregCliConfig().http_timeout,
    )

    last_request_url.set(logurl)
    last_request_method.set(operation_type)

    request_id = result.headers.get("X-Request-Id", "?")
    correlation_id = result.headers.get("X-Correlation-ID", "?")
    id_str = f"[R:{request_id} C:{correlation_id}]"
    log_message = f"Response: {operation_type.upper()} {logurl} {result.status_code} {id_str}"

    if result.status_code >= 300:
        logger.warning(log_message)
    else:
        logger.info(log_message)

    # This is a workaround for old server versions that can't handle JSON data in requests
    if (
        result.status_code == 500
        and (operation_type == "post" or operation_type == "patch")
        and params == {}
        and data
    ):
        result = func(url, params={}, timeout=MregCliConfig().http_timeout, data=data)

    OutputManager().recording_request(operation_type, url, params, data, result)

    if first and result.status_code == 401:
        prompt_for_password_and_try_update_token()
        return _request_wrapper(operation_type, path, params=params, first=False, **data)
    elif result.status_code == 404 and ok404:
        return None

    result_check(result, operation_type.upper(), url)
    return result


@overload
def get(path: str, params: QueryParams | None, ok404: Literal[True]) -> Response | None: ...


@overload
def get(path: str, params: QueryParams | None, ok404: Literal[False]) -> Response: ...


@overload
def get(path: str, params: QueryParams | None = ..., *, ok404: bool) -> Response | None: ...


@overload
def get(path: str, params: QueryParams | None = ...) -> Response: ...


def get(path: str, params: QueryParams | None = None, ok404: bool = False) -> Response | None:
    """Make a standard get request."""
    return _do_get(path, params, ok404)


def _do_get(path: str, params: QueryParams | None = None, ok404: bool = False) -> Response | None:
    """Perform a GET request.

    Separated out from get(), so that we can patch this function with a memoized version
    without affecting other modules that do `from mreg_cli.utilities.api import get`, as
    they would then operate on the unpatched version instead of the modified one,
    since their `get` symbol differs from the `get` symbol in this module
    in a scenario where `get` itself is patched _after_ it is imported elsewhere.

    The caching module can modify this function instead of `get`,
    allowing other modules to be oblivious of the caching behavior, and freely
    import `get` into their namespaces.

    Yes... Patching sucks when you have other modules that import scoped symbols
    into their own namespace.
    """
    if params is None:
        params = {}
    return _request_wrapper("get", path, params=params, ok404=ok404)


def get_list(
    path: str,
    params: QueryParams | None = None,
    ok404: bool = False,
    limit: int | None = 500,
) -> list[Json]:
    """Make a get request that produces a list.

    Will iterate over paginated results and return result as list. If the number of hits is
    greater than limit, the function will raise an exception.

    :param path: The path to the API endpoint.
    :param params: The parameters to pass to the API endpoint.
    :param ok404: Whether to allow 404 responses.
    :param limit: The maximum number of hits to allow.
        If the number of hits is greater than this, the function will raise an exception.
        Set to None to disable this check.
    :raises CliError: If the result from get_list_generic is not a list.

    :returns: A list of dictionaries.
    """
    return get_list_generic(path, params, ok404, limit, expect_one_result=False)


def get_list_in(
    path: str,
    search_field: str,
    search_values: list[int],
    ok404: bool = False,
) -> list[Json]:
    """Get a list of items by a key value pair.

    :param path: The path to the API endpoint.
    :param search_field: The field to search for.
    :param search_values: The values to search for.
    :param ok404: Whether to allow 404 responses.

    :returns: A list of dictionaries.
    """
    return get_list(
        path,
        params={f"{search_field}__in": ",".join(str(x) for x in search_values)},
        ok404=ok404,
    )


def get_item_by_key_value(
    path: str,
    search_field: str,
    search_value: str | int,
    ok404: bool = False,
) -> None | JsonMapping:
    """Get an item by a key value pair.

    :param path: The path to the API endpoint.
    :param search_field: The field to search for.
    :param search_value: The value to search for.
    :param ok404: Whether to allow 404 responses.

    :raises CliWarning: If no result was found and ok404 is False.

    :returns: A single dictionary, or None if no result was found and ok404 is True.
    """
    return get_list_unique(path, params={search_field: search_value}, ok404=ok404)


def get_list_unique(
    path: str,
    params: QueryParams | None = None,
    ok404: bool = False,
) -> None | JsonMapping:
    """Do a get request that returns a single result from a search.

    :param path: The path to the API endpoint.
    :param params: The parameters to pass to the API endpoint.
    :param ok404: Whether to allow 404 responses.

    :raises CliWarning: If no result was found and ok404 is False.

    :returns: A single dictionary, or None if no result was found and ok404 is True.
    """
    ret = get_list_generic(path, params, ok404, expect_one_result=True)
    if not ret:
        return None
    try:
        return JsonMappingValidator.validate_python(ret)
    except ValueError as e:
        raise ValidationError(f"Failed to validate response from {path}: {e}") from e


class PaginatedResponse(BaseModel):
    """Paginated response data from the API."""

    count: int
    next: str | None  # noqa: A003
    previous: str | None
    results: list[Json]

    @field_validator("count", mode="before")
    @classmethod
    def _none_count_is_0(cls, v: Any) -> Any:
        """Ensure `count` is never `None`."""
        # Django count doesn't seem to be guaranteed to be an integer.
        # https://github.com/django/django/blob/bcbc4b9b8a4a47c8e045b060a9860a5c038192de/django/core/paginator.py#L105-L111
        # Theoretically any callable can be passed to the "count" attribute of the paginator.
        # Ensures here that None (and any falsey value) is treated as 0.
        return v or 0

    @classmethod
    def from_response(cls, response: Response) -> PaginatedResponse:
        """Create a PaginatedResponse from a Response."""
        return cls.model_validate_json(response.text)


ListResponse = TypeAdapter(list[Json])
"""JSON list (array) response adapter."""


# TODO: Provide better validation error introspection
def validate_list_response(response: Response) -> list[Json]:
    """Parse and validate that a response contains a JSON array.

    :param response: The response to validate.
    :raises ValidationError: If the response does not contain a valid JSON array.
    :returns: Parsed response data as a list of Python objects.
    """
    try:
        return ListResponse.validate_json(response.text)
    # NOTE: ValueError catches custom Pydantic errors too
    except ValueError as e:
        raise ValidationError(f"{response.url} did not return a valid JSON array") from e


def validate_paginated_response(response: Response) -> PaginatedResponse:
    """Validate and parse that a response contains paginated JSON data.

    :param response: The response to validate.
    :raises ValidationError: If the response does not contain valid paginated JSON.
    :returns: Parsed response data as a PaginatedResponse object.
    """
    try:
        return PaginatedResponse.from_response(response)
    except ValueError as e:
        raise ValidationError(f"{response.url} did not return valid paginated JSON") from e


@overload
def get_list_generic(
    path: str,
    params: QueryParams | None = ...,
    ok404: bool = ...,
    limit: int | None = ...,
    expect_one_result: Literal[False] = False,
) -> list[Json]: ...


@overload
def get_list_generic(
    path: str,
    params: QueryParams | None = ...,
    ok404: bool = ...,
    limit: int | None = ...,
    expect_one_result: Literal[True] = True,
) -> Json: ...


def get_list_generic(
    path: str,
    params: QueryParams | None = None,
    ok404: bool = False,
    limit: int | None = 500,
    expect_one_result: bool | None = False,
) -> Json | list[Json]:
    """Make a get request that produces a list.

    Will iterate over paginated results and return result as list. If the number of hits is
    greater than limit, the function will raise an exception.

    :param path: The path to the API endpoint.
    :param params: The parameters to pass to the API endpoint.
    :param ok404: Whether to allow 404 responses.
    :param limit: The maximum number of hits to allow.
        If the number of hits is greater than this, the function will raise an exception.
        Set to None to disable this check.
    :param expect_one_result: If True, expect exactly one result and return it as a list.

    :raises CliError: If expect_one_result is True and the number of results is not zero or one.
    :raises CliError: If expect_one_result is True and there is a response without a 'results' key.
    :raises CliError: If the number of hits is greater than limit.

    :returns: A list of dictionaries or a dictionary if expect_one_result is True.
    """
    response = get(path, params)

    # Non-paginated results, return them directly
    if "count" not in response.text:
        return validate_list_response(response)

    resp = validate_paginated_response(response)

    if limit and resp.count > abs(limit):
        raise TooManyResults(f"Too many hits ({resp.count}), please refine your search criteria.")

    # Iterate over all pages and collect the results
    ret: list[Json] = resp.results
    while resp.next:
        response = get(resp.next, ok404=ok404)
        if response is None:
            break
        resp = validate_paginated_response(response)
        ret.extend(resp.results)
    if expect_one_result:
        if len(ret) == 0:
            return {}
        if len(ret) > 1 and any(ret[0] != x for x in ret):
            raise MultipleEntitiesFound(
                f"Expected a unique result, got {len(ret)} distinct results."
            )
        return ret[0]
    return ret


def get_typed(
    path: str,
    type_: type[T],
    params: QueryParams | None = None,
    limit: int | None = 500,
) -> T:
    """Fetch and deserialize JSON from an endpoint into a specific type.

    This function is a wrapper over the `get()` function, adding the additional
    functionality of validating and converting the response data to the specified type.

    :param path: The path to the API endpoint.
    :param type_: The type to which the response data should be deserialized.
    :param params: The parameters to pass to the API endpoint.
    :param limit: The maximum number of hits to allow for paginated responses.

    :raises pydantic.ValidationError: If the response cannot be deserialized into the given type.

    :returns: An instance of `type_` populated with data from the response.
    """
    adapter = get_type_adapter(type_)
    if type_ is list or get_origin(type_) is list:
        resp = get_list(path, params=params, limit=limit)
        return adapter.validate_python(resp)
    else:
        resp = get(path, params=params)
        return adapter.validate_json(resp.text)


P = ParamSpec("P")


def clear_cache(f: Callable[P, T]) -> Callable[P, T]:
    """Clear the API cache after running the function."""

    @wraps(f)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        result = f(*args, **kwargs)
        try:
            cache = get_cache()
            cache.cache.evict("api")  # does not reset stats
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
        return result

    return wrapper


@clear_cache
def post(path: str, params: QueryParams | None = None, **kwargs: Any) -> Response | None:
    """Use requests to make a post request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("post", path, params=params, **kwargs)


@clear_cache
def patch(path: str, params: QueryParams | None = None, **kwargs: Any) -> Response | None:
    """Use requests to make a patch request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("patch", path, params=params, **kwargs)


@clear_cache
def delete(path: str, params: QueryParams | None = None) -> Response | None:
    """Use requests to make a delete request."""
    if params is None:
        params = {}
    return _request_wrapper("delete", path, params=params)
