"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from typing import Any, Literal, NoReturn, TypeVar, cast, overload
from urllib.parse import urljoin
from uuid import uuid4

import requests
from prompt_toolkit import prompt
from pydantic import TypeAdapter

from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliError, LoginFailedError
from mreg_cli.log import cli_error, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.tokenfile import TokenFile
from mreg_cli.types import ResponseLike

session = requests.Session()
session.headers.update({"User-Agent": "mreg-cli"})

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 20

T = TypeVar("T")


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
            urljoin(MregCliConfig().get_url(), "/api/v1/hosts/"),
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
            e.print_self()
        else:
            raise LoginFailedError() from e


def logout() -> None:
    """Logout from MREG."""
    path = urljoin(MregCliConfig().get_url(), "/api/token-logout/")
    # Try to logout, and ignore errors
    try:
        session.post(path)
    except requests.exceptions.ConnectionError:
        pass


def prompt_for_password_and_try_update_token() -> None:
    """Prompt for a password and try to update the token."""
    password = prompt("You need to re-autenticate\nEnter password: ", is_password=True)
    try:
        user = MregCliConfig().get("user")
        if not user:
            raise CliError("Unable to determine username.")
        auth_and_update_token(user, password)
    except CliError as e:
        e.print_self()


def auth_and_update_token(username: str, password: str) -> None:
    """Perform the actual token update."""
    tokenurl = urljoin(MregCliConfig().get_url(), "/api/token-auth/")
    try:
        result = requests.post(tokenurl, {"username": username, "password": password})
    except requests.exceptions.SSLError as e:
        error(e)
    except requests.exceptions.ConnectionError as err:
        error(err)
    if not result.ok:
        try:
            res = result.json()
        except json.JSONDecodeError:
            res = result.text
        if result.status_code == 400:
            if "non_field_errors" in res:
                cli_error("Invalid username/password")
        else:
            cli_error(res)
    token = result.json()["token"]
    set_session_token(token)
    TokenFile.set_entry(username, MregCliConfig().get_url(), token)


def result_check(result: ResponseLike, operation_type: str, url: str) -> None:
    """Check the result of a request."""
    if not result.ok:
        message = f'{operation_type} "{url}": {result.status_code}: {result.reason}'
        try:
            body = result.json()
        except ValueError:
            pass
        else:
            message += f"\n{json.dumps(body, indent=2)}"
        cli_warning(message)


def _request_wrapper(
    operation_type: str,
    path: str,
    params: dict[str, Any] | None = None,
    ok404: bool = False,
    first: bool = True,
    **data: Any,
) -> ResponseLike | None:
    """Wrap request calls to MREG for logging and token management."""
    if params is None:
        params = {}
    url = urljoin(MregCliConfig().get_url(), path)

    result = getattr(session, operation_type)(
        url,
        params=params,
        json=data or None,
        timeout=HTTP_TIMEOUT,
    )
    result = cast(requests.Response, result)  # convince mypy that result is a Response

    OutputManager().recording_request(operation_type, url, params, data, result)

    if first and result.status_code == 401:
        prompt_for_password_and_try_update_token()
        return _request_wrapper(operation_type, path, params=params, first=False, **data)
    elif result.status_code == 404 and ok404:
        return None

    result_check(result, operation_type.upper(), url)
    return result


@overload
def get(path: str, params: dict[str, Any] | None, ok404: Literal[True]) -> ResponseLike | None: ...


@overload
def get(path: str, params: dict[str, Any] | None, ok404: Literal[False]) -> ResponseLike: ...


@overload
def get(path: str, params: dict[str, Any] | None = ..., *, ok404: bool) -> ResponseLike | None: ...


@overload
def get(path: str, params: dict[str, Any] | None = ...) -> ResponseLike: ...


def get(
    path: str, params: dict[str, Any] | None = None, ok404: bool = False
) -> ResponseLike | None:
    """Make a standard get request."""
    if params is None:
        params = {}
    return _request_wrapper("get", path, params=params, ok404=ok404)


def get_list(
    path: str,
    params: dict[str, Any] | None = None,
    ok404: bool = False,
    limit: int | None = 500,
) -> list[dict[str, Any]]:
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
    ret = get_list_generic(path, params, ok404, limit, expect_one_result=False)

    if not isinstance(ret, list):
        raise CliError(f"Expected a list of results, got {type(ret)}.")

    return ret


def get_list_in(
    path: str,
    search_field: str,
    search_values: list[int],
    ok404: bool = False,
) -> list[dict[str, Any]]:
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
    search_value: str,
    ok404: bool = False,
) -> None | dict[str, Any]:
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
    params: dict[str, str],
    ok404: bool = False,
) -> None | dict[str, Any]:
    """Do a get request that returns a single result from a search.

    :param path: The path to the API endpoint.
    :param params: The parameters to pass to the API endpoint.
    :param ok404: Whether to allow 404 responses.

    :raises CliWarning: If no result was found and ok404 is False.

    :returns: A single dictionary, or None if no result was found and ok404 is True.
    """
    ret = get_list_generic(path, params, ok404, expect_one_result=True)

    if not isinstance(ret, dict):
        raise CliError(f"Expected a single result, got {type(ret)}.")

    if not ret:
        return None

    return ret


def get_list_generic(
    path: str,
    params: dict[str, Any] | None = None,
    ok404: bool = False,
    limit: int | None = 500,
    expect_one_result: bool | None = False,
) -> dict[str, Any] | list[dict[str, Any]]:
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

    def _check_expect_one_result(
        ret: list[dict[str, Any]],
    ) -> dict[str, Any] | list[dict[str, Any]]:
        if expect_one_result:
            if len(ret) == 0:
                return {}
            if len(ret) != 1:
                raise CliError(f"Expected exactly one result, got {len(ret)}.")

            return ret[0]

        return ret

    if params is None:
        params = {}

    ret: list[dict[str, Any]] = []

    # Get the first page to check the number of hits, and raise an exception if it is too high.
    get_params = params.copy()
    # get_params["page_size"] = 1
    resp = get(path, get_params).json()
    if limit and resp.get("count", 0) > abs(limit):
        cli_warning(f"Too many hits ({resp['count']}), please refine your search criteria.")

    # Short circuit if there are no more pages. This means that there are no more results to
    # be had so we can return the results we already have.
    if "next" in resp and not resp["next"]:
        return _check_expect_one_result(resp["results"])

    while True:
        resp = get(path, params=params, ok404=ok404)
        if resp is None:
            return _check_expect_one_result(ret)
        result = resp.json()

        ret.extend(result["results"])

        if "next" in result and result["next"]:
            path = result["next"]
        else:
            return _check_expect_one_result(ret)


def get_typed(
    path: str,
    type_: type[T],
    params: dict[str, Any] | None = None,
    paginated: bool = False,
    limit: int | None = 500,
) -> T:
    """Fetch and deserialize JSON from an endpoint into a specific type.

    This function is a wrapper over the `get()` function, adding the additional
    functionality of validating and converting the response data to the specified type.

    :param path: The path to the API endpoint.
    :param type_: The type to which the response data should be deserialized.
    :param params: The parameters to pass to the API endpoint.
    :param paginated: Whether the response is paginated.
    :param limit: The maximum number of hits to allow for paginated responses.

    :raises ValidationError: If the response cannot be deserialized into the given type.

    :returns: An instance of `type_` populated with data from the response.
    """
    adapter = TypeAdapter(type_)
    if paginated:
        resp = get_list(path, params=params, limit=limit)
        return adapter.validate_python(resp)
    else:
        resp = get(path, params=params)
        return adapter.validate_json(resp.text)


def post(path: str, params: dict[str, Any] | None = None, **kwargs: Any) -> ResponseLike | None:
    """Use requests to make a post request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("post", path, params=params, **kwargs)


def patch(path: str, params: dict[str, Any] | None = None, **kwargs: Any) -> ResponseLike | None:
    """Use requests to make a patch request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("patch", path, params=params, **kwargs)


def delete(path: str, params: dict[str, Any] | None = None) -> ResponseLike | None:
    """Use requests to make a delete request."""
    if params is None:
        params = {}
    return _request_wrapper("delete", path, params=params)
