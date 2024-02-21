"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

import json
import logging
import os
import re
import sys
from typing import TYPE_CHECKING, Any, Dict, List, NoReturn, Optional, Union, cast, overload
from urllib.parse import urljoin
from uuid import uuid4

import requests

from mreg_cli.outputmanager import OutputManager

if TYPE_CHECKING:
    from typing_extensions import Literal

    from mreg_cli.types import ResponseLike

from prompt_toolkit import prompt

from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliError, LoginFailedError
from mreg_cli.log import cli_error, cli_warning

session = requests.Session()
session.headers.update({"User-Agent": "mreg-cli"})

mreg_auth_token_file = os.path.join(str(os.getenv("HOME")), ".mreg-cli_auth_token")

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 20


def error(msg: Union[str, Exception], code: int = os.EX_UNAVAILABLE) -> NoReturn:
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


def set_file_permissions(f: str, mode: int) -> None:
    """Set file permissions on a file."""
    try:
        os.chmod(f, mode)
    except PermissionError:
        print("Failed to set permissions on " + f, file=sys.stderr)
    except FileNotFoundError:
        pass


def try_token_or_login(user: str, url: str, fail_without_token: bool = False) -> None:
    """Check for a valid token or interactively log in to MREG.

    Exits on connection failure.

    :param user: Username to login with.
    :param url: URL to MREG.

    :raises LoginFailedError: If login fails.

    :returns: Nothing.
    """
    if os.path.isfile(mreg_auth_token_file):
        try:
            with open(mreg_auth_token_file, encoding="utf-8") as tokenfile:
                tokenuser, token = tokenfile.readline().split("¤")
                if tokenuser == user:
                    session.headers.update({"Authorization": f"Token {token}"})
        except PermissionError:
            pass

    # Unconditionally set file permissions to 0600.  This is done here
    # in order to migrate existing installations and can be removed when
    # 0.9.11+ is reasonably widespread.  --Marius, 2021-04-22
    # Consider inlining set_file_permissions afterwards!
    set_file_permissions(mreg_auth_token_file, 0o600)

    # Find a better URL.. but so far so good
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
        auth_and_update_token(MregCliConfig().get("user"), password)
    except CliError as e:
        e.print_self()


def auth_and_update_token(username: Optional[str], password: str) -> None:
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
    session.headers.update({"Authorization": f"Token {token}"})
    try:
        with open(mreg_auth_token_file, "w", encoding="utf-8") as tokenfile:
            tokenfile.write(f"{username}¤{token}")
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    set_file_permissions(mreg_auth_token_file, 0o600)


def result_check(result: "ResponseLike", operation_type: str, url: str) -> None:
    """Check the result of a request."""
    if not result.ok:
        message = f'{operation_type} "{url}": {result.status_code}: {result.reason}'
        try:
            body = result.json()
        except ValueError:
            pass
        else:
            message += "\n{}".format(json.dumps(body, indent=2))
        cli_warning(message)


def _request_wrapper(
    operation_type: str,
    path: str,
    params: Optional[Dict[str, Any]] = None,
    ok404: bool = False,
    first: bool = True,
    use_json: bool = False,
    **data: Any,
) -> Optional["ResponseLike"]:
    """Wrap request calls to MREG for logging and token management."""
    if params is None:
        params = {}
    url = urljoin(MregCliConfig().get_url(), path)

    if use_json:
        result = getattr(session, operation_type)(url, json=params, timeout=HTTP_TIMEOUT)
    else:
        result = getattr(session, operation_type)(
            url, params=params, data=data, timeout=HTTP_TIMEOUT
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
def get(path: str, params: Dict[str, Any], ok404: "Literal[True]") -> Optional["ResponseLike"]:
    ...


@overload
def get(path: str, params: Dict[str, Any], ok404: "Literal[False]") -> "ResponseLike":
    ...


@overload
def get(path: str, params: Dict[str, Any] = ..., *, ok404: bool) -> Optional["ResponseLike"]:
    ...


@overload
def get(path: str, params: Dict[str, Any] = ...) -> "ResponseLike":
    ...


def get(
    path: str, params: Optional[Dict[str, Any]] = None, ok404: bool = False
) -> Optional["ResponseLike"]:
    """Make a standard get request."""
    if params is None:
        params = {}
    return _request_wrapper("get", path, params=params, ok404=ok404)


def get_list(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    ok404: bool = False,
    max_hits_to_allow: Optional[int] = 500,
) -> List[Dict[str, Any]]:
    """Make a get request that produces a list.

    Will iterate over paginated results and return result as list. If the number of hits is
    greater than max_hits_to_allow, the function will raise an exception.

    Parameters
    ----------
    path : str
        The path to the API endpoint.
    params : dict, optional
        The parameters to pass to the API endpoint.
    ok404 : bool, optional
        Whether to allow 404 responses.
    max_hits_to_allow : int, optional
        The maximum number of hits to allow. If the number of hits is greater than this, the
        function will raise an exception.

    Returns
    -------
    * A list of dictionaries.

    """
    if params is None:
        params = {}

    ret: List[Dict[str, Any]] = []

    # Get the first page to check the number of hits, and raise an exception if it is too high.
    get_params = params.copy()
    get_params["page_size"] = 1
    resp = get(path, get_params).json()
    if "count" in resp and resp["count"] > max_hits_to_allow:
        raise cli_warning(f"Too many hits ({resp['count']}), please refine your search criteria.")

    while True:
        resp = get(path, params=params, ok404=ok404)
        if resp is None:
            return ret
        result = resp.json()

        ret.extend(result["results"])

        if "next" in result and result["next"]:
            path = result["next"]
        else:
            return ret


def post(
    path: str, params: Optional[Dict[str, Any]] = None, **kwargs: Any
) -> Optional["ResponseLike"]:
    """Use requests to make a post request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("post", path, params=params, **kwargs)


def patch(
    path: str, params: Optional[Dict[str, Any]] = None, use_json: bool = False, **kwargs: Any
) -> Optional["ResponseLike"]:
    """Use requests to make a patch request. Assumes that all kwargs are data fields."""
    if params is None:
        params = {}
    return _request_wrapper("patch", path, params=params, use_json=use_json, **kwargs)


def delete(path: str, params: Optional[Dict[str, Any]] = None) -> Optional["ResponseLike"]:
    """Use requests to make a delete request."""
    if params is None:
        params = {}
    return _request_wrapper("delete", path, params=params)
