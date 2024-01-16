"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

import json
import logging
import os
import sys
from typing import TYPE_CHECKING, Any, Dict, List, NoReturn, Optional, Union, cast, overload
from urllib.parse import urljoin

import requests

from mreg_cli.outputmanager import OutputManager

if TYPE_CHECKING:
    from typing_extensions import Literal

    from mreg_cli.types import ResponseLike

from prompt_toolkit import prompt

from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliError
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


def set_file_permissions(f: str, mode: int) -> None:
    """Set file permissions on a file."""
    try:
        os.chmod(f, mode)
    except PermissionError:
        print("Failed to set permissions on " + f, file=sys.stderr)
    except FileNotFoundError:
        pass


def login1(user: str, url: str) -> None:
    """Login to MREG."""
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
            urljoin(MregCliConfig().get("url"), "/api/v1/hosts/"),
            params={"page_size": 1},
            timeout=5,
        )
    except requests.exceptions.ConnectionError:
        error(f"Could not connect to {url}")

    if ret.status_code == 401:
        login(user, url)


def login(user: str, url: str) -> None:
    """Login to MREG."""
    print(f"Connecting to {url}")
    # get url
    password = prompt(f"Password for {user}: ", is_password=True)
    try:
        _update_token(user, password)
    except CliError as e:
        e.print_self()


def logout() -> None:
    """Logout from MREG."""
    path = urljoin(MregCliConfig().get("url"), "/api/token-logout/")
    # Try to logout, and ignore errors
    try:
        session.post(path)
    except requests.exceptions.ConnectionError:
        pass


def update_token() -> None:
    """Update the token."""
    password = prompt("You need to re-autenticate\nEnter password: ", is_password=True)
    try:
        _update_token(MregCliConfig().get("user"), password)
    except CliError as e:
        e.print_self()


def _update_token(username: Optional[str], password: str) -> None:
    """Perform the actual token update."""
    tokenurl = urljoin(MregCliConfig().get("url"), "/api/token-auth/")
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
    url = urljoin(MregCliConfig().get("url"), path)

    if use_json:
        result = getattr(session, operation_type)(url, json=params, timeout=HTTP_TIMEOUT)
    else:
        result = getattr(session, operation_type)(
            url, params=params, data=data, timeout=HTTP_TIMEOUT
        )
    result = cast(requests.Response, result)  # convince mypy that result is a Response

    OutputManager().recording_request(operation_type, url, params, data, result)

    if first and result.status_code == 401:
        update_token()
        return _request_wrapper(operation_type, path, first=False, **data)
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
    path: Optional[str], params: Optional[Dict[str, Any]] = None, ok404: bool = False
) -> List[Dict[str, Any]]:
    """Make a get request that produces a list.

    Will iterate over paginated results and return result as list.
    """
    if params is None:
        params = {}
    ret: List[Dict[str, Any]] = []
    while path:
        resp = get(path, params=params, ok404=ok404)
        if resp is None:
            return ret
        result = resp.json()

        if "next" in result:
            path = result["next"]
            ret.extend(result["results"])
        else:
            path = None
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
