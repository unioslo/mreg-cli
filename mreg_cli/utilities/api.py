"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

from __future__ import annotations

import functools
import logging
import os
import sys
from typing import Callable, NoReturn, ParamSpec, TypeVar
from urllib.parse import urljoin

import httpx
import mreg_api
import requests
from mreg_api import MregClient
from prompt_toolkit import prompt

from mreg_cli.__about__ import __version__
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliError, LoginFailedError
from mreg_cli.tokenfile import TokenFile

session = requests.Session()
session.headers.update({"User-Agent": f"mreg-cli-{__version__}"})

logger = logging.getLogger(__name__)


T = TypeVar("T")
P = ParamSpec("P")


def disable_cache(func: Callable[P, T]) -> Callable[P, T]:
    """Disable cache for the duration of the decorated function."""

    @functools.wraps(func)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        with MregClient().caching(enable=False):
            return func(*args, **kwargs)

    return wrapper


def error(msg: str | Exception, code: int = os.EX_UNAVAILABLE) -> NoReturn:
    """Print an error message and exits with the given code."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def try_token_or_login(user: str, url: str, fail_without_token: bool = False) -> None:
    """Check for a valid token or interactively log in to MREG.

    Exits on connection failure.

    :param user: Username to login with.
    :param url: URL to MREG.

    :raises LoginFailedError: If login fails.

    :returns: Nothing.
    """
    token = TokenFile.get_entry(user, url)
    client = MregClient()

    if token and token.token:
        client.set_token(token.token)

    try:
        client.test_auth()
        logger.info("Using stored token for %s @ %s", user, url)
    except httpx.RequestError as e:
        error(f"Could not connect to {url}: {e}")
    except mreg_api.exceptions.InvalidAuthTokenError as e:
        client.unset_token()  # NOTE: might be redundant
        logger.info("Stored token for %s @ %s is invalid", user, url)
        if not e.response:
            raise e
        if e.response and e.response.status_code == 401:
            if fail_without_token:
                raise SystemExit("Token only login failed.") from None
            prompt_for_password_and_login(user, url)
        return
    else:
        return


def prompt_for_password_and_login(user: str, url: str) -> None:
    """Login to MREG.

    :param user: Username to login with.
    :param url: URL to MREG.

    :raises LoginFailedError: If login fails and catch_exception is False.

    :returns: Nothing.
    """
    print(f"Connecting to {url}")
    password = prompt(f"Password for {user}: ", is_password=True)
    try:
        auth_and_update_token(user, password)
    except CliError as e:
        if isinstance(e, LoginFailedError):
            raise e
        else:
            raise LoginFailedError("Updating token failed.") from e


def prompt_for_password_and_try_update_token() -> None:
    """Prompt for a password and try to update the token."""
    password = prompt("You need to re-authenticate\nEnter password: ", is_password=True)
    try:
        user = MregCliConfig().user
        if not user:
            raise LoginFailedError("Unable to determine username.")
        auth_and_update_token(user, password)
    except CliError as e:
        raise e


def auth_and_update_token(username: str, password: str) -> None:
    """Perform the actual token update."""
    client = MregClient()

    base_url = MregCliConfig().url
    tokenurl = urljoin(base_url, "/api/token-auth/")
    logger.info("Updating token for %s @ %s", username, tokenurl)
    try:
        token = client.login(username, password)
    except httpx.HTTPError as e:
        raise CliError(str(e)) from e  # should be unreachable
    except mreg_api.exceptions.LoginFailedError as e:
        raise LoginFailedError(e.details) from e
    else:
        TokenFile.set_entry(username, base_url, token)
        logger.info("Token updated for %s @ %s", username, tokenurl)
