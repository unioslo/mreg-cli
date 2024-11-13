from __future__ import annotations

import os
from typing import Iterator

import pytest
from pytest_httpserver import HTTPServer

from mreg_cli.config import MregCliConfig


@pytest.fixture(autouse=True)
def set_url_env(httpserver: HTTPServer) -> Iterator[None]:
    """Set the config URL to the test HTTP server URL."""
    conf = MregCliConfig()
    pre_override_conf = conf._config_cmd.copy()  # pyright: ignore[reportPrivateUsage]
    conf._config_cmd["url"] = httpserver.url_for("/")  # pyright: ignore[reportPrivateUsage]
    yield
    conf._config_cmd = pre_override_conf  # pyright: ignore[reportPrivateUsage]


@pytest.fixture(autouse=True if os.environ.get("PYTEST_HTTPSERVER_STRICT") else False)
def check_assertions(httpserver: HTTPServer) -> Iterator[None]:
    """Ensure all HTTP server assertions are checked after the test."""
    # If the HTTP server raises errors or has failed assertions in its handlers
    # themselves, we want to raise an exception to fail the test.
    #
    # The `check_assertions` method will raise an exception if there are
    # if any tests have HTTP test server errors.
    # See: https://pytest-httpserver.readthedocs.io/en/latest/tutorial.html#handling-test-errors
    #      https://pytest-httpserver.readthedocs.io/en/latest/howto.html#using-custom-request-handler
    #
    # If a test has an assertion or handler error that is expected, it should
    # call `httpserver.clear_assertions()` and/or `httpserver.clear_handler_errors()` as needed.
    yield
    httpserver.check_assertions()
    httpserver.check_handler_errors()


@pytest.fixture(autouse=True)
def refresh_config() -> Iterator[MregCliConfig]:
    """Delete the singleton instance after each test."""
    conf = MregCliConfig()
    yield conf
    conf._instance = None


@pytest.fixture()
def empty_config() -> Iterator[MregCliConfig]:
    """A config with no values set in any source."""
    conf = MregCliConfig()
    conf._config_cmd = {}
    conf._config_env = {}
    conf._config_file = {}
    yield conf
