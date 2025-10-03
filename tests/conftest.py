from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from pytest_httpserver import HTTPServer

from mreg_cli.config import MregCliConfig
from mreg_cli.utilities.api import last_request_method, last_request_url


@pytest.fixture(autouse=True)
def reset_os_environ() -> Iterator[None]:
    """Reset os.environ after each test to avoid side effects."""
    original_environ = os.environ.copy()
    yield
    # Modify the environment in place to preserve references
    os.environ.clear()
    os.environ.update(original_environ)


@pytest.fixture(autouse=True)
def default_conf() -> Iterator[MregCliConfig]:
    """Use the default config for tests."""
    try:
        conf = MregCliConfig.get_default_config()
        # Pretend we loaded the config from a file
        MregCliConfig._instance = conf
        MregCliConfig._init = True
        yield conf
    finally:
        MregCliConfig._reset_instance()


@pytest.fixture(autouse=True)
def set_url_env(httpserver: HTTPServer, default_conf: MregCliConfig) -> Iterator[None]:
    """Set the config URL to the test HTTP server URL."""
    pre_override_conf = default_conf.url
    default_conf.url = httpserver.url_for("/")
    yield
    default_conf.url = pre_override_conf


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


@pytest.fixture()
def default_config() -> Iterator[MregCliConfig]:
    """Return a default config with no values set in any source."""
    conf = MregCliConfig.get_default_config()
    yield conf


@pytest.fixture(autouse=True)
def reset_context_vars() -> Iterator[None]:
    """Reset all context variables after each test."""
    yield

    last_request_method.set(None)
    last_request_url.set(None)
