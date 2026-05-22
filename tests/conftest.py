from __future__ import annotations

import os
from collections.abc import Iterator

import pytest
from mreg_api import MregClient
from mreg_api.client import last_request_method, last_request_url

from mreg_cli.config import MregCliConfig
from mreg_cli.outputmanager import OutputManager


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


@pytest.fixture(autouse=True)
def reset_mreg_client() -> Iterator[None]:
    """Reset the MregClient after each test."""
    yield
    try:
        MregClient.reset_instance()
    except KeyError:
        pass


@pytest.fixture(autouse=True)
def reset_outputmanager() -> Iterator[None]:
    """Reset the OutputManager after each test."""
    yield
    try:
        OutputManager().clear()
    except KeyError:
        pass
