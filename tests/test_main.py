from __future__ import annotations

import argparse

import pytest
from prompt_toolkit import HTML

from mreg_cli.config import MregCliConfig
from mreg_cli.main import get_prompt_message

PROMPT_TEST_CASES = [
    pytest.param(
        {"url": "https://example.com", "user": "admin", "prompt": "{user}@{host}"},
        "admin@example.com",
        id="Custom prompt (name+host)",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin", "prompt": "{user}"},
        "admin",
        id="Custom prompt (name)",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin", "prompt": "foo{host}bar"},
        "fooexample.combar",
        id="Custom prompt (interpolated)",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin"},
        "admin@example.com",
        id="Default prompt",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin", "prompt": ""},
        "admin@example.com",
        id="Empty prompt (default)",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin", "prompt": "{user}@{domain}"},
        "admin@example.com",  # default
        id="Invalid format variable (domain)",
    ),
]


@pytest.mark.parametrize("args, expected", PROMPT_TEST_CASES)
def test_get_prompt_message_args(empty_config: MregCliConfig, args: dict, expected: str) -> None:
    a = argparse.Namespace(prompt=args.get("prompt"), user=args.get("user"), url=args.get("url"))
    conf = empty_config
    conf._config_file = {}
    conf.set_cmd_config(a)
    assert get_prompt_message(a, conf).value == HTML(f"{expected}> ").value


@pytest.mark.parametrize("config, expected", PROMPT_TEST_CASES)
def test_get_prompt_message_config(
    empty_config: MregCliConfig, config: dict, expected: str
) -> None:
    args = argparse.Namespace()
    conf = empty_config
    conf._config_file = config
    assert get_prompt_message(args, conf).value == HTML(f"{expected}> ").value
