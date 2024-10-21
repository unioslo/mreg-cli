import argparse

import pytest
from prompt_toolkit import HTML

from mreg_cli.config import MregCliConfig
from mreg_cli.main import get_prompt_message


@pytest.mark.parametrize(
    "args, expected",
    [
        (
            {"user": "admin", "url": "https://example.com"},
            "admin@example.com",
        ),
    ],
)
def test_get_prompt_message_args(empty_config: MregCliConfig, args: dict, expected: str) -> None:
    a = argparse.Namespace(prompt=args.get("prompt"), user=args.get("user"), url=args.get("url"))
    conf = empty_config
    conf._config_file = {}
    conf.set_cmd_config(a)
    assert get_prompt_message(a, conf).value == HTML(f"{expected}> ").value


@pytest.mark.parametrize(
    "config, expected",
    [
        (
            {"url": "https://example.com", "user": "admin", "prompt": "{user}@{host}"},
            "admin@example.com",
        ),
    ],
)
def test_get_prompt_message_config(
    empty_config: MregCliConfig, config: dict, expected: str
) -> None:
    args = argparse.Namespace(prompt=None, user=None, url=None)
    conf = empty_config
    conf._config_file = config
    assert get_prompt_message(args, conf).value == HTML(f"{expected}> ").value
