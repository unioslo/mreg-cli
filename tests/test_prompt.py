from __future__ import annotations

import argparse

import pytest
from prompt_toolkit import HTML

from mreg_cli.config import MregCliConfig
from mreg_cli.prompt import get_prompt_message

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
        id="Interpolation mid-word",
    ),
    pytest.param(
        {
            "url": "https://example.com:8000",
            "user": "admin",
            "domain": "custom.url",
            "prompt": "{user}@{proto}://{host}:{port} ({domain})",
        },
        "admin@https://example.com:8000 (custom.url)",
        id="Prompt with all variables",
    ),
    pytest.param(
        {
            "url": "https://example.com",
            "user": "admin",
            "prompt": "{user}@{proto}://{host}:{port} ({domain})",
        },
        "admin@https://example.com: (uio.no)",
        id="Prompt with all variables (no port in url, no custom domain)",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin"},
        "admin@example.com",
        id="Default prompt",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin", "prompt": ""},
        "",
        id="Empty prompt (empty string)",
    ),
    pytest.param(
        {"url": "https://example.com", "user": "admin", "prompt": None},
        "admin@example.com",
        id="Empty prompt (None) (default prompt)",
    ),
    pytest.param(
        {"url": "http://127.0.0.1:8000", "user": "admin"},
        "admin@127.0.0.1",
        id="URL w/ IPv4 & port (default prompt)",
    ),
    pytest.param(
        {"url": "https://[fe80::5074:f2ff:feb1:a87f]:8000", "user": "admin"},
        "admin@fe80::5074:f2ff:feb1:a87f",
        id="URL w/ IPv6 (Link-local) & port (default prompt)",
    ),
    pytest.param(
        {
            "url": "https://[fe80::5074:f2ff:feb1:a87f]:8000",
            "user": "admin",
            "prompt": "{user}@{proto}://{host}:{port}",
        },
        "admin@https://fe80::5074:f2ff:feb1:a87f:8000",
        id="URL w/ IPv6 (Link-local) & port (custom prompt)",
    ),
    pytest.param(
        {
            "url": "http://localhost:8000",
            "user": "admin",
            "prompt": "{user}@{proto}://{host}:{port}",
        },
        "admin@http://localhost:8000",
        id="URL w/ localhost & port (custom prompt)",
    ),
    pytest.param(
        {
            "url": "http://localhost.localdomain:8000",
            "user": "admin",
            "prompt": "{user}@{host}:{port}",
        },
        "admin@localhost.localdomain:8000",
        id="URL w/ localhost.localdomain & port (custom prompt)",
    ),
]


@pytest.mark.parametrize("args, expected", PROMPT_TEST_CASES)
def test_get_prompt_message_args(args: dict, expected: str) -> None:
    a = argparse.Namespace(
        prompt=args.get("prompt"),
        user=args.get("user"),
        url=args.get("url"),
        domain=args.get("domain"),
    )
    conf = MregCliConfig()
    conf.parse_cli_args(a)
    assert get_prompt_message(conf).value == HTML(f"{expected}> ").value


# NOTE: this test is pretty redundant. What is really the difference
# between passing in the CLI args as a dict vs namespace?
@pytest.mark.parametrize("config, expected", PROMPT_TEST_CASES)
def test_get_prompt_message_config(config: dict, expected: str) -> None:
    conf = MregCliConfig()
    conf.parse_cli_args(config)
    assert get_prompt_message(conf).value == HTML(f"{expected}> ").value
