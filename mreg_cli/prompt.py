from __future__ import annotations

import argparse
import functools
import logging
import re
from typing import NamedTuple, Optional

from prompt_toolkit import HTML

from mreg_cli.config import DEFAULT_PROMPT, MregCliConfig
from mreg_cli.outputmanager import OutputManager

logger = logging.getLogger(__name__)


class ConnectionInfo(NamedTuple):
    """Connection information for a server."""

    protocol: str
    host: Optional[str]
    tld: Optional[str]
    port: Optional[int]


@functools.lru_cache()
def parse_connection_string(
    connection_string: str,
) -> ConnectionInfo:
    """Parse a connection string into protocol, host, and port components.

    :param connection_string: The connection string in the format
        'http(s)://[host.domain|host|ip]:port'.
    :returns: A tuple containing protocol, host or IP, domain (if present),
        and port.
    :raises ValueError: If the connection string is improperly formatted.
    """
    # Regular expression to match the protocol (http or https), host/IP (v4/v6), and port
    regex = (
        r"^(?P<protocol>https?)://" r"(?P<host>(?:[a-zA-Z0-9.-]+|\[.*?\]))" r"(?::(?P<port>\d+))?$"
    )

    match = re.match(regex, connection_string)
    if not match:
        raise ValueError(f"Invalid connection string format {connection_string!r}")

    protocol = match.group("protocol")
    host = match.group("host")
    port = int(match.group("port")) if match.group("port") else None

    # Check if host is in brackets (indicating IPv6)
    if host.startswith("[") and host.endswith("]"):
        ip = host[1:-1]
        return ConnectionInfo(protocol, ip, None, port)

    # Check if host is an IPv4 address or domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return ConnectionInfo(protocol, host, None, port)

    # Otherwise, it's a domain
    domain = host.split(".")[-1] if "." in host else None
    return ConnectionInfo(protocol, host, domain, port)


def get_prompt_message(args: argparse.Namespace, config: MregCliConfig) -> HTML:
    """Construct a prompt message based on the CLI args and active config.

    :param args: CLI args parsed by argparse.
    :param config: Active configuration.
    :returns: The prompt message as a prompt-toolkit HTML object.
    """
    manager = OutputManager()
    args_map = vars(args)

    def fmt_prompt(prompt: str) -> str:
        url = config.get_url()
        try:
            info = parse_connection_string(url)
        except Exception as e:
            logger.error("Failed to parse connection string: %s", e)
            info = ConnectionInfo("", url, None, None)

        user = args_map.get("user") or config.get("user", "?")
        domain = args_map.get("domain") or config.get_default_domain()
        return prompt.format(
            # Available variables for the prompt:
            user=str(user),
            host=str(info.host or ""),
            domain=str(domain),
            port=str(info.port or ""),
            proto=info.protocol,
        )

    # Try to get prompt from args -> config -> default
    if (args_prompt := args_map.get("prompt")) is not None:
        prompt = str(args_prompt)
    elif (config_prompt := config.get_prompt()) is not None:
        prompt = config_prompt
    else:
        prompt = DEFAULT_PROMPT

    # Fall back on default prompt if the prompt is invalid
    try:
        prompt = fmt_prompt(prompt)
    except KeyError:
        logger.error("Invalid prompt format: %s", prompt)
        prompt = fmt_prompt(DEFAULT_PROMPT)

    prefix: list[str] = []

    if manager.recording_active():
        prefix.append(f"&gt;'{manager.recording_filename()}'")

    if prefix:
        prefix_str = ",".join(prefix)
        return HTML(f"[{prefix_str}] {prompt}> ")
    return HTML(f"{prompt}> ")
