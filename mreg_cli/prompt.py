"""Prompt customization for the CLI."""

from __future__ import annotations

import functools
import logging
import re
from typing import NamedTuple

from prompt_toolkit import HTML

from mreg_cli.config import DEFAULT_PROMPT, MregCliConfig
from mreg_cli.outputmanager import OutputManager

logger = logging.getLogger(__name__)


class ConnectionInfo(NamedTuple):
    """Connection information for a server."""

    protocol: str
    host: str | None
    tld: str | None
    port: int | None


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


def get_prompt_message(config: MregCliConfig) -> HTML:
    """Construct a prompt message based on the CLI args and active config.

    :param args: CLI args parsed by argparse.
    :param config: Active configuration.
    :returns: The prompt message as a prompt-toolkit HTML object.
    """
    manager = OutputManager()

    def fmt_prompt(prompt: str) -> str:
        url = config.url
        try:
            info = parse_connection_string(url)
        except Exception as e:
            logger.error("Failed to parse connection string: %s", e)
            info = ConnectionInfo("", url, None, None)

        user = config.user
        domain = config.domain
        return prompt.format(
            # Available variables for the prompt:
            user=str(user),
            host=str(info.host or ""),
            domain=str(domain),
            port=str(info.port or ""),
            proto=info.protocol,
        )

    # Fall back on default prompt if the prompt is invalid
    try:
        prompt = fmt_prompt(config.prompt)
    except KeyError:
        logger.error("Invalid prompt format: %s", config.prompt)
        prompt = fmt_prompt(DEFAULT_PROMPT)

    prefix: list[str] = []

    if fname := manager.recording_filename():
        prefix.append(f"&gt;'{str(fname)}'")

    if prefix:
        prefix_str = ",".join(prefix)
        return HTML(f"[{prefix_str}] {prompt}> ")
    return HTML(f"{prompt}> ")
