"""Shared utilities for the mreg_cli package."""
from __future__ import annotations

import re
from typing import Any

from mreg_cli.log import cli_warning


# Temporary, to avoid circular imports and to allow old code to remain without
# breaking. This should be removed once the all the old code is refactored.
def clean_hostname(name: str | bytes) -> str:
    """Ensure hostname is fully qualified, lowercase, and has valid characters.

    :param name: The hostname to clean.

    :raises CliWarning: If the hostname is invalid.

    :returns: The cleaned hostname.
    """
    import re

    from mreg_cli.config import MregCliConfig

    # bytes?
    if not isinstance(name, (str, bytes)):
        cli_warning(f"Invalid input for hostname: {name}")

    if isinstance(name, bytes):
        name = name.decode()

    name = name.lower()

    # invalid characters?
    if re.search(r"^(\*\.)?([a-z0-9_][a-z0-9\-]*\.?)+$", name) is None:
        cli_warning(f"Invalid input for hostname: {name}")

    # Assume user is happy with domain, but strip the dot.
    if name.endswith("."):
        return name[:-1]

    # If a dot in name, assume long name.
    if "." in name:
        return name

    config = MregCliConfig()
    default_domain = config.get("domain")
    # Append domain name if in config and it does not end with it
    if default_domain and not name.endswith(default_domain):
        return f"{name}.{default_domain}"
    return name


def string_to_int(value: Any, error_tag: str) -> int:
    """Convert a string to an integer."""
    try:
        return int(value)
    except ValueError:
        cli_warning("%s: Not a valid integer" % error_tag)


def format_mac(mac: str) -> str:
    """Create a strict 'aa:bb:cc:11:22:33' MAC address.

    Replaces any other delimiters with a colon and turns it into all lower case.
    """
    mac = re.sub("[.:-]", "", mac).lower()
    return ":".join(["%s" % (mac[i : i + 2]) for i in range(0, 12, 2)])


def convert_wildcard_to_regex(
    param: str, arg: str, autoWildcards: bool = False
) -> tuple[str, str]:
    """Convert wildcard filter "foo*bar*" to something DRF will understand.

    E.g. "foo*bar*" -> "?name__regex=$foo.*bar.*"

    :param param: The parameter to filter on
    :param arg: The argument to filter on
    :param autoWildcards: If True, add wildcards to the beginning and end of the argument if
                          they are not already present.
    """
    if "*" not in arg:
        if autoWildcards:
            arg = f"*{arg}*"
        else:
            return (param, arg)

    args = arg.split("*")
    args_len = len(args) - 1
    regex = ""
    for i, piece in enumerate(args):
        if i == 0 and piece:
            regex += f"^{piece}"
        elif i == args_len and piece:
            regex += f"{piece}$"
        elif piece:
            regex += f".*{piece}.*"
    #        if i == 0 and piece:
    #            parts.append(f'{param}__startswith={piece}')
    #        elif i == args_len and piece:
    #            parts.append(f'{param}__endswith={piece}')
    #        elif piece:
    #            parts.append(f'{param}__contains={piece}')

    if arg == "*":
        regex = "."

    return (f"{param}__regex", regex)
