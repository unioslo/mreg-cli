"""Shared utilities for the mreg_cli package."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.exceptions import InputFailure


def string_to_int(value: Any, error_tag: str) -> int:
    """Convert a string to an integer."""
    try:
        return int(value)
    except ValueError as e:
        raise InputFailure("%s: Not a valid integer" % error_tag) from e


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


def sizeof_fmt(num: float, suffix: str = "B"):
    """Human readable file size."""
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def args_to_mapping(args: argparse.Namespace, *, filter_none: bool = False) -> dict[str, Any]:
    """Convert argparse.Namespace to a dictionary.

    Removes certain keys by default.

    :param args: The argparse.Namespace object to convert.
    :param filter_none: If True, remove keys with a value of None.

    :returns: A dictionary of the argparse.Namespace object.
    """
    m = vars(args)
    for k in ["func"]:  # expand with more exclusions if needed
        m.pop(k, None)
    if not filter_none:
        return m
    return {k: v for k, v in m.items() if v is not None}
