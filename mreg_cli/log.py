"""Logging functions for the CLI."""

import getpass
import inspect
import re
from datetime import datetime
from typing import NoReturn, Optional, Type

from .exceptions import CliError, CliWarning
from .outputmanager import OutputManager

logfile = None


def _prefix_from_stack() -> str:
    """Get a prefix for log entries from the stack."""
    stack = inspect.stack()
    stack.reverse()
    prefix = ""
    for f in stack:
        m = re.match("^do_(?P<name>.+)$", f[3])
        if m:
            prefix += " " + m.group("name")
        m = re.match("^opt_(?P<name>.+)$", f[3])
        if m:
            prefix += " " + m.group("name")
    return prefix.strip()


def _write_log(entry: str, end: str = "\n") -> None:
    """Write a log entry to the log file."""
    if logfile is not None:
        with open(logfile, "a+") as f:
            f.write(entry + end)


def cli_error(
    msg: str, raise_exception: bool = True, exception: Type[Exception] = CliError
) -> Optional[NoReturn]:
    """Write a ERROR log entry."""
    pre = _prefix_from_stack()
    s = "{} {} [ERROR] {}: {}".format(
        datetime.now().isoformat(sep=" ", timespec="seconds"),
        getpass.getuser(),
        pre,
        msg,
    )
    _write_log(s)
    msg = "ERROR: {}: {}".format(pre, msg)
    OutputManager().add_error(msg)
    if raise_exception:
        # A simplified message for console
        raise exception(msg)
    return None


def cli_warning(
    msg: str, raise_exception: bool = True, exception: Type[Exception] = CliWarning
) -> Optional[NoReturn]:
    """Write a WARNING log entry."""
    pre = _prefix_from_stack()
    s = "{} {} [WARNING] {}: {}".format(
        datetime.now().isoformat(sep=" ", timespec="seconds"),
        getpass.getuser(),
        pre,
        msg,
    )
    _write_log(s)
    msg = "WARNING: {}: {}".format(pre, msg)
    OutputManager().add_warning(msg)
    if raise_exception:
        # A simplified message for console
        raise exception(msg)
    return None


def cli_info(msg: str, print_msg: bool = False) -> None:
    """Write an OK log entry."""
    pre = _prefix_from_stack()
    s = "{} {} [OK] {}: {}".format(
        datetime.now().isoformat(sep=" ", timespec="seconds"),
        getpass.getuser(),
        pre,
        msg,
    )
    _write_log(s)
    msg = "OK: {}: {}".format(pre, msg)
    OutputManager().add_ok(msg)
    if print_msg:
        # A simplified message for console
        print(msg)
