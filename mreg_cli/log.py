import getpass
import inspect
import re
from datetime import datetime
from typing import NoReturn, Optional, Type

from .exceptions import CliError, CliWarning

from . import mocktraffic

logfile = None


def _prefix_from_stack() -> str:
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
    if logfile is not None:
        with open(logfile, "a+") as f:
            f.write(entry + end)


def cli_error(
    msg: str, raise_exception: bool = True, exception: Type[Exception] = CliError
) -> Optional[NoReturn]:
    """Write a ERROR log entry."""
    pre = _prefix_from_stack()
    s = "{} {} [ERROR] {}: {}".format(
        datetime.now().isoformat(sep=' ', timespec="seconds"),
        getpass.getuser(),
        pre,
        msg,
    )
    _write_log(s)
    if raise_exception:
        # A simplified message for console
        msg = "ERROR: {}: {}".format(pre, msg)
        mt = mocktraffic.MockTraffic()
        if mt.is_recording():
            # If recording traffic, also record the console output
            mt.record_output(msg)
        elif mt.is_playback():
            # If playing back traffic, verify the console output is as expected
            mt.compare_with_expected_output(msg)
        # Raise the exception
        raise exception(msg)
    return None


def cli_warning(
    msg: str, raise_exception: bool = True, exception: Type[Exception] = CliWarning
) -> Optional[NoReturn]:
    """Write a WARNING log entry."""
    pre = _prefix_from_stack()
    s = "{} {} [WARNING] {}: {}".format(
        datetime.now().isoformat(sep=' ', timespec="seconds"),
        getpass.getuser(),
        pre,
        msg,
    )
    _write_log(s)
    if raise_exception:
        # A simplified message for console
        msg = "WARNING: {}: {}".format(pre, msg)
        mt = mocktraffic.MockTraffic()
        if mt.is_recording():
            # If recording traffic, also record the console output
            mt.record_output(msg)
        elif mt.is_playback():
            # If playing back traffic, verify the console output is as expected
            mt.compare_with_expected_output(msg)
        raise exception(msg)
    return None


def cli_info(msg: str, print_msg: bool = False) -> None:
    """Write an OK log entry."""
    pre = _prefix_from_stack()
    s = "{} {} [OK] {}: {}".format(
        datetime.now().isoformat(sep=' ', timespec="seconds"),
        getpass.getuser(),
        pre,
        msg,
    )
    _write_log(s)
    if print_msg:
        # A simplified message for console
        msg = "OK: {}: {}".format(pre, msg)
        print(msg)
        mt = mocktraffic.MockTraffic()
        if mt.is_recording():
            # If recording traffic, also record the console output
            mt.record_output(msg)
        elif mt.is_playback():
            # If playing back traffic, verify the console output is as expected
            mt.compare_with_expected_output(msg)
