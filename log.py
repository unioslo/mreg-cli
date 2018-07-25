import getpass
import inspect
import re
import sys
import traceback

from datetime import datetime
from exceptions import *
from config import cli_config

try:
    conf = cli_config(required_fields=("server_ip", "server_port", "log_file"))
except Exception as e:
    print("util.py: cli_config:", e)
    traceback.print_exc()
    sys.exit(1)


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
    with open(conf["log_file"], "a+") as f:
        f.write(entry + end)


def cli_error(msg: str, raise_exception: bool = True, exception=CliError) -> None:
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
        raise exception("ERROR: {}: {}".format(pre, msg))


def cli_warning(msg: str, raise_exception: bool = True, exception=CliWarning) -> None:
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
        raise exception("WARNING: {}: {}".format(pre, msg))


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
        print("OK: {}: {}".format(pre, msg))
