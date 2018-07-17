import inspect
import re


def _prefix_from_stack() -> str:
    stack = inspect.stack()
    stack.reverse()
    prefix = ""
    for f in stack:
        if re.match("^do_.*$", f[3]):
            prefix += " " + f[3].split('_', maxsplit=1)[1]
        if re.match("^opt_.*$", f[3]):
            prefix += " " + f[3].split('_', maxsplit=1)[1]
    return prefix.strip() + ":"


class CliException(Exception):
    pass


class CliError(CliException):
    pass


class CliWarning(CliException):
    pass


class HostNotFoundWarning(CliWarning):
    pass

class SubnetNotFoundWarning(CliWarning):
    pass