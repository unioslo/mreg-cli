from typing import TextIO
from ._Logger import _Logger
from .levels import *

_l = _Logger()
set_quiet = _l.set_quiet
set_file = _l.set_file
set_level = _l.set_level


def trace(s: str):
    _l.log(TRACE, s)


def debug(s: str):
    assert type(s) == str
    _l.log(DEBUG, s)


def info(s: str):
    assert type(s) == str
    _l.log(INFO, s)


def warn(s: str):
    assert type(s) == str
    _l.log(WARN, s)


def error(s: str):
    assert type(s) == str
    _l.log(ERROR, s)


def fatal(s: str):
    assert type(s) == str
    _l.log(FATAL, s)


if __name__ == '__main__':
    print("Testing testing!")
    set_file(open("log.txt", "a"))
    trace("sporing")
