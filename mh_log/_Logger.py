from sys import stderr
from typing import TextIO, Any
from threading import Lock
from time import strftime, localtime
from .levels import *

_lvl_str = {
    TRACE: "TRACE",
    DEBUG: "DEBUG",
    INFO: "INFO",
    WARN: "WARNING",
    ERROR: "ERROR",
    FATAL: "FATAL"
}


def _prefix(lvl: int) -> str:
    return "%s [%-7s]" % (strftime("%Y-%m-%d %H:%M:%S", localtime()), _lvl_str[lvl])


def _std_prefix(lvl: int) -> str:
    return "%s [%-7s]" % (strftime("%H:%M:%S", localtime()), _lvl_str[lvl])


class _Logger():
    def __init__(self):
        self.quiet = False
        self.log_file = None
        self.level = TRACE
        self.lock = Lock()

    def set_quiet(self, enable: Any = True):
        with self.lock:
            self.quiet = True if enable else False

    def set_file(self, file: TextIO):
        with self.lock:
            self.log_file = file

    def set_level(self, lvl: int):
        with self.lock:
            self.level = lvl

    def log(self, lvl: int, s: Any):
        if not self.quiet:
            print("{} {}".format(_std_prefix(lvl), s), file=stderr)
        if self.log_file is not None:
            print("{} {}".format(_prefix(lvl), s), file=self.log_file)
