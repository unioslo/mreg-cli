from mh_log import log
from typing import *


def zone(option: str, args: Sequence[str]) -> None:
    log.trace("called zone({}, {})".format(option, args))
