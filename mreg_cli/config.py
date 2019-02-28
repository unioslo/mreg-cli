import logging
import os
import sys


logger = logging.getLogger(__name__)

# Config file locations
DEFAULT_CONFIG_PATH = tuple((
    'cli.conf',
    os.path.expanduser('~/.config/mreg-cli'),
    '/etc/mreg-cli',
    os.path.join(sys.prefix, 'local', 'share', 'mreg-cli'),
    os.path.join(sys.prefix, 'share', 'mreg-cli'),
))

# Default logging format
# TODO: Support logging config
LOGGING_FORMAT = "%(levelname)s - %(name)s - %(message)s"

# Verbosity count to logging level
LOGGING_VERBOSITY = tuple((
    logging.ERROR,
    logging.WARNING,
    logging.INFO,
    logging.DEBUG,
))


def get_verbosity(verbosity):
    """
    Translate verbosity to logging level.

    Levels are traslated according to :py:const:`LOGGING_VERBOSITY`.

    :param int verbosity: verbosity level

    :rtype: int
    """
    level = LOGGING_VERBOSITY[min(len(LOGGING_VERBOSITY) - 1, verbosity)]
    return level


def configure_logging(level):
    """
    Enable and configure logging.

    :param int level: logging level
    """
    logging.basicConfig(level=level, format=LOGGING_FORMAT)
