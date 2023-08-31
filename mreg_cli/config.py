"""
Logging
-------
This module can be used to configure basic logging to stderr, with an optional
filter level.

When prompting for user input (verbosity, debug level), log levels can be
translated according to a mapping:

.. py:data:: LOGGING_VERBOSITY

    0. :py:const:`logging.ERROR`
    1. :py:const:`logging.WARNING`
    2. :py:const:`logging.INFO`
    3. :py:const:`logging.DEBUG`
"""
import logging
import os
import sys

logger = logging.getLogger(__name__)

# Config file locations
DEFAULT_CONFIG_PATH = tuple(
    (
        os.path.expanduser("~/.config/mreg-cli.conf"),
        "/etc/mreg-cli.conf",
        os.path.join(sys.prefix, "local", "share", "mreg-cli.conf"),
        os.path.join(sys.prefix, "share", "mreg-cli.conf"),
        # At last, look in ../data/ in case we're developing
        os.path.join(os.path.dirname(__file__), "..", "data", "mreg-cli.conf"),
    )
)

DEFAULT_URL = None
DEFAULT_DOMAIN = None

# Default logging format
# TODO: Support logging config
LOGGING_FORMAT = "%(levelname)s - %(name)s - %(message)s"

# Verbosity count to logging level
LOGGING_VERBOSITY = (
    logging.ERROR,
    logging.WARNING,
    logging.INFO,
    logging.DEBUG,
)


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


def get_config_file():
    """
    :return:
        returns the best (first) match from DEFAULT_CONFIG_PATH, or
        None if no file was found.
    """
    for path in DEFAULT_CONFIG_PATH:
        logger.debug("looking for config in %r", os.path.abspath(path))
        if os.path.isfile(path):
            logger.info("found config in %r", path)
            return path
    logger.debug("no config file found in config paths")
    return None


def get_default_domain():
    return DEFAULT_DOMAIN


def get_default_url():
    for url in (os.environ.get("MREGCLI_DEFAULT_URL"), DEFAULT_URL):
        if url is not None:
            return url
    return None
