"""Logging.

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

from __future__ import annotations

import configparser
import logging
import os
import sys
from typing import Any, overload

from mreg_cli.types import DefaultType

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

# Default logging format
# TODO: Support logging config
LOGGING_FORMAT = "%(levelname)s - %(name)s - %(message)s"

# Verbosity count to logging level
LOGGING_VERBOSITY: tuple[int, int, int, int] = (
    logging.ERROR,
    logging.WARNING,
    logging.INFO,
    logging.DEBUG,
)


class MregCliConfig:
    """Configuration class for the mreg-cli.

    This is a singleton class that is used to store configuration information.
    Configuration is loaded with the following priority:
    1. Command line options
    2. Environment variables (prefixed with 'MREG_')
    3. Configuration file
    """

    _instance = None
    _config_cmd: dict[str, str]
    _config_file: dict[str, str]
    _config_env: dict[str, str]

    def __new__(cls) -> MregCliConfig:
        """Create a new instance of the configuration class.

        This ensures that only one instance of the configuration class is created.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._config_file = {}
            cls._instance._config_env = cls._load_env_config()
            cls._instance._config_cmd = {}
            cls._instance.get_config()

        return cls._instance

    @staticmethod
    def _load_env_config() -> dict[str, str]:
        """Load environment variables into the configuration, filtering with 'MREGCLI_' prefix."""
        env_prefix = "MREGCLI_"
        return {
            key[len(env_prefix) :].lower(): value
            for key, value in os.environ.items()
            if key.startswith(env_prefix)
        }

    @overload
    def get(self, key: str) -> str | None: ...

    @overload
    def get(self, key: str, default: DefaultType = ...) -> str | DefaultType: ...

    def get(self, key: str, default: DefaultType | None = None) -> str | DefaultType | None:
        """Get a configuration value with priority: cmdline, env, file.

        :param str key: Configuration key.
        :param default: Default value if key is not found.

        :returns: Configuration value.
        """
        return self._config_cmd.get(
            key, self._config_env.get(key, self._config_file.get(key, default))
        )

    def set_cmd_config(self, cmd_config: dict[str, Any]) -> None:
        """Set command line configuration options.

        :param Dict[str, Any] cmd_config: Dictionary of command line configurations.
        """
        self._config_cmd.update(cmd_config)

    def get_config(self, reload: bool = False) -> None:
        """Load the configuration file into the class.

        :param bool reload: Reload the configuration from the config file.
        """
        if not self._config_file or reload:
            configpath = self.get_config_file()
            if configpath is not None:
                cfgparser = configparser.ConfigParser()
                cfgparser.read(configpath)
                self._config_file = dict(cfgparser["mreg"].items())

    def get_verbosity(self, verbosity: int) -> int:
        """Translate verbosity to logging level.

        Levels are traslated according to :py:const:`LOGGING_VERBOSITY`.

        :param int verbosity: verbosity level

        :rtype: int
        """
        level = LOGGING_VERBOSITY[min(len(LOGGING_VERBOSITY) - 1, verbosity)]
        return level

    def configure_logging(self, level: int = logging.INFO) -> None:
        """Enable and configure logging.

        :param int level: logging level, defaults to :py:const:`logging.INFO`
        """
        logging.basicConfig(level=level, format=LOGGING_FORMAT)

    def get_config_file(self) -> str | None:
        """Get the first config file found in DEFAULT_CONFIG_PATH.

        :returns: path to config file, or None if no config file was found
        """
        for path in DEFAULT_CONFIG_PATH:
            logger.debug("looking for config in %r", os.path.abspath(path))
            if os.path.isfile(path):
                logger.info("found config in %r", path)
                return path
        logger.debug("no config file found in config paths")
        return None

    def get_default_domain(self):
        """Get the default domain from the application."""
        return self.get("domain")

    def get_location_tags(self) -> list[str]:
        """Get the location tags from the application."""
        return self.get("location_tags", "").split(",")

    def get_category_tags(self) -> list[str]:
        """Get the category tags from the application."""
        return self.get("category_tags", "").split(",")

    # We handle url by itself because it's a required config option,
    # it cannot be none once options, env, and config file are parsed.
    def get_url(self) -> str:
        """Get the default url from the application."""
        url = self.get("url", self.get("default_url"))
        if url is None:
            raise ValueError("No URL found in config, no defaults available!")
        return url

    def _calculate_column_width(self, data: dict[str, Any], min_width: int = 8) -> int:
        """Calculate the maximum column width, ensuring a minimum width.

        :param data: Dictionary of data for the column.
        :param min_width: Minimum width of the column.
        :returns: Calculated column width.
        """
        max_length = max((len(str(value)) for value in data.values()), default=0)
        return max(max_length, min_width) + 2  # Adding 2 for padding

    def print_config_table(self) -> None:
        """Pretty print the configuration options in a dynamic table format."""
        all_keys = set(self._config_cmd) | set(self._config_env) | set(self._config_file)
        key_width = max(max(len(key) for key in all_keys), 8) + 2

        # Calculate column widths
        cmd_width = self._calculate_column_width(self._config_cmd)
        env_width = self._calculate_column_width(self._config_env)
        file_width = self._calculate_column_width(self._config_file)

        # Print the table header
        print("Configuration Options:")
        header_format = f"{{:<{key_width}}} {{:<{cmd_width}}} {{:<{env_width}}} {{:<{file_width}}}"
        print(header_format.format("Key", "Active", "Envir", "File"))
        print("-" * (key_width + cmd_width + env_width + file_width))

        # Print each row
        row_format = f"{{:<{key_width}}} {{:<{cmd_width}}} {{:<{env_width}}} {{:<{file_width}}}"
        for key in sorted(all_keys):
            cmd_line_val = str(self._config_cmd.get(key, "-"))
            env_var_val = str(self._config_env.get(key, "-"))
            config_file_val = str(self._config_file.get(key, "-"))
            print(row_format.format(key, cmd_line_val, env_var_val, config_file_val))
