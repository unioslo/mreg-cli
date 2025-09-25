"""Directory and file paths for the application."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import platformdirs

logger = logging.getLogger(__name__)

_pdirs = platformdirs.PlatformDirs(appname="mreg-cli", appauthor="UiO")


# Default file names and paths
CONFIG_DIR = _pdirs.user_config_path
CONFIG_FILE_NAME = "mreg-cli.conf"
CONFIG_FILE_DEFAULT = CONFIG_DIR / CONFIG_FILE_NAME
"""Default config file path."""

LOG_DIR = _pdirs.user_log_path
LOG_FILE_NAME = "mreg-cli.log"
LOG_FILE_DEFAULT = LOG_DIR / LOG_FILE_NAME
"""Default log file path."""

# Config file locations
DEFAULT_CONFIG_PATH: tuple[Path, ...] = tuple(
    (
        CONFIG_FILE_DEFAULT,
        # legacy locations
        # Unresolved to avoid issues if home dir is not available
        Path("~") / ".config" / CONFIG_FILE_NAME,
        _pdirs.site_config_path / CONFIG_FILE_NAME,
        Path("/etc/mreg-cli.conf"),
        Path(sys.prefix) / "local" / "share" / CONFIG_FILE_NAME,
        Path(sys.prefix) / "share" / CONFIG_FILE_NAME,
        # At last, look in ../data/ in case we're developing
        Path(__file__).parent.parent / "data" / CONFIG_FILE_NAME,
    )
)
