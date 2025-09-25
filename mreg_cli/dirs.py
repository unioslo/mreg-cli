"""Directory and file paths for the application."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import platformdirs

logger = logging.getLogger(__name__)

p = platformdirs.PlatformDirs(appname="mreg-cli", appauthor="UiO")

# Path objects for various application directories

try:
    DATA_DIR = p.user_data_path
    LOG_DIR = p.user_log_path
    CACHE_DIR = p.user_cache_path
    CONFIG_DIR = p.user_config_path
except RuntimeError as e:
    # This can happen if the user has no home directory
    logger.error("Unable to determine user directories: %s", e)
    # Fall back to site directories
    DATA_DIR = p.site_data_path  # pyright: ignore[reportConstantRedefinition]
    LOG_DIR = p.site_data_path / "logs"  # pyright: ignore[reportConstantRedefinition]
    CACHE_DIR = p.site_cache_path  # pyright: ignore[reportConstantRedefinition]
    CONFIG_DIR = p.site_config_path  # pyright: ignore[reportConstantRedefinition]

APP_DIRS = (
    DATA_DIR,
    LOG_DIR,
    CACHE_DIR,
    CONFIG_DIR,
)


# Default file names and paths
CONFIG_FILE_NAME = "mreg-cli.conf"
CONFIG_FILE_DEFAULT = CONFIG_DIR / CONFIG_FILE_NAME
"""Default config file path."""

LOG_FILE_NAME = "mreg-cli.log"
LOG_FILE_DEFAULT = LOG_DIR / LOG_FILE_NAME
"""Default log file path."""

# Config file locations.
# This needs migration to platformdirs... Without breaking historical usage.
DEFAULT_CONFIG_PATH: tuple[Path, ...] = tuple(
    (
        CONFIG_FILE_DEFAULT,
        # legacy locations
        # Unresolved to avoid issues if home dir is not available
        Path("~") / ".config" / CONFIG_FILE_NAME,
        Path("/etc/mreg-cli.conf"),
        Path(sys.prefix) / "local" / "share" / CONFIG_FILE_NAME,
        Path(sys.prefix) / "share" / CONFIG_FILE_NAME,
        # At last, look in ../data/ in case we're developing
        Path(__file__).parent.parent / "data" / CONFIG_FILE_NAME,
    )
)
