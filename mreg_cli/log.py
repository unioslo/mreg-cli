"""Manage logging state for the application.

Implements the MregCliLogger singleton, which can be used to start, stop,
and configure logging.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import NamedTuple, Self

from mreg_cli.types import LogLevel

LOGGING_FORMAT = "%(asctime)s - %(levelname)-8s - %(name)s - %(message)s"


class LoggingStatus(NamedTuple):
    """Information about the current logging state."""

    enabled: bool
    file: Path | None
    level: LogLevel

    def as_str(self) -> str:
        """Get a string representation of the logging status."""
        return f"{self.level} > {self.file or 'stderr'}" if self.enabled else "disabled"


class MregCliLogger:
    """Singleton that manages logging state."""

    _instance = None
    _is_logging: bool = False
    _file: Path | None = None
    _level: LogLevel = LogLevel.INFO

    def __new__(cls) -> Self:
        """Create a new instance of the logger, or return the existing instance."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    @property
    def status(self) -> LoggingStatus:
        """Get information about the current logging state."""
        return LoggingStatus(self._is_logging, self._file, self._level)

    def start_logging(
        self,
        logfile: Path | None,
        level: LogLevel | str = LogLevel.INFO,
        fmt: str = LOGGING_FORMAT,
    ) -> None:
        """Start logging to the specified file. Disables logging if already enabled."""
        level = LogLevel(level)
        if self._is_logging:
            # Flush buffer, reset state before reconfiguring
            self.stop_logging()

        try:
            logging.basicConfig(
                filename=logfile,
                level=level.as_int(),
                format=fmt,
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        except Exception as e:
            print(f"Failed to set up logging: {e}", file=sys.stderr)
            return

        self._is_logging = True
        self._file = logfile
        self._level = level

    def stop_logging(self) -> None:
        """Stop logging."""
        logging.shutdown()
        self._is_logging = False
        self._file = None
