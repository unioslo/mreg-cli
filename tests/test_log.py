from __future__ import annotations

import logging
from pathlib import Path

from inline_snapshot import snapshot

from mreg_cli.log import MregCliLogger

# NOTE: we cannot use caplog fixture together with `MregCliLogger`, because
# `start_logging` does nothing if logging already has handlers (which is the case when caplog is used),
# and `stop_logging` removes the caplog handlers.


def test_logging_start(tmp_path: Path) -> None:
    logfile = tmp_path / "test.log"
    mreg_logger = MregCliLogger()
    mreg_logger.start_logging(logfile, "DEBUG")

    logger = logging.getLogger("test_logging_start")
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")

    # Stop logging to flush buffer to the file
    mreg_logger.stop_logging()

    # 5 log messages should be written
    assert logfile.read_text().count("\n") == snapshot(5)


def test_logging_singleton(tmp_path: Path) -> None:
    """Ensure that MregCliLogger behaves as a singleton."""
    logfile = tmp_path / "singleton.log"

    # Do some setup on the first instance
    logger = MregCliLogger()
    logger.stop_logging()
    logger.start_logging(logfile, "INFO")

    logger2 = MregCliLogger()

    assert logger is logger2
    assert logger.status == logger2.status


def test_logging_status_as_str_stderr() -> None:
    logger = MregCliLogger()
    logger.stop_logging()
    logger.start_logging(None, "INFO")
    status = logger.status
    assert status.as_str() == snapshot("INFO > stderr")


def test_logging_status_as_str_file(tmp_path: Path) -> None:
    logfile = tmp_path / "test.log"

    logger = MregCliLogger()
    logger.stop_logging()

    # Actually start logging to the real temp file
    logger.start_logging(logfile, "INFO")
    # But override the file in the logger object to make it deterministic
    logger._file = Path("/path/to/logfile.log")

    status = logger.status
    assert status.as_str() == snapshot("INFO > /path/to/logfile.log")


def test_logging_status_as_str_disabled() -> None:
    logger = MregCliLogger()
    logger.stop_logging()
    status = logger.status
    assert status.as_str() == snapshot("disabled")
