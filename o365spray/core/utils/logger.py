#!/usr/bin/env python3
# fmt: off

import logging

from o365spray.core.utils.colors import text_colors as bcolors


class LoggingLevels:
    CRITICAL = f"{bcolors.FAIL}%s{bcolors.ENDC}" % "crit"     # 50
    ERROR    = f"{bcolors.FAIL}%s{bcolors.ENDC}" % "fail"     # 40
    WARNING  = f"{bcolors.WARNING}%s{bcolors.ENDC}" % "warn"  # 30
    INFO     = f"{bcolors.OKBLUE}%s{bcolors.ENDC}" % "info"   # 20
    DEBUG    = f"{bcolors.OKBLUE}%s{bcolors.ENDC}" % "debg"   # 10


def init_logger(debug: bool):
    """Initialize program logging

    Arguments:
        debug: if debugging is enabled
    """
    # Updated: keep format construction centralized for reuse by file handlers.
    logging_level = logging.DEBUG if debug else logging.INFO
    logging_format = _build_logging_format(debug)
    logging.basicConfig(format=logging_format, level=logging_level)

    # Update log level names with colorized output
    logging.addLevelName(logging.CRITICAL, LoggingLevels.CRITICAL)  # 50
    logging.addLevelName(logging.ERROR,    LoggingLevels.ERROR)     # 40
    logging.addLevelName(logging.WARNING,  LoggingLevels.WARNING)   # 30
    logging.addLevelName(logging.INFO,     LoggingLevels.INFO)      # 20
    logging.addLevelName(logging.DEBUG,    LoggingLevels.DEBUG)     # 10


def _build_logging_format(debug: bool) -> str:
    # Updated: helper to standardize console/file formatting.
    if debug:
        return "[%(asctime)s] %(levelname)-5s | %(filename)17s:%(lineno)-4s | %(message)s"
    return "[%(asctime)s] %(levelname)-5s | %(message)s"


def add_file_logger(log_path: str, debug: bool) -> logging.Handler:
    """Attach a file handler that mirrors CLI output for raw logging."""
    # Updated: create a per-run raw CLI output file handler.
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.setFormatter(logging.Formatter(_build_logging_format(debug)))
    logging.getLogger().addHandler(handler)
    return handler


def remove_file_logger(handler: logging.Handler):
    """Detach and close a file handler."""
    # Updated: ensure per-action log handlers are removed cleanly.
    root = logging.getLogger()
    root.removeHandler(handler)
    handler.close()
