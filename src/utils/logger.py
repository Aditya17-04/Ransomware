"""
utils/logger.py
───────────────
Centralised, colour-coded logging for AI-RIDS.

Usage
-----
    from src.utils.logger import get_logger
    log = get_logger(__name__)
    log.info("System started")
    log.warning("Suspicious activity detected")
    log.critical("HIGH ALERT — triggering response chain")
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

try:
    import colorlog
    _COLORLOG_AVAILABLE = True
except ImportError:
    _COLORLOG_AVAILABLE = False

# ── Severity colour map ───────────────────────────────────────────────────────
_COLOUR_MAP: dict[str, str] = {
    "DEBUG":    "cyan",
    "INFO":     "green",
    "WARNING":  "yellow",
    "ERROR":    "red",
    "CRITICAL": "bold_red",
}

_LOG_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
)
_COLOUR_FORMAT = (
    "%(log_color)s%(asctime)s | %(levelname)-8s | %(name)-30s | %(message)s"
)


def _build_console_handler(level: int) -> logging.Handler:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    if _COLORLOG_AVAILABLE:
        formatter = colorlog.ColoredFormatter(
            _COLOUR_FORMAT,
            datefmt="%Y-%m-%d %H:%M:%S",
            log_colors=_COLOUR_MAP,
        )
    else:
        formatter = logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    handler.setFormatter(formatter)
    return handler


def _build_file_handler(log_dir: str, level: int) -> logging.Handler:
    """Rotating file handler — 10 MB per file, 5 back-ups kept."""
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = os.path.join(
        log_dir,
        f"ai_rids_{datetime.now().strftime('%Y%m%d')}.log",
    )
    handler = RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(_LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    )
    return handler


# ── Public API ───────────────────────────────────────────────────────────────

def configure_root_logger(
    level: str = "INFO",
    log_dir: str = "logs",
) -> None:
    """
    Call once at application startup to configure the root logger.
    Subsequent calls to get_logger() will inherit this configuration.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Avoid adding duplicate handlers on re-import
    if root.handlers:
        return

    root.addHandler(_build_console_handler(numeric_level))
    root.addHandler(_build_file_handler(log_dir, numeric_level))


def get_logger(name: str) -> logging.Logger:
    """Return a named child logger.  configure_root_logger() should be called
    first, but this is safe to call independently."""
    return logging.getLogger(name)
