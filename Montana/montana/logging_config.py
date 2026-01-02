"""
Montana Logging Configuration

Provides structured logging for all Montana components.
"""

import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


# Log format
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_FORMAT_DEBUG = "%(asctime)s | %(levelname)-8s | %(name)s:%(lineno)d | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class MontanaLogger:
    """Centralized logging configuration for Montana."""

    _instance: Optional["MontanaLogger"] = None
    _initialized: bool = False

    def __new__(cls) -> "MontanaLogger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._loggers: dict[str, logging.Logger] = {}

    def setup(
        self,
        level: str = "INFO",
        log_dir: Optional[Path] = None,
        console: bool = True,
        file: bool = True,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
    ) -> None:
        """
        Configure logging for Montana.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_dir: Directory for log files (default: ~/.montana/logs)
            console: Enable console logging
            file: Enable file logging
            max_bytes: Max log file size before rotation
            backup_count: Number of backup files to keep
        """
        # Set up log directory
        if log_dir is None:
            log_dir = Path.home() / ".montana" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

        # Get numeric level
        numeric_level = getattr(logging, level.upper(), logging.INFO)

        # Configure root logger
        root_logger = logging.getLogger("montana")
        root_logger.setLevel(numeric_level)

        # Clear existing handlers
        root_logger.handlers.clear()

        # Console handler
        if console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(numeric_level)
            console_format = LOG_FORMAT_DEBUG if numeric_level == logging.DEBUG else LOG_FORMAT
            console_handler.setFormatter(logging.Formatter(console_format, DATE_FORMAT))
            root_logger.addHandler(console_handler)

        # File handler
        if file:
            log_file = log_dir / f"montana_{datetime.now().strftime('%Y%m%d')}.log"
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
            )
            file_handler.setLevel(numeric_level)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT_DEBUG, DATE_FORMAT))
            root_logger.addHandler(file_handler)

        # Error log (separate file for errors)
        if file:
            error_file = log_dir / "montana_errors.log"
            error_handler = logging.handlers.RotatingFileHandler(
                error_file,
                maxBytes=max_bytes,
                backupCount=backup_count,
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.setFormatter(logging.Formatter(LOG_FORMAT_DEBUG, DATE_FORMAT))
            root_logger.addHandler(error_handler)

    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger for a specific component.

        Args:
            name: Component name (e.g., 'vdf', 'consensus', 'network')

        Returns:
            Configured logger instance
        """
        full_name = f"montana.{name}" if not name.startswith("montana.") else name

        if full_name not in self._loggers:
            self._loggers[full_name] = logging.getLogger(full_name)

        return self._loggers[full_name]


# Global instance
_logger_manager = MontanaLogger()


def setup_logging(
    level: str = "INFO",
    log_dir: Optional[Path] = None,
    console: bool = True,
    file: bool = True,
) -> None:
    """
    Set up Montana logging.

    Args:
        level: Log level
        log_dir: Log directory
        console: Enable console output
        file: Enable file output
    """
    _logger_manager.setup(level=level, log_dir=log_dir, console=console, file=file)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a component.

    Args:
        name: Component name

    Returns:
        Logger instance
    """
    return _logger_manager.get_logger(name)


# Component loggers
def get_vdf_logger() -> logging.Logger:
    return get_logger("vdf")


def get_consensus_logger() -> logging.Logger:
    return get_logger("consensus")


def get_network_logger() -> logging.Logger:
    return get_logger("network")


def get_crypto_logger() -> logging.Logger:
    return get_logger("crypto")


def get_node_logger() -> logging.Logger:
    return get_logger("node")


def get_api_logger() -> logging.Logger:
    return get_logger("api")
