import logging
from logging import Logger
from pathlib import Path
from typing import Optional


# ANSI color codes for terminal
LEVEL_COLORS = {
    "DEBUG": "\033[36m",  # Cyan
    "INFO": "\033[32m",  # Green
    "WARNING": "\033[33m",  # Yellow
    "ERROR": "\033[31m",  # Red
    "CRITICAL": "\033[35m",  # Magenta
}
RESET_COLOR = "\033[0m"


class ColorFormatter(logging.Formatter):
    """
    Custom formatter that adds colors based on log level.
    Only affects console output (handlers using this formatter).
    """

    def format(self, record: logging.LogRecord) -> str:
        # Build a padded level name so spacing stays consistent
        padded_level = f"{record.levelname + ':':<9}"
        color = LEVEL_COLORS.get(record.levelname, "")
        record.colored_levelname = (
            f"{color}{padded_level}{RESET_COLOR}" if color else padded_level
        )

        # Let the base class format the message (uses colored_levelname)
        return super().format(record)


class AppLogger:
    """
    Central logging helper.

    Usage:
        from logger import AppLogger

        # In main.py (once)
        AppLogger.init(level=logging.INFO)

        # In any module
        logger = AppLogger.get_logger(__name__)
        logger.info("Hello")
    """

    _configured: bool = False

    @classmethod
    def init(
        cls,
        level: int = logging.INFO,
        log_to_file: bool = False,
        filename: str = "sigscan.log",
    ) -> None:
        """
        Initialize root logger with colored console handler and optional file handler.
        Safe to call multiple times – only configures once.
        """
        if cls._configured:
            return

        cls._configured = True

        # Get root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)

        # Remove any existing handlers (e.g., Streamlit/basicConfig)
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Console handler with colors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)

        console_format = "%(colored_levelname)s %(name)s | %(message)s"
        console_formatter = ColorFormatter(console_format)
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)

        # Optional file handler (no colors)
        if log_to_file:
            # Place logs alongside sibling microservices at Microservices/logs
            logs_dir = Path(__file__).resolve().parents[2] / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            file_path = logs_dir / filename

            file_handler = logging.FileHandler(file_path, encoding="utf-8")
            file_handler.setLevel(logging.WARNING)

            file_format = (
                "%(asctime)s | %(levelname)-8s | %(name)s | "
                "%(filename)s:%(lineno)d | %(message)s"
            )
            file_formatter = logging.Formatter(
                file_format,
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(file_formatter)
            root_logger.addHandler(file_handler)

    @staticmethod
    def get_logger(name: Optional[str] = None) -> Logger:
        """
        Get a named logger. Call this in any module instead of logging.getLogger().
        """
        return logging.getLogger(name if name is not None else __name__)
