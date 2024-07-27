import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(log_file=None, log_level=None, max_size=10*1024*1024, backup_count=5):
    """
    Setup a logger with a rotating file handler and a stream handler.

    :param log_file: Path to the log file. Defaults to 'portseeker.log' or PORTSEEKER_LOG_FILE env var.
    :param log_level: Logging level as an integer or string. Defaults to 'DEBUG' or PORTSEEKER_LOG_LEVEL env var.
    :param max_size: Maximum size of the log file before rotation.
    :param backup_count: Number of backup files to keep.
    :return: Configured logger instance.
    """
    logger = logging.getLogger('portseeker')
    logger.handlers.clear()  # Remove existing handlers if any

    # Set log file and level from environment variables if not provided
    log_file = log_file or os.getenv('PORTSEEKER_LOG_FILE', 'portseeker.log')
    log_level = log_level or os.getenv('PORTSEEKER_LOG_LEVEL', 'DEBUG')

    # Convert log level to integer if it's a string
    if isinstance(log_level, str):
        log_level = log_level.upper()
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            raise ValueError(f"Invalid log level: {log_level}")
        log_level = getattr(logging, log_level)
    elif not isinstance(log_level, int):
        log_level = logging.DEBUG

    logger.setLevel(log_level)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # File handler
    file_handler_added = False
    try:
        file_handler = RotatingFileHandler(log_file, maxBytes=max_size, backupCount=backup_count)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        file_handler_added = True
    except Exception as e:
        print(f"Failed to create file handler: {e}")

    # Stream handler
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.debug(f"Logger initialized. Log file: {log_file}, Log level: {logging.getLevelName(log_level)}")
    return logger

# Default logger setup
log_file = os.getenv('PORTSEEKER_LOG_FILE', 'portseeker.log')
log_level = os.getenv('PORTSEEKER_LOG_LEVEL', 'DEBUG')
log_level = getattr(logging, log_level.upper(), logging.DEBUG)

default_logger = setup_logger(log_file=log_file, log_level=log_level)

__all__ = ['setup_logger', 'default_logger']
