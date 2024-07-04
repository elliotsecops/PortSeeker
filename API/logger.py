import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(log_file=None, log_level=None, max_size=1048576, backup_count=5):
    # Remove existing handlers if any
    logger = logging.getLogger('portseeker')
    logger.handlers.clear()
    
    # Set log file and level from environment variables if not provided
    log_file = log_file or os.getenv('PORTSEEKER_LOG_FILE', 'portseeker.log')
    log_level = log_level or os.getenv('PORTSEEKER_LOG_LEVEL', 'DEBUG')

    # Convert log level to integer if it's a string
    if isinstance(log_level, str):
        log_level = getattr(logging, log_level.upper(), logging.DEBUG)
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

default_logger = setup_logger()
