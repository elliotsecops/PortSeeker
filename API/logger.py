import logging
import os
from logging.handlers import RotatingFileHandler

def setup_logger(log_file='portseeker.log', log_level=logging.DEBUG, max_size=10*1024*1024, backup_count=5):
    logger = logging.getLogger('portseeker')
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

log_file = os.getenv('PORTSEEKER_LOG_FILE', 'portseeker.log')
log_level = os.getenv('PORTSEEKER_LOG_LEVEL', 'DEBUG')
log_level = getattr(logging, log_level.upper(), logging.DEBUG)

default_logger = setup_logger(log_file=log_file, log_level=log_level)

__all__ = ['default_logger', 'setup_logger']

default_logger = setup_logger(log_file=log_file, log_level=log_level)

__all__ = ['setup_logger', 'default_logger']
