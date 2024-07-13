# API/config.py

import os
from dotenv import load_dotenv

def get_config():
    """
    Load configuration settings from environment variables.

    Returns:
        dict: A dictionary containing configuration settings.
    """
    load_dotenv()

    nvd_api_key = os.getenv('NVD_API_KEY')
    if not nvd_api_key:
        raise ValueError("NVD_API_KEY environment variable is not set")

    config = {
        'SCAN_TIMEOUT': int(os.getenv('SCAN_TIMEOUT', 300)),  # 5 minutes default
        'NVD_API_KEY': nvd_api_key
    }

    return config
