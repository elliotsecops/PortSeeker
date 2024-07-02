import os
from dotenv import load_dotenv

load_dotenv()

SCAN_TIMEOUT = 300  # 5 minutes
NVD_API_KEY = os.getenv('NVD_API_KEY')