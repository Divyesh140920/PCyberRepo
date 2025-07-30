import logging
import os
from datetime import datetime

log_dir = "./logs/"
os.makedirs(log_dir, exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = f"{log_dir}test_log_{timestamp}.txt"
print(f"Creating test log: {log_file}")

logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')
logging.info("This is a test log entry for demonstration.")
