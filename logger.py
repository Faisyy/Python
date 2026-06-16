import os
from datetime import datetime

# ─── Log File Setup ───────────────────────────────────────────────────────────
LOG_DIR  = "logs"
LOG_FILE = os.path.join(LOG_DIR, f"ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")


def _ensure_log_dir():
    """Create logs/ folder if it doesn't exist."""
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)


def init_logger():
    """Call this once at startup to prepare the log file."""
    _ensure_log_dir()
    with open(LOG_FILE, "w") as f:
        f.write(f"=== IDS Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")
    return LOG_FILE


def log_alert(message):
    """Write an alert to the log file with a timestamp."""
    _ensure_log_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [ALERT] {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)


def log_info(message):
    """Write a general info message to the log file."""
    _ensure_log_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [INFO]  {message}\n"
    with open(LOG_FILE, "a") as f:
        f.write(entry)