from datetime import datetime
import os


def log_activity(message):

    os.makedirs("reports", exist_ok=True)

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    line = f"[{timestamp}] {message}\n"

    with open("reports/activity.log", "a") as f:
        f.write(line)
