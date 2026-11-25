from datetime import datetime


def log_activity(message):

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    line = f"[{timestamp}] {message}\n"

    with open("reports/activity.log", "a") as f:
        f.write(line)
