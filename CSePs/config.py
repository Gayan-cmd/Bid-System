import json
import os
from datetime import datetime, timedelta

CONFIG_FILE = "storage/config.json"


def initialize_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump({}, f)


def set_deadline(minutes_from_now):
    initialize_config()

    deadline = datetime.utcnow() + timedelta(minutes=minutes_from_now)

    config_data = {
        "deadline": deadline.isoformat()
    }

    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f, indent=4)

    print("Deadline set to:", deadline.isoformat())


def get_deadline():
    initialize_config()

    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)

    return config.get("deadline", None)


def is_deadline_passed():
    deadline_str = get_deadline()

    if not deadline_str:
        return False

    deadline = datetime.fromisoformat(deadline_str)
    return datetime.utcnow() > deadline