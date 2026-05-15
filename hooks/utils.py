import json
import os
import re
from datetime import datetime

def debug_log(msg, log_file):
    """Append timestamped debug message to log file."""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with open(log_file, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except OSError:
        pass


def get_state_file(session_id, prefix):
    """Return path to session-specific state file for dedup."""
    sanitized_session_id = re.sub(r"[^a-zA-Z0-9_-]", "_", session_id)
    return os.path.expanduser(f"~/.claude/.{prefix}_{sanitized_session_id}.json")


def load_shown(session_id, prefix):
    """Load set of already-shown warning keys for this session."""
    path = get_state_file(session_id, prefix)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return set(json.load(f))
        except (json.JSONDecodeError, OSError):
            return set()
    return set()


def save_shown(session_id, prefix, shown):
    """Persist the set of shown warning keys."""
    path = get_state_file(session_id, prefix)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(list(shown), f)
    except OSError:
        pass
