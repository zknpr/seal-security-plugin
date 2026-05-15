import os
import json
import re
from datetime import datetime

DEBUG_LOG = os.path.expanduser("~/.claude/.seal_scanner_debug.log")

def debug_log(msg, log_file=DEBUG_LOG):
    """Append timestamped debug message."""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        # Ensure directory exists for logging, ignoring errors if we can't create it
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        with open(log_file, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except OSError:
        pass


def get_state_file(session_id, prefix="seal_scanner_state"):
    """Session-scoped state file for dedup."""
    # Mitigate Path Traversal / Arbitrary File Write by sanitizing the session_id.
    # Replace anything that isn't a letter, number, underscore or hyphen with an underscore.
    safe_session_id = re.sub(r"[^a-zA-Z0-9_-]", "_", str(session_id))
    return os.path.expanduser(f"~/.claude/.{prefix}_{safe_session_id}.json")


def load_shown(session_id, prefix="seal_scanner_state"):
    """Load shown warning keys."""
    path = get_state_file(session_id, prefix)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return set(json.load(f))
        except (json.JSONDecodeError, OSError):
            return set()
    return set()


def save_shown(session_id, shown, prefix="seal_scanner_state"):
    """Persist shown warning keys."""
    path = get_state_file(session_id, prefix)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(list(shown), f)
    except OSError:
        pass
