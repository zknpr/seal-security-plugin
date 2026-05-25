"""Shared helpers for SEAL hook state and debug logging.

The hook scripts run as standalone Python files, so this module stays stdlib-only
and avoids side effects beyond the explicitly requested log and state writes.
"""

import json
import os
import re
from datetime import datetime


def debug_log(msg, log_file):
    """Append a timestamped debug message to the requested hook log file."""
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with open(log_file, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except OSError:
        pass


def get_state_file(session_id, prefix):
    """Build a per-session state file path under ~/.claude with a safe name."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", str(session_id))
    return os.path.expanduser(f"~/.claude/.{prefix}_{safe}.json")


def load_shown(session_id, prefix):
    """Load the warning keys already shown for this session and hook prefix."""
    path = get_state_file(session_id, prefix)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return set(json.load(f))
        except (json.JSONDecodeError, OSError):
            return set()
    return set()


def save_shown(session_id, prefix, shown, log_file=None):
    """Persist the shown warning keys so duplicate warnings stay suppressed."""
    path = get_state_file(session_id, prefix)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(list(shown), f)
    except OSError as e:
        if log_file is not None:
            debug_log(f"Failed to save state file: {e}", log_file)
