"""Shared helpers for SEAL hook state and debug logging.

The hook scripts run as standalone Python files, so this module stays stdlib-only
and avoids side effects beyond the explicitly requested log and state writes.
"""

import functools
import json
import os
import re
from datetime import datetime


def debug_log(msg, log_file):
    """Append a timestamped debug message to the requested hook log file."""
    # Best-effort logger: it must NEVER break the hook. msg can carry untrusted
    # text (command/file_path) including lone surrogates, so f.write() may raise
    # UnicodeEncodeError (a ValueError, not OSError); swallow everything here.
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        with open(log_file, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


@functools.lru_cache(maxsize=None)
def get_state_file(session_id, prefix):
    """Build a per-session state file path under ~/.claude with a safe name."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", str(session_id))
    return os.path.expanduser(f"~/.claude/.{prefix}_{safe}.json")


@functools.lru_cache(maxsize=None)
def _read_shown_file(path):
    """Cached internal reader. Returns a frozen set to prevent cache mutation."""
    try:
        with open(path, "r") as f:
            return frozenset(json.load(f))
    except (json.JSONDecodeError, OSError, TypeError):
        return frozenset()

def load_shown(session_id, prefix):
    """Load the warning keys already shown for this session and hook prefix."""
    path = get_state_file(session_id, prefix)
    # Return a mutable copy so callers can add to it without mutating the cache
    return set(_read_shown_file(path))

def save_shown(session_id, prefix, shown, log_file=None):
    """Persist the shown warning keys so duplicate warnings stay suppressed."""
    path = get_state_file(session_id, prefix)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(list(shown), f)
        # Clear cache for this specific path
        _read_shown_file.cache_clear()
    except OSError as e:
        if log_file is not None:
            debug_log(f"Failed to save state file: {e}", log_file)
