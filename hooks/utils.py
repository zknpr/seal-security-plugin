"""Shared helpers for SEAL hook state and debug logging.

The hook scripts run as standalone Python files, so this module stays stdlib-only
and avoids side effects beyond the explicitly requested log and state writes.
"""

import json
import os
import re
import sys
from datetime import datetime

# Precompiled once at import: get_state_file runs per hook invocation and the
# pattern never changes, so compiling it here avoids re-parsing on every call.
_SAFE_SESSION_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")


def debug_log(msg, log_file):
    """Append a timestamped debug message to the requested hook log file."""
    # Opt-in only: the debug log persists plaintext file-path fragments, so it
    # stays OFF unless SEAL_DEBUG is set to a truthy value (1/true/yes/on). This
    # avoids both per-call I/O and writing sensitive content by default. An
    # explicit allow-list means SEAL_DEBUG=0 / false correctly disables it.
    if os.environ.get("SEAL_DEBUG", "").strip().lower() not in ("1", "true", "yes", "on"):
        return
    # Best-effort logger: it must NEVER break the hook. msg can carry untrusted
    # text (command/file_path) including lone surrogates, so f.write() may raise
    # UnicodeEncodeError (a ValueError, not OSError); swallow everything here.
    try:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        dirname = os.path.dirname(log_file)
        if dirname:  # skip makedirs("") for a bare filename (would raise)
            os.makedirs(dirname, exist_ok=True)
        fd = os.open(log_file, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def read_hook_input(log_file):
    """Read, parse, and shape-check the hook's JSON tool input from stdin.

    Both hooks share the same stdin -> json.loads -> graceful-exit flow, so it
    lives here instead of being duplicated. On malformed OR unexpectedly-shaped
    input we log and exit 0 (allow): a parser hiccup or a non-object payload must
    never crash — and thus block — a legitimate tool call. A present-but-non-dict
    ``tool_input`` is normalized to ``{}`` so callers can safely ``.get(...)``.
    """
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        debug_log(f"JSON parse error: {e}", log_file)
        sys.exit(0)  # allow on parse failure
    # A hook payload is always a JSON object. Anything else (list/null/number/str)
    # would make the callers' data.get(...) raise AttributeError, so guard here.
    if not isinstance(data, dict):
        debug_log(f"Unexpected hook input type: {type(data).__name__}", log_file)
        sys.exit(0)  # allow on unexpected shape
    # Normalize a present-but-non-object tool_input to {}. A truthy non-dict
    # (e.g. "oops", 1, [..]) slips past a `... or {}` guard and would crash on
    # tool_input.get(...); coercing here keeps the never-crash contract central.
    if "tool_input" in data and not isinstance(data["tool_input"], dict):
        data["tool_input"] = {}
    return data


def get_state_file(session_id, prefix):
    """Build a per-session state file path under ~/.claude with a safe name."""
    safe = _SAFE_SESSION_ID_RE.sub("_", str(session_id))
    return os.path.expanduser(f"~/.claude/.{prefix}_{safe}.json")


def load_shown(session_id, prefix):
    """Load the warning keys already shown for this session and hook prefix."""
    path = get_state_file(session_id, prefix)
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                return set(json.load(f))
        except (json.JSONDecodeError, OSError, TypeError):
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
