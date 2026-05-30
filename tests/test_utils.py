import os

import json
from unittest.mock import patch

from utils import debug_log, get_state_file, load_shown, save_shown


def test_get_state_file_sanitizes_session_id_path_traversal():
    path = get_state_file("../../../etc/passwd", "seal_guard_state")
    prefix = os.path.expanduser("~/.claude/.seal_guard_state_")

    assert ".." not in path
    assert path.startswith(prefix)


def test_get_state_file_preserves_safe_session_id_characters():
    path = get_state_file("abc-DEF_123", "seal_guard_state")

    assert path == os.path.expanduser("~/.claude/.seal_guard_state_abc-DEF_123.json")


def test_load_shown_returns_empty_set_for_non_iterable_json(tmp_path, monkeypatch):
    monkeypatch.setattr(
        os.path,
        "expanduser",
        lambda path: str(tmp_path / path.removeprefix("~/")),
    )
    path = get_state_file("bad-shape", "seal_guard_state")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("123")

    assert load_shown("bad-shape", "seal_guard_state") == set()


def test_debug_log_never_raises_on_unencodable_text(tmp_path):
    # A lone surrogate (e.g. from JSON "\ud800") can't encode to UTF-8 and would
    # raise UnicodeEncodeError on write; debug_log must swallow it rather than
    # let it propagate and crash the hook before rule evaluation.
    log_file = tmp_path / "debug.log"
    debug_log("payload \ud800 end", str(log_file))


def test_save_shown_happy_path(tmp_path, monkeypatch):
    monkeypatch.setattr(
        os.path,
        "expanduser",
        lambda path: str(tmp_path / path.removeprefix("~/")),
    )
    shown = {"item1", "item2"}
    save_shown("test-session", "test_prefix", shown)

    path = get_state_file("test-session", "test_prefix")
    assert os.path.exists(path)
    with open(path, "r") as f:
        data = json.load(f)
    assert set(data) == shown


def test_save_shown_oserror_without_log_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        os.path,
        "expanduser",
        lambda path: str(tmp_path / path.removeprefix("~/")),
    )

    with patch("os.makedirs", side_effect=OSError("Permission denied")):
        # Should not raise
        save_shown("test-session", "test_prefix", {"item"})


def test_save_shown_oserror_with_log_file(tmp_path, monkeypatch):
    monkeypatch.setattr(
        os.path,
        "expanduser",
        lambda path: str(tmp_path / path.removeprefix("~/")),
    )

    log_file = str(tmp_path / "test.log")
    with patch("os.makedirs", side_effect=OSError("Permission denied")):
        with patch("utils.debug_log") as mock_debug_log:
            save_shown("test-session", "test_prefix", {"item"}, log_file=log_file)

            mock_debug_log.assert_called_once()
            args = mock_debug_log.call_args[0]
            assert "Failed to save state file: Permission denied" in args[0]
            assert args[1] == log_file
