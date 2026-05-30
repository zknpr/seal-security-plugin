import os

import pytest
from unittest.mock import patch
from utils import debug_log, get_state_file, load_shown, read_hook_input
import utils


def test_read_hook_input_allows_invalid_json_and_logs_parse_error():
    with patch("sys.stdin.read", return_value="bad"), patch.object(
        utils, "debug_log"
    ) as mock_debug_log:
        with pytest.raises(SystemExit) as exc:
            read_hook_input("/tmp/log.log")

    assert exc.value.code == 0
    assert mock_debug_log.call_args is not None
    assert "JSON parse error" in mock_debug_log.call_args.args[0]


def test_read_hook_input_returns_parsed_json():
    with patch("sys.stdin.read", return_value='{"key": "value"}'):
        data = read_hook_input("/tmp/log.log")
        assert data == {"key": "value"}


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
