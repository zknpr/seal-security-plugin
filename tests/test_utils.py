import json
import os
from unittest.mock import patch

import pytest

import utils
from utils import (
    debug_log,
    get_state_file,
    load_shown,
    read_hook_input,
    save_shown,
)


def test_get_state_file_sanitizes_session_id_path_traversal():
    path = get_state_file("../../../etc/passwd", "seal_guard_state")
    prefix = os.path.expanduser("~/.claude/.seal_guard_state_")

    assert ".." not in path
    assert path.startswith(prefix)


def test_get_state_file_preserves_safe_session_id_characters():
    path = get_state_file("abc-DEF_123", "seal_guard_state")

    assert path == os.path.expanduser(
        "~/.claude/.seal_guard_state_abc-DEF_123.json"
    )


def test_load_shown_returns_empty_set_for_non_iterable_json(
    tmp_path, monkeypatch
):
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


def test_load_shown_returns_empty_set_for_invalid_json(tmp_path, monkeypatch):
    monkeypatch.setattr(
        os.path,
        "expanduser",
        lambda path: str(tmp_path / path.removeprefix("~/")),
    )
    path = get_state_file("invalid-json", "seal_guard_state")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("{invalid json")

    assert load_shown("invalid-json", "seal_guard_state") == set()


def test_load_shown_handles_oserror(tmp_path, monkeypatch):
    monkeypatch.setattr(
        os.path,
        "expanduser",
        lambda path: str(tmp_path / path.removeprefix("~/")),
    )
    path = get_state_file("oserror", "seal_guard_state")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write('["test"]')

    import builtins

    def mock_open(*args, **kwargs):
        raise OSError("Permission denied")

    with monkeypatch.context() as m:
        m.setattr(builtins, "open", mock_open)
        assert load_shown("oserror", "seal_guard_state") == set()


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
            save_shown(
                "test-session", "test_prefix", {"item"}, log_file=log_file
            )

            mock_debug_log.assert_called_once()
            args = mock_debug_log.call_args[0]
            assert "Failed to save state file: Permission denied" in args[0]
            assert args[1] == log_file


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


@pytest.mark.parametrize("raw", ["[]", "null", "123", '"a string"', "true"])
def test_read_hook_input_allows_non_object_json(raw):
    # Valid JSON that is not an object (list/null/number/string/bool) must not
    # crash the callers' data.get(...); read_hook_input exits 0 (allow) instead.
    with patch("sys.stdin.read", return_value=raw):
        with pytest.raises(SystemExit) as exc:
            read_hook_input("/tmp/log.log")
    assert exc.value.code == 0


@pytest.mark.parametrize(
    "raw",
    [
        '{"tool_input": "oops"}',
        '{"tool_input": 123}',
        '{"tool_input": [1, 2]}',
        '{"tool_input": null}',
    ],
)
def test_read_hook_input_coerces_non_dict_tool_input(raw):
    # A present-but-non-object tool_input is normalized to {} so callers can
    # safely call tool_input.get(...) without crashing.
    with patch("sys.stdin.read", return_value=raw):
        data = read_hook_input("/tmp/log.log")
    assert data["tool_input"] == {}


def test_read_hook_input_preserves_dict_tool_input():
    with patch(
        "sys.stdin.read", return_value='{"tool_input": {"command": "x"}}'
    ):
        data = read_hook_input("/tmp/log.log")
    assert data["tool_input"] == {"command": "x"}


def test_debug_log_never_raises_on_unencodable_text(tmp_path, monkeypatch):
    # A lone surrogate (e.g. from JSON "\ud800") can't encode to UTF-8 and would
    # raise UnicodeEncodeError on write; debug_log must swallow it rather than
    # let it propagate and crash the hook before rule evaluation.
    # SEAL_DEBUG must be set or debug_log returns early and never exercises the write.
    monkeypatch.setattr(utils, "IS_DEBUG", True)
    log_file = tmp_path / "debug.log"
    debug_log("payload \ud800 end", str(log_file))


def test_debug_log_swallows_exception(tmp_path, monkeypatch):
    monkeypatch.setattr(utils, "IS_DEBUG", True)
    log_file = tmp_path / "debug.log"
    import builtins

    def mock_open(*args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr(builtins, "open", mock_open)
    # Should not raise exception
    debug_log("test", str(log_file))
