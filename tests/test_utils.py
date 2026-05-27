import os

from utils import debug_log, get_state_file, load_shown


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
