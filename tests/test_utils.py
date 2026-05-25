import os

from utils import get_state_file, load_shown


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
