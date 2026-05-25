import os

from utils import get_state_file


def test_get_state_file_sanitizes_session_id_path_traversal():
    path = get_state_file("../../../etc/passwd", "seal_guard_state")
    prefix = os.path.expanduser("~/.claude/.seal_guard_state_")

    assert ".." not in path
    assert path.startswith(prefix)


def test_get_state_file_preserves_safe_session_id_characters():
    path = get_state_file("abc-DEF_123", "seal_guard_state")

    assert path == os.path.expanduser("~/.claude/.seal_guard_state_abc-DEF_123.json")
