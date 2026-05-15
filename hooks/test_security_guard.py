import pytest
import os

# Mocking os.path.expanduser to avoid touching real ~
original_expanduser = os.path.expanduser

def mock_expanduser(path):
    return path.replace("~", "/tmp/mock_home")

def test_get_state_file(monkeypatch):
    monkeypatch.setattr(os.path, "expanduser", mock_expanduser)

    # We need to import get_state_file
    import sys
    sys.path.append(os.path.abspath(os.path.dirname(__file__)))
    from security_guard import get_state_file

    path1 = get_state_file("normal_id_123")
    assert "/tmp/mock_home/.claude/.seal_guard_state_normal_id_123.json" == path1

    # With path traversal attack
    path2 = get_state_file("../../../etc/passwd")
    # After sanitization it should be:
    assert "/tmp/mock_home/.claude/.seal_guard_state__________etc_passwd.json" == path2
