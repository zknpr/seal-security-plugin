import json
import pytest
import sys
from unittest.mock import patch, MagicMock

# Make sure we can import the module correctly
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import security_guard

@patch('sys.stdin.read')
@patch('security_guard.debug_log')
def test_security_guard_main_json_error(mock_debug_log, mock_stdin_read):
    # Simulate unparseable input from the hook host
    mock_stdin_read.return_value = "invalid json input"

    # We expect sys.exit(0) to be called
    with pytest.raises(SystemExit) as exc_info:
        security_guard.main()

    # Verify exit behavior
    assert exc_info.value.code == 0

    # Verify debug_log was called with the correct error
    mock_debug_log.assert_called_once()
    assert "JSON parse error" in mock_debug_log.call_args[0][0]
