import json
import sys
from unittest.mock import patch
import pytest

from hooks.secret_scanner import main

def test_main_invalid_json():
    with patch("sys.stdin.read", return_value="invalid json"), \
         patch("hooks.secret_scanner.debug_log") as mock_debug_log:
        with pytest.raises(SystemExit) as excinfo:
            main()

        mock_debug_log.assert_called_once()
        assert "JSON parse error" in mock_debug_log.call_args[0][0]
        assert excinfo.value.code == 0
