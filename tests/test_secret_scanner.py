from unittest.mock import patch

import pytest

import secret_scanner
from secret_scanner import extract_content, is_env_file, main, scan_content


def test_is_env_file_identifies_expected_secret_files():
    assert is_env_file("/repo/.env")
    assert is_env_file("/repo/.env.local")
    assert is_env_file("/repo/credentials")
    assert is_env_file("/repo/secrets.yaml")
    assert is_env_file("/repo/secrets.yml")
    assert is_env_file("/repo/secrets.json")
    assert not is_env_file("/repo/app.py")


def test_extract_content_reads_write_and_edit_payloads():
    assert extract_content("Write", {"content": "new file"}) == "new file"
    assert extract_content("Edit", {"new_string": "replacement"}) == "replacement"
    assert extract_content("Read", {"content": "ignored"}) == ""


@pytest.mark.parametrize(
    ("content", "expected_rule", "should_block"),
    [
        ("private_key = '0x" + "a" * 64 + "'", "eth_private_key", True),
        (
            "seed = 'abandon ability able about above absent absorb abstract absurd abuse access accident'",
            "mnemonic_phrase",
            True,
        ),
        ("aws_key = 'AKIAIOSFODNN7EXAMPLE'", "aws_key", True),
        ("test_api_key = '" + "A" * 30 + "'", "api_key_assignment", False),
        ('api_key = "live_test_token_1234567890"', "api_key_assignment", False),
        (
            'api_key = "dummyservice_prod_key_1234567890"',
            "api_key_assignment",
            False,
        ),
        (
            "token = 'eyJaaaaaaaaaaa.eyJbbbbbbbbbbb.cccccccccccc'",
            "jwt_token",
            False,
        ),
    ],
)
def test_scan_content_reports_positive_secret_patterns(content, expected_rule, should_block):
    rule_name, message, block = scan_content(content, "/repo/app.py")

    assert rule_name == expected_rule
    assert "SEAL" in message
    assert block is should_block


@pytest.mark.parametrize(
    "content",
    [
        "sha256 = '" + "a" * 64 + "'",
        "phrase = 'test example sample fixture mock lorem ipsum alpha bravo charlie delta echo'",
        "aws_key = 'not-a-real-key'",
        'api_key = "test"',
        'api_key = "placeholder_value_xxxxxxxxxxxx"',
        'api_key = "process.env.SOME_LONG_SECRET"',
        "example_token = 'eyJaaaaaaaaaaa.eyJbbbbbbbbbbb.cccccccccccc'",
    ],
)
def test_scan_content_excludes_negative_and_dummy_patterns(content):
    assert scan_content(content, "/repo/app.py") == (None, None, False)


import re

def test_scan_content_exclude_window():
    test_pattern = re.compile(r"SECRET_MATCH")
    test_exclude = re.compile(r"IGNORE_ME")
    mock_patterns = [
        {
            "name": "test_exclude_rule",
            "pattern": test_pattern,
            "exclude": test_exclude,
            "message": "Blocked test rule",
            "block": True,
        }
    ]

    # Test 1: Match without exclude -> Should block
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        rule_name, message, should_block = scan_content("Here is a SECRET_MATCH.", "test.py")
        assert rule_name == "test_exclude_rule"

    # Test 2: Match with exclude nearby (within 100 chars) -> Should skip
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        content = "IGNORE_ME " + "SECRET_MATCH"
        assert scan_content(content, "test.py") == (None, None, False)

        content = "SECRET_MATCH " + "IGNORE_ME"
        assert scan_content(content, "test.py") == (None, None, False)

        content = "a" * 90 + " IGNORE_ME " + "SECRET_MATCH"
        assert scan_content(content, "test.py") == (None, None, False)

    # Test 3: Match with exclude far away (outside 100 chars window) -> Should block
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        content = "IGNORE_ME" + "a" * 150 + "SECRET_MATCH"
        rule_name, _, _ = scan_content(content, "test.py")
        assert rule_name == "test_exclude_rule"


def test_scan_content_value_exclude():
    # Test with named group 'quoted_value'
    mock_patterns_named = [
        {
            "name": "test_value_exclude_named",
            "pattern": re.compile(r"API_KEY=(?P<quoted_value>.*)"),
            "value_exclude": re.compile(r"test_value"),
            "message": "Blocked named",
            "block": True,
        }
    ]
    with patch.object(secret_scanner, "PATTERNS", mock_patterns_named):
        # Excluded value
        assert scan_content("API_KEY=test_value", "test.py") == (None, None, False)
        # Not excluded value
        rule_name, _, _ = scan_content("API_KEY=real_value", "test.py")
        assert rule_name == "test_value_exclude_named"

    # Test without named group (falls back to group(0))
    mock_patterns_unnamed = [
        {
            "name": "test_value_exclude_unnamed",
            "pattern": re.compile(r"API_KEY=.*"),
            "value_exclude": re.compile(r"API_KEY=test_value"),
            "message": "Blocked unnamed",
            "block": True,
        }
    ]
    with patch.object(secret_scanner, "PATTERNS", mock_patterns_unnamed):
        # Excluded value
        assert scan_content("API_KEY=test_value", "test.py") == (None, None, False)
        # Not excluded value
        rule_name, _, _ = scan_content("API_KEY=real_value", "test.py")
        assert rule_name == "test_value_exclude_unnamed"


def test_main_allows_invalid_json_and_logs_parse_error():
    with patch("sys.stdin.read", return_value="bad"), patch.object(
        secret_scanner, "debug_log"
    ) as debug_log:
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    assert debug_log.call_args is not None
    assert "JSON parse error" in debug_log.call_args.args[0]
