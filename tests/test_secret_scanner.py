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
