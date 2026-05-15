import pytest
from hooks.secret_scanner import is_env_file, extract_content, scan_content

def test_is_env_file():
    # True cases
    assert is_env_file(".env") is True
    assert is_env_file(".env.local") is True
    assert is_env_file(".environment") is True
    assert is_env_file("credentials") is True
    assert is_env_file("secrets.yaml") is True
    assert is_env_file("secrets.yml") is True
    assert is_env_file("secrets.json") is True
    assert is_env_file("/path/to/.env") is True

    # False cases
    assert is_env_file("config.py") is False
    assert is_env_file("app.js") is False
    assert is_env_file("index.html") is False
    assert is_env_file("docker-compose.yaml") is False
    assert is_env_file("secret.txt") is False

def test_extract_content():
    # Write case
    tool_input_write = {"content": "my new file content"}
    assert extract_content("Write", tool_input_write) == "my new file content"

    # Edit case
    tool_input_edit = {"new_string": "updated content"}
    assert extract_content("Edit", tool_input_edit) == "updated content"

    # Empty/Other cases
    assert extract_content("Write", {}) == ""
    assert extract_content("Edit", {}) == ""
    assert extract_content("Read", {"content": "should not return"}) == ""

def test_scan_content_eth_private_key():
    # Positive case
    key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    rule_name, message, should_block = scan_content(f"My private key is {key}", "file.txt")
    assert rule_name == "eth_private_key"
    assert should_block is True

    # Negative case (exclude pattern: sha256)
    rule_name, message, should_block = scan_content(f"The sha256 is {key}", "file.txt")
    assert rule_name is None
    assert should_block is False

def test_scan_content_mnemonic_phrase():
    # Positive case
    # The MNEMONIC_PATTERN needs words between 3 and 8 chars.
    # Words used here:
    # app (3), ban (3), che (3), dat (3), eld (3), fig (3), gra (3),
    # hon (3), kiw (3), lem (3), man (3), nec (3)
    phrase = "apple banana cherry dates elder figgy grape honey kiwis lemon mango nectar"
    rule_name, message, should_block = scan_content(f"My seed phrase is {phrase}", "file.txt")
    assert rule_name == "mnemonic_phrase"
    assert should_block is True

    # Negative case (exclude pattern: test)
    rule_name, message, should_block = scan_content(f"This is a test mnemonic {phrase}", "file.txt")
    assert rule_name is None
    assert should_block is False

def test_scan_content_aws_key():
    # Positive case
    aws_key = "AKIA1234567890ABCDEF"
    rule_name, message, should_block = scan_content(f"aws_access_key_id = {aws_key}", "file.txt")
    assert rule_name == "aws_key"
    assert should_block is True

def test_scan_content_api_key_assignment():
    # Positive case
    api_key = "abcdefghijklmnopqrstuvwxyz1234567890"
    rule_name, message, should_block = scan_content(f"api_key = '{api_key}'", "file.txt")
    assert rule_name == "api_key_assignment"
    assert should_block is False # Warns, doesn't block

    # Negative case (exclude pattern: placeholder)
    rule_name, message, should_block = scan_content(f"api_key = 'placeholder_{api_key}'", "file.txt")
    assert rule_name is None
    assert should_block is False

def test_scan_content_jwt_token():
    # Positive case
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    rule_name, message, should_block = scan_content(f"Token: {jwt}", "file.txt")
    assert rule_name == "jwt_token"
    assert should_block is False # Warns, doesn't block

    # Negative case (exclude pattern: test)
    rule_name, message, should_block = scan_content(f"Test token: {jwt}", "file.txt")
    assert rule_name is None
    assert should_block is False
