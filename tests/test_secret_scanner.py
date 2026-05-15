import sys
import os

# Add the 'hooks' directory to sys.path so we can import secret_scanner
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'hooks'))
from secret_scanner import scan_content

def test_scan_content_no_match():
    """Test a safe string with no secrets returns None."""
    content = "This is a safe string with no secrets."
    file_path = "safe.py"
    result = scan_content(content, file_path)
    assert result == (None, None, False)

def test_scan_content_aws_key_match():
    """Test string with AWS key triggers the aws_key rule."""
    content = "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    file_path = "config.py"
    rule_name, message, should_block = scan_content(content, file_path)
    assert rule_name == "aws_key"
    assert "AWS Access Key ID detected" in message
    assert should_block is True

def test_scan_content_api_key_no_exclude():
    """Test string with an API key and no exclusion keywords triggers warning."""
    content = "api_key = '12345678901234567890'"
    file_path = "config.py"
    rule_name, message, should_block = scan_content(content, file_path)
    assert rule_name == "api_key_assignment"
    assert should_block is False

def test_scan_content_api_key_with_exclude():
    """Test string with an API key and an exclusion keyword is ignored."""
    # The 'api_key_assignment' rule excludes contexts with 'test'
    content = "test_api_key = '12345678901234567890'"
    file_path = "config.py"
    rule_name, message, should_block = scan_content(content, file_path)
    assert rule_name is None
    assert message is None
    assert should_block is False

def test_scan_content_multiple_rules():
    """Test that if the first match is excluded, it still finds the second non-excluded match."""
    # 'api_key_assignment' will match the first line but be excluded by 'test'
    # 'aws_key' will match the second line and should be returned
    content = """
    test_api_key = '12345678901234567890'
    aws_access_key_id = AKIAIOSFODNN7EXAMPLE
    """
    file_path = "config.py"
    rule_name, message, should_block = scan_content(content, file_path)
    assert rule_name == "aws_key"
    assert should_block is True
