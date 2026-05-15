import pytest
from hooks.secret_scanner import extract_content

def test_extract_content_write_success():
    tool_input = {"content": "Hello World"}
    assert extract_content("Write", tool_input) == "Hello World"

def test_extract_content_write_missing_key():
    tool_input = {"other_key": "Hello"}
    assert extract_content("Write", tool_input) == ""

def test_extract_content_edit_success():
    tool_input = {"new_string": "Updated Text"}
    assert extract_content("Edit", tool_input) == "Updated Text"

def test_extract_content_edit_missing_key():
    tool_input = {"other_key": "Updated"}
    assert extract_content("Edit", tool_input) == ""

def test_extract_content_unhandled_tool():
    tool_input = {"content": "Text", "new_string": "Other"}
    assert extract_content("OtherTool", tool_input) == ""
