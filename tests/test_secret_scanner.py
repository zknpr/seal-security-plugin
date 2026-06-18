import json
import re
from unittest.mock import patch

import pytest

import secret_scanner
from secret_scanner import (
    _line_contains,
    extract_content,
    is_env_file,
    main,
    scan_content,
)


@pytest.mark.parametrize(
    ("content", "index", "marker", "expected"),
    [
        ("first line\nsecond line\nthird line", 0, "first", True),  # start of first line
        ("first line\nsecond line\nthird line", 5, "line", True),  # middle of first line
        ("first line\nsecond line\nthird line", 10, "first", True),  # on first \n
        ("first line\nsecond line\nthird line", 11, "second", True),  # start of second line
        ("first line\nsecond line\nthird line", 15, "line", True),  # middle of second line
        ("first line\nsecond line\nthird line", 22, "second", True),  # on second \n
        ("first line\nsecond line\nthird line", 23, "third", True),  # start of third line
        ("first line\nsecond line\nthird line", 30, "line", True),  # end of string
        ("single line string", 5, "single", True),  # single line, no newline
        ("", 0, "anything", False),  # empty string
        ("first line\nsecond line\nthird line", 0, "second", False), # check doesn't match other lines
        ("first line\nsecond line\nthird line", 15, "third", False),
    ],
)
def test_line_contains(content, index, marker, expected):
    assert _line_contains(content, index, marker) == expected


@pytest.mark.parametrize(
    ("filepath", "expected"),
    [
        # Happy paths - expected secrets files
        ("/repo/.env", True),
        ("/repo/.env.local", True),
        ("/repo/.env.development", True),
        ("/repo/.env.test", True),
        ("/repo/.environment", True),
        ("/repo/credentials", True),
        ("/repo/secrets.yaml", True),
        ("/repo/secrets.yml", True),
        ("/repo/secrets.json", True),
        # Files without directory path
        (".env", True),
        (".env.production", True),
        ("credentials", True),
        ("secrets.json", True),
        # Negative cases - shouldn't match
        ("/repo/app.py", False),
        ("/repo/config.json", False),
        ("/repo/env", False),           # missing dot
        ("/repo/my.env", False),        # doesn't start with .env
        ("/repo/my_credentials.txt", False),
        ("/repo/secrets.txt", False),
        ("env", False),
        ("my.env", False),
    ],
)
def test_is_env_file_identifies_expected_secret_files(filepath, expected):
    assert is_env_file(filepath) == expected


def test_extract_content_reads_write_and_edit_payloads():
    assert extract_content("Write", {"content": "new file"}) == "new file"
    assert extract_content("Edit", {"new_string": "replacement"}) == "replacement"
    assert extract_content("Read", {"content": "ignored"}) == ""


@pytest.mark.parametrize(
    ("content", "expected_rule", "should_block"),
    [
        ("private_key = '0x" + "a" * 64 + "'", "eth_private_key", True),
        (
            "seed = 'abandon ability able about above absent absorb abstract absurd abuse access accident'",  # seal-allow-secret
            "mnemonic_phrase",
            True,
        ),
        ("aws_key = 'AKIAIOSFODNN7EXAMPLE'", "aws_key", True),  # seal-allow-secret
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

    # Match without an exclude word nearby -> reports the rule
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        rule_name, message, should_block = scan_content("Here is a SECRET_MATCH.", "test.py")
        assert rule_name == "test_exclude_rule"

    # Exclude word within the 100-char context window -> suppressed
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        assert scan_content("IGNORE_ME " + "SECRET_MATCH", "test.py") == (None, None, False)
        assert scan_content("SECRET_MATCH " + "IGNORE_ME", "test.py") == (None, None, False)
        assert scan_content("a" * 90 + " IGNORE_ME " + "SECRET_MATCH", "test.py") == (None, None, False)

    # Exclude word outside the 100-char window -> still reports
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        content = "IGNORE_ME" + "a" * 150 + "SECRET_MATCH"
        rule_name, _, _ = scan_content(content, "test.py")
        assert rule_name == "test_exclude_rule"


def test_scan_content_value_exclude():
    # Named group 'quoted_value' is what value_exclude is matched against
    mock_patterns_named = [
        {
            "name": "test_value_exclude_named",
            "pattern": re.compile(r"API_KEY=(?P<quoted_value>.*)"),
            "value_exclude": re.compile(r"placeholder_value"),
            "message": "Blocked named",
            "block": True,
        }
    ]
    with patch.object(secret_scanner, "PATTERNS", mock_patterns_named):
        assert scan_content("API_KEY=placeholder_value", "test.py") == (None, None, False)
        rule_name, _, _ = scan_content("API_KEY=real_secret", "test.py")
        assert rule_name == "test_value_exclude_named"

    # Without a named group, value_exclude falls back to the full match
    mock_patterns_unnamed = [
        {
            "name": "test_value_exclude_unnamed",
            "pattern": re.compile(r"API_KEY=.*"),
            "value_exclude": re.compile(r"API_KEY=placeholder_value"),
            "message": "Blocked unnamed",
            "block": True,
        }
    ]
    with patch.object(secret_scanner, "PATTERNS", mock_patterns_unnamed):
        assert scan_content("API_KEY=placeholder_value", "test.py") == (None, None, False)
        rule_name, _, _ = scan_content("API_KEY=real_secret", "test.py")
        assert rule_name == "test_value_exclude_unnamed"


def test_scan_content_respects_allowlist_marker():
    # A line carrying the seal-allow-secret marker is not flagged; a marker on a
    # different line does not suppress the finding.
    mock_patterns = [{
        "name": "fake_rule",
        "pattern": re.compile(r"SECRET_TOKEN_HERE"),
        "message": "[SEAL] BLOCKED: test",
        "block": True,
    }]
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        rule_name, _, _ = scan_content("k = SECRET_TOKEN_HERE", "t.py")
        assert rule_name == "fake_rule"

        assert scan_content("k = SECRET_TOKEN_HERE  # seal-allow-secret", "t.py") == (None, None, False)

        rule_name, _, _ = scan_content("# seal-allow-secret\nk = SECRET_TOKEN_HERE", "t.py")
        assert rule_name == "fake_rule"

        # An allowlisted match must NOT mask a later non-allowlisted match of the
        # same rule (regression: a suppressed first match used to skip the rule).
        rule_name, _, _ = scan_content(
            "k1 = SECRET_TOKEN_HERE  # seal-allow-secret\nk2 = SECRET_TOKEN_HERE", "t.py"
        )
        assert rule_name == "fake_rule"


def test_scan_content_exclude_does_not_mask_later_match():
    # A first match suppressed by `exclude` must not hide a later real match of
    # the same rule (regression: multi-match masking via the exclude path).
    mock_patterns = [{
        "name": "ex_rule",
        "pattern": re.compile(r"HIT"),
        "exclude": re.compile(r"SKIP"),
        "message": "[SEAL] BLOCKED: test",
        "block": True,
    }]
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        # First HIT sits next to SKIP (excluded); the second HIT is clean and far
        # outside the 100-char exclude window.
        content = "SKIP HIT" + " " * 200 + "clean HIT"
        rule_name, _, _ = scan_content(content, "t.py")
        assert rule_name == "ex_rule"


def test_scan_content_value_exclude_does_not_mask_later_match():
    # A first match suppressed by value_exclude must not hide a later real match
    # of the same rule (the third multi-match masking path).
    mock_patterns = [{
        "name": "ve_rule",
        "pattern": re.compile(r"KEY=(?P<quoted_value>\S+)"),
        "value_exclude": re.compile(r"PLACEHOLDER"),
        "message": "[SEAL] BLOCKED: test",
        "block": True,
    }]
    with patch.object(secret_scanner, "PATTERNS", mock_patterns):
        content = "KEY=PLACEHOLDER\nKEY=real_value_not_placeholder"
        rule_name, _, _ = scan_content(content, "t.py")
        assert rule_name == "ve_rule"


def test_scan_content_ignores_non_bip39_word_run():
    # A 12+ run of short lowercase words that aren't BIP39 (ordinary prose) must
    # not be flagged as a mnemonic now that matches are validated against the
    # wordlist. (Built from a list so this file itself isn't a 12-word sequence.)
    prose = " ".join([
        "the", "lazy", "brown", "dogs", "were", "running", "through", "green",
        "valleys", "under", "cloudy", "winter", "skies", "yesterday",
    ])
    assert scan_content(prose, "/repo/notes.txt") == (None, None, False)


def test_looks_like_seed_phrase_validates_against_bip39():
    real = " ".join([
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
    ])
    assert secret_scanner._looks_like_seed_phrase(real) is True
    prose = " ".join([
        "the", "lazy", "brown", "dogs", "were", "running", "through",
        "green", "valleys", "under", "cloudy", "winter", "skies",
    ])
    assert secret_scanner._looks_like_seed_phrase(prose) is False


def test_looks_like_seed_phrase_fails_safe_without_wordlist(monkeypatch):
    # If the vendored wordlist can't be loaded, accept the structural match
    # (better a false positive than missing a real seed).
    monkeypatch.setattr(secret_scanner, "BIP39_WORDS", frozenset())
    assert secret_scanner._looks_like_seed_phrase("any unknown words at all here now") is True


def test_load_bip39_words_loads_full_official_list():
    words = secret_scanner._load_bip39_words()
    assert len(words) == 2048
    assert "abandon" in words and "zoo" in words


def test_load_bip39_words_fails_safe_on_malformed_asset(monkeypatch):
    # A truncated/garbled wordlist must fail safe (return empty -> accept all),
    # never silently weaken detection with a partial set.
    import io
    monkeypatch.setattr("builtins.open", lambda *a, **k: io.StringIO("only\na\nfew\nwords\n"))
    assert secret_scanner._load_bip39_words() == frozenset()


def test_scan_content_finds_seed_after_junk_words():
    # A real seed preceded by many non-BIP39 short words must still be found: the
    # greedy regex match that fails BIP39 validation retries OVERLAPPING.
    seed = " ".join([
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
    ])
    content = ("foobar " * 13) + seed
    rule_name, _, _ = scan_content(content, "/repo/notes.txt")
    assert rule_name == "mnemonic_phrase"


def test_scan_content_allowlist_does_not_absorb_next_line_seed():
    # The phrase pattern is single-line ([ \t]+), so an allowlisted line can't be
    # merged with a real seed on the NEXT line into one suppressed match. (Line 1
    # uses a non-exclude word so the cross-line exclude window doesn't suppress
    # line 2 — that path is covered separately.)
    phrase = " ".join([
        "abandon", "ability", "able", "about", "above", "absent",
        "absorb", "abstract", "absurd", "abuse", "access", "accident",
    ])
    content = "wallet1 = " + phrase + "  # seal-allow-secret\nwallet2 = " + phrase
    rule_name, _, _ = scan_content(content, "/repo/x.txt")
    assert rule_name == "mnemonic_phrase"


def test_main_clean_content_exits_success():
    payload = json.dumps({
        "session_id": "test1",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/repo/clean.py",
            "content": "print('clean')",
        },
    })
    with patch("sys.stdin.read", return_value=payload):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 0


def test_main_blocks_on_first_secret_exposure():
    payload = json.dumps({
        "session_id": "test2",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/repo/app.py",
            "content": "private_key = '0x" + "a" * 64 + "'",
        },
    })

    with patch("sys.stdin.read", return_value=payload), \
         patch("sys.stderr.write") as mock_stderr, \
         patch.object(secret_scanner, "load_shown", return_value=set()), \
         patch.object(secret_scanner, "save_shown") as mock_save:
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2
    # Blocks bypass dedup state — save is not called for a blocking write.
    mock_save.assert_not_called()
    mock_stderr.assert_called()


def test_main_blocks_repeated_secret_exposure():
    # Regression: a blocking secret must be blocked on EVERY write, even after the
    # rule:file_path key was recorded. Otherwise a later write of the same (or a
    # different!) private key to that file would slip through.
    payload = json.dumps({
        "session_id": "test3",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/repo/app.py",
            "content": "private_key = '0x" + "a" * 64 + "'",
        },
    })

    shown_set = {"eth_private_key:/repo/app.py"}

    with patch("sys.stdin.read", return_value=payload), \
         patch("sys.stderr.write"), \
         patch.object(secret_scanner, "load_shown", return_value=shown_set):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2


def test_main_warns_instead_of_blocking_on_env_files():
    payload = json.dumps({
        "session_id": "test4",
        "tool_name": "Write",
        "tool_input": {
            "file_path": "/repo/.env",
            "content": "private_key = '0x" + "a" * 64 + "'",
        },
    })

    with patch("sys.stdin.read", return_value=payload), \
         patch("sys.stderr.write"), \
         patch.object(secret_scanner, "load_shown", return_value=set()), \
         patch.object(secret_scanner, "save_shown") as mock_save:
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_save.assert_called_once()


def test_main_ignores_irrelevant_tools():
    payload = json.dumps({
        "session_id": "test5",
        "tool_name": "Read",
        "tool_input": {"file_path": "/repo/app.py"},
    })
    with patch("sys.stdin.read", return_value=payload):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 0


@pytest.mark.parametrize("bad_tool_input", [None, "oops", 123, [1, 2]])
def test_main_handles_non_dict_tool_input(bad_tool_input):
    # A non-object tool_input must not crash the hook (never-crash contract).
    payload = json.dumps({
        "session_id": "test6",
        "tool_name": "Write",
        "tool_input": bad_tool_input,
    })
    with patch("sys.stdin.read", return_value=payload):
        with pytest.raises(SystemExit) as exc:
            main()
    assert exc.value.code == 0


def test_load_bip39_words_failsafe_on_decode_error():
    # A corrupt wordlist with invalid UTF-8 raises UnicodeDecodeError while the
    # file is read. The loader must not let that crash the module import; it fails
    # safe to an empty set (mnemonic detection falls back to the structural regex).
    boom = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
    with patch("secret_scanner.open", side_effect=boom):
        assert secret_scanner._load_bip39_words() == frozenset()
