#!/usr/bin/env python3
"""
SEAL Secret Scanner Hook — PreToolUse for Write/Edit
Detects private keys, mnemonics, API keys, and credentials being written to files.
Based on SEAL Framework wallet security and opsec principles.

Blocks writes that contain:
- Ethereum/blockchain private keys (hex, 64 chars)
- BIP39 mnemonic seed phrases (12/24 words)
- AWS/GCP/Azure credentials
- API keys and tokens (common patterns)
- JWT tokens
- SSH private keys
- Database connection strings with passwords

Does NOT block writes to:
- .env files (expected to contain secrets, but warns)
- .gitignore'd paths (user has already excluded from VCS)
- Test fixtures with obviously fake values
- Lines carrying a `seal-allow-secret` marker (explicit per-line opt-out)
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import debug_log, load_shown, read_hook_input, save_shown

# Debug log (opt-in via SEAL_DEBUG). Kept under the user-owned ~/.claude dir
# rather than a predictable /tmp path, which in a world-writable directory is a
# symlink/info-disclosure risk (CWE-377).
DEBUG_LOG = os.path.expanduser("~/.claude/seal-secret-scanner.log")
STATE_PREFIX = "seal_scanner_state"

# Explicit per-line opt-out: a line carrying this marker (e.g. a known-fake
# secret in a test fixture) is not flagged. Mirrors detect-secrets'
# "pragma: allowlist secret" / gitleaks' "gitleaks:allow".
ALLOWLIST_MARKER = "seal-allow-secret"

# Mnemonic detection is two-stage: a cheap structural regex finds candidate runs
# of 12-24 short lowercase words, then we confirm the words are actually BIP39
# wordlist entries — otherwise ordinary prose ("the quick brown fox ...") trips it.
# Whitespace between words is space/tab only ([ \t], NOT newlines or exotic
# Unicode line separators like U+2028): a seed phrase is a single line, and
# letting the match span lines would let an allowlisted line absorb a real phrase
# on the next line (per-match suppression inspects only the match-start line).
MNEMONIC_PATTERN = re.compile(
    r"\b([a-z]{3,8}[ \t]+){11,23}[a-z]{3,8}\b"
)


def _load_bip39_words():
    """Load the official 2048-word BIP39 English wordlist for mnemonic validation.

    Returns a frozenset, or an empty set if the vendored file is unavailable — in
    which case mnemonic detection falls back to the structural regex alone.
    """
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bip39_english.txt")
        with open(path, "r", encoding="utf-8") as f:
            words = frozenset(line.strip() for line in f if line.strip())
    except (OSError, UnicodeError):
        # Never crash the import: a missing/unreadable file is OSError, but a
        # corrupt asset with invalid UTF-8 raises UnicodeDecodeError while
        # iterating lines. Both fail safe to an empty set (structural fallback).
        return frozenset()
    # Fail safe: a truncated/garbled asset must not silently weaken detection.
    # The BIP39 English list is exactly 2048 words; if it isn't (or is the wrong
    # list), treat the wordlist as unavailable so _looks_like_seed_phrase accepts
    # every structural candidate rather than under-matching.
    if len(words) != 2048 or "abandon" not in words:
        return frozenset()
    return words


BIP39_WORDS = _load_bip39_words()


def _looks_like_seed_phrase(text):
    """True if `text` has >= 12 consecutive BIP39 words (i.e. a real seed phrase).

    A run of short lowercase words is only a mnemonic if the words are actually
    from the BIP39 list, so this filters out prose / identifier lists that the
    structural regex would otherwise flag. If the wordlist couldn't be loaded we
    accept the structural match (fail safe — better a false positive than a miss).
    """
    if not BIP39_WORDS:
        return True
    run = 0
    for word in text.split():
        if word in BIP39_WORDS:
            run += 1
            if run >= 12:
                return True
        else:
            run = 0
    return False

# Pattern definitions: (name, regex, message, block?)
PATTERNS = [
    # --- Ethereum / EVM private keys (64 hex chars, optionally 0x-prefixed) ---
    {
        "name": "eth_private_key",
        "pattern": re.compile(
            r"(?:0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])"
        ),
        # Exclude common hashes (git commit SHAs are 40 chars, not 64)
        # and known non-key patterns
        "exclude": re.compile(
            r"(sha256|sha512|hash|digest|checksum|integrity|commit)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] BLOCKED: Potential private key detected (64 hex characters).\n"
            "NEVER write private keys to source files. Use environment variables or a secrets manager.\n"
            "Ref: SEAL Framework > Wallet Security > Seed Phrase Management — PROHIBITED: digital storage"
        ),
        "block": True,
    },
    # --- BIP39 mnemonic seed phrases (12 or 24 words) ---
    {
        "name": "mnemonic_phrase",
        "pattern": MNEMONIC_PATTERN,
        "exclude": re.compile(
            r"(test|example|sample|fixture|mock|lorem|ipsum|the\s+quick\s+brown)",
            re.IGNORECASE,
        ),
        # Confirm the candidate is actually BIP39 words, not just any short-word run.
        "validate": _looks_like_seed_phrase,
        "message": (
            "[SEAL] BLOCKED: Potential mnemonic seed phrase detected (12+ word sequence).\n"
            "NEVER store seed phrases in code or config files.\n"
            "Ref: SEAL Framework > Wallet Security > Seed Phrase Management — "
            "PROHIBITED: digital storage, cloud backup, photos, email, password managers"
        ),
        "block": True,
    },
    # --- AWS Access Keys ---
    {
        "name": "aws_key",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "exclude": None,
        "message": (
            "[SEAL] BLOCKED: AWS Access Key ID detected.\n"
            "Use IAM roles, OIDC federation, or environment variables — never hardcode credentials.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation > Short-lived credentials via OIDC"
        ),
        "block": True,
    },
    # --- AWS Secret Key pattern ---
    {
        "name": "aws_secret",
        "pattern": re.compile(r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
        "exclude": None,
        "message": (
            "[SEAL] BLOCKED: AWS Secret Access Key detected.\n"
            "Use IAM roles or environment variables. Rotate this key immediately if it was ever committed.\n"
            "Ref: SEAL Framework > DevSecOps > Securing Development Environments"
        ),
        "block": True,
    },
    # --- Generic API key patterns ---
    # value_exclude rules must define a (?P<quoted_value>...) group; otherwise it falls back to the full match.
    {
        "name": "api_key_assignment",
        "pattern": re.compile(
            r"(?i)(api[_-]?key|api[_-]?secret|api[_-]?token|auth[_-]?token|access[_-]?token"
            r"|secret[_-]?key|client[_-]?secret)\s*[=:]\s*['\"]"
            r"(?P<quoted_value>[A-Za-z0-9_\-\.]{20,})['\"]"
        ),
        "exclude": re.compile(
            r"(process\.env|os\.environ|os\.getenv|ENV\[|System\.getenv|env\()",
            re.IGNORECASE,
        ),
        "value_exclude": re.compile(
            r"(x{3,}|0{3,}|your[_\- ].*|replace[_\- ].*|placeholder.*|<.*>|changeme|example|sample|test|fake|dummy|mock)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] WARNING: Hardcoded API key/token/secret detected.\n"
            "Use environment variables or a secrets manager instead of hardcoding credentials.\n"
            "Ref: SEAL Framework > DevSecOps > Securing Development Environments"
        ),
        "block": False,
    },
    # --- JWT tokens ---
    {
        "name": "jwt_token",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "exclude": re.compile(r"(example|test|mock|fixture|sample)", re.IGNORECASE),
        "message": (
            "[SEAL] WARNING: JWT token detected in file content.\n"
            "Tokens should be stored in environment variables or secure storage, not in source files.\n"
            "Ref: SEAL Framework > Operational Security > Account Management"
        ),
        "block": False,
    },
    # --- SSH Private Keys ---
    {
        "name": "ssh_private_key",
        "pattern": re.compile(r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----"),
        "exclude": None,
        "message": (
            "[SEAL] BLOCKED: SSH private key detected.\n"
            "Never write private keys to source files. Use ~/.ssh/ with proper permissions (600).\n"
            "Ref: SEAL Framework > Infrastructure > Registrar Security"
        ),
        "block": True,
    },
    # --- PGP/GPG Private Keys ---
    {
        "name": "pgp_private_key",
        "pattern": re.compile(r"-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----"),
        "exclude": None,
        "message": (
            "[SEAL] BLOCKED: PGP/GPG private key detected.\n"
            "Private keys must never be stored in source files.\n"
            "Ref: SEAL Framework > DevSecOps > Code Signing"
        ),
        "block": True,
    },
    # --- Database connection strings with passwords ---
    {
        "name": "db_connection_string",
        "pattern": re.compile(
            r"(?i)(mongodb|postgres|mysql|redis|amqp|sqlite)://[^:]+:[^@\s]+@"
        ),
        "exclude": re.compile(
            r"(localhost|127\.0\.0\.1|example\.com|test|mock|fake|placeholder|username:password)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] WARNING: Database connection string with embedded password detected.\n"
            "Use environment variables for connection strings. Never hardcode database credentials.\n"
            "Ref: SEAL Framework > DevSecOps > Data Security"
        ),
        "block": False,
    },
    # --- Slack/Discord webhook URLs ---
    {
        "name": "webhook_url",
        "pattern": re.compile(
            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"
            r"|https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+"
        ),
        "exclude": re.compile(r"(example|test|placeholder|YOUR_)", re.IGNORECASE),
        "message": (
            "[SEAL] WARNING: Webhook URL detected.\n"
            "Webhook URLs are secrets — store them in environment variables.\n"
            "Ref: SEAL Framework > Operational Security > Account Management"
        ),
        "block": False,
    },
    # --- Infura/Alchemy API keys in URLs ---
    {
        "name": "rpc_api_key",
        "pattern": re.compile(
            r"https://(mainnet|goerli|sepolia)\.(infura\.io|alchemy\.com)/v[0-9]+/[a-zA-Z0-9]{20,}"
        ),
        "exclude": re.compile(r"(example|test|YOUR_|placeholder)", re.IGNORECASE),
        "message": (
            "[SEAL] WARNING: RPC provider URL with embedded API key detected.\n"
            "Use environment variables for RPC URLs. Exposed keys can be rate-limited or abused.\n"
            "Ref: SEAL Framework > Supply Chain Security > Vendor Risk Management"
        ),
        "block": False,
    },
]


def is_env_file(file_path):
    """Check if file is an expected secrets file (.env, .env.local, etc.)."""
    basename = os.path.basename(file_path)
    return basename.startswith(".env") or basename in (
        "credentials", "secrets.yaml", "secrets.yml", "secrets.json"
    )


def extract_content(tool_name, tool_input):
    """Extract the content being written from the tool input."""
    if tool_name == "Write":
        return tool_input.get("content", "")
    elif tool_name == "Edit":
        return tool_input.get("new_string", "")
    return ""


def _matched_line(content, index):
    """Return the line of `content` that contains the character at `index`."""
    start = content.rfind("\n", 0, index) + 1
    end = content.find("\n", index)
    return content[start:] if end == -1 else content[start:end]


def scan_content(content, file_path):
    """Scan content against all patterns. Returns (rule_name, message, should_block) or (None, None, False)."""
    for rule in PATTERNS:
        pattern = rule["pattern"]
        exclude = rule.get("exclude")
        value_exclude = rule.get("value_exclude")
        validate = rule.get("validate")
        # Search EVERY match, not just the first: a suppressed match (allowlist /
        # exclude / value_exclude / validate) must not skip the whole rule, or a
        # later real secret of the same type would bypass the scanner.
        pos = 0
        while True:
            match = pattern.search(content, pos)
            if match is None:
                break
            # By default skip past this match; a *validate* failure instead retries
            # OVERLAPPING, because a real candidate can start inside a greedy match
            # that failed validation (e.g. a seed phrase preceded by junk words).
            next_pos = match.end()
            suppressed = True

            # Explicit per-line allowlist: a `seal-allow-secret` marker on the
            # matched line suppresses THIS match (for known-fake test fixtures).
            if ALLOWLIST_MARKER in _matched_line(content, match.start()):
                pass
            # Exclude check: a +-100 char window of context. This intentionally
            # crosses line boundaries so a label on the line above (sha256:\n<hex>)
            # still suppresses a checksum/lockfile false positive. Best effort, not
            # a security boundary — use the line-bound `seal-allow-secret` marker
            # for guaranteed allowlisting.
            elif exclude and exclude.search(
                content, max(0, match.start() - 100), min(len(content), match.end() + 100)
            ):
                pass
            # For API assignments, placeholder words only suppress the match when
            # the complete quoted value is a placeholder form.
            elif value_exclude and value_exclude.fullmatch(
                match.groupdict().get("quoted_value") or match.group(0)
            ):
                pass
            # Semantic validation (e.g. confirm a candidate mnemonic is really BIP39
            # words); on failure, retry overlapping for a real candidate inside it.
            elif validate and not validate(match.group(0)):
                next_pos = match.start() + 1
            else:
                suppressed = False

            if not suppressed:
                return rule["name"], rule["message"], rule["block"]
            pos = next_pos if next_pos > pos else pos + 1

    return None, None, False


def main():
    """Main hook entry point."""
    data = read_hook_input(DEBUG_LOG)

    session_id = data.get("session_id", "default")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})  # read_hook_input guarantees a dict

    if tool_name not in ("Write", "Edit"):
        sys.exit(0)

    file_path = tool_input.get("file_path", "")
    content = extract_content(tool_name, tool_input)

    if not content:
        sys.exit(0)

    debug_log(f"Scanning {tool_name} on {file_path} ({len(content)} chars)", DEBUG_LOG)

    rule_name, message, should_block = scan_content(content, file_path)

    if rule_name:
        # For .env files: always warn but never block (they're supposed to have secrets)
        if is_env_file(file_path):
            message = message.replace("BLOCKED", "NOTE (env file)")
            should_block = False

        # A blocking secret must be blocked on EVERY write. Enforcement must never
        # sit behind the once-per-session dedup, or a later same-rule write to the
        # same file (the dedup key is rule:file_path) would slip through.
        if should_block:
            print(message, file=sys.stderr)
            debug_log(f"BLOCKED: {rule_name} in {file_path}", DEBUG_LOG)
            sys.exit(2)

        # Warning (incl. the .env note): show once per session, then allow.
        warning_key = f"{rule_name}:{file_path}"
        shown = load_shown(session_id, STATE_PREFIX)
        if warning_key not in shown:
            shown.add(warning_key)
            save_shown(session_id, STATE_PREFIX, shown, DEBUG_LOG)
            print(message, file=sys.stderr)
            debug_log(f"WARNED: {rule_name} in {file_path}", DEBUG_LOG)

    sys.exit(0)


if __name__ == "__main__":
    main()
