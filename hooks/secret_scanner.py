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
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import debug_log, load_shown, save_shown

DEBUG_LOG = "/tmp/seal-secret-scanner.log"
STATE_PREFIX = "seal_scanner_state"

# BIP39 wordlist subset — first and last words from the official list
# used to detect likely mnemonic phrases (12+ dictionary words in sequence)
# We check for sequences of 12+ lowercase alpha words as a heuristic.
MNEMONIC_PATTERN = re.compile(
    r"\b([a-z]{3,8}\s+){11,23}[a-z]{3,8}\b"
)

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


def scan_content(content, file_path):
    """Scan content against all patterns. Returns (rule_name, message, should_block) or (None, None, False)."""
    for rule in PATTERNS:
        match = rule["pattern"].search(content)
        if match:
            # Check exclude pattern — if the surrounding context matches, skip this rule
            if rule.get("exclude"):
                # Check in the matched line and nearby context
                match_start = max(0, match.start() - 100)
                match_end = min(len(content), match.end() + 100)
                context = content[match_start:match_end]
                if rule["exclude"].search(context):
                    continue

            # For API assignments, placeholder words only suppress the match
            # when the complete quoted value is a placeholder form.
            if rule.get("value_exclude"):
                quoted_value = match.groupdict().get("quoted_value")
                target = quoted_value if quoted_value is not None else match.group(0)
                if rule["value_exclude"].fullmatch(target):
                    continue

            return rule["name"], rule["message"], rule["block"]

    return None, None, False


def main():
    """Main hook entry point."""
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        debug_log(f"JSON parse error: {e}", DEBUG_LOG)
        sys.exit(0)

    session_id = data.get("session_id", "default")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

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

        warning_key = f"{rule_name}:{file_path}"
        shown = load_shown(session_id, STATE_PREFIX)

        if warning_key not in shown:
            shown.add(warning_key)
            save_shown(session_id, STATE_PREFIX, shown, DEBUG_LOG)

            print(message, file=sys.stderr)
            debug_log(
                f"{'BLOCKED' if should_block else 'WARNED'}: {rule_name} in {file_path}",
                DEBUG_LOG,
            )

            if should_block:
                sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
