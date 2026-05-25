#!/usr/bin/env python3
"""
SEAL Security Guard Hook — PreToolUse for Bash
Catches dangerous shell commands based on SEAL framework principles:
- Pipe-to-shell execution (curl|sh, wget|bash)
- Overly permissive file permissions (chmod 777)
- Force pushes to protected branches
- Secret/credential exposure
- Untrusted package installation
- Sudo abuse
- Dangerous git operations
- Insecure network operations
"""

import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import debug_log, get_state_file, load_shown, save_shown

# Log file for debugging hook behavior
DEBUG_LOG = "/tmp/seal-security-guard.log"
STATE_PREFIX = "seal_guard_state"

# State file tracks which warnings have been shown per session
# so we don't nag repeatedly for the same pattern in one session


# Each rule: (name, compiled regex or check function, message)
# Rules are checked in order; first match wins.

RULES = [
    # --- Pipe-to-shell: remote code execution ---
    {
        "name": "pipe_to_shell",
        "pattern": re.compile(
            r"(curl|wget|fetch)\s+.*\|\s*(sh|bash|zsh|python|python3|node|ruby|perl)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] BLOCKED: Pipe-to-shell detected (curl/wget piped to interpreter).\n"
            "This is a top supply chain attack vector. Download first, inspect, then execute.\n"
            "Ref: SEAL Framework > Supply Chain Security > Dependency Awareness"
        ),
    },
    # --- chmod 777 / overly permissive ---
    {
        "name": "chmod_777",
        "pattern": re.compile(r"chmod\s+(-[a-zA-Z]+\s+)*777\b"),
        "message": (
            "[SEAL] BLOCKED: chmod 777 grants read/write/execute to everyone.\n"
            "Use least-privilege permissions: chmod 755 for dirs, 644 for files, 600 for secrets.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation & Sandboxing > Least Privilege"
        ),
    },
    # --- chmod world-writable ---
    {
        "name": "chmod_world_writable",
        "pattern": re.compile(r"chmod\s+(-[a-zA-Z]+\s+)*o\+w\b"),
        "message": (
            "[SEAL] BLOCKED: Making files world-writable violates least-privilege.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation"
        ),
    },
    # --- Force push to main/master ---
    {
        "name": "force_push_main",
        "pattern": re.compile(
            r"git\s+push\s+.*--force(-with-lease)?\s+.*(main|master)\b"
            r"|git\s+push\s+.*--force(-with-lease)?\s*$"
            r"|git\s+push\s+-f\s+.*(main|master)\b",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] BLOCKED: Force push detected (potentially to main/master).\n"
            "Force pushes can destroy commit history and bypass branch protection.\n"
            "Ref: SEAL Framework > DevSecOps > Repository Hardening — block force pushes to protected branches"
        ),
    },
    # --- git reset --hard (destructive) ---
    {
        "name": "git_reset_hard",
        "pattern": re.compile(r"git\s+reset\s+--hard"),
        "message": (
            "[SEAL] WARNING: git reset --hard discards all uncommitted changes permanently.\n"
            "Consider git stash or git reset --soft instead.\n"
            "Ref: SEAL Framework > DevSecOps > Repository Hardening"
        ),
    },
    # --- Expose secrets via env/printenv ---
    {
        "name": "expose_env",
        "pattern": re.compile(r"\b(printenv|env\b(?!\s+\S+=))(?!.*grep)"),
        "message": (
            "[SEAL] WARNING: Dumping full environment may expose secrets (API keys, tokens, credentials).\n"
            "Use `echo $SPECIFIC_VAR` to check individual variables instead.\n"
            "Ref: SEAL Framework > DevSecOps > Securing Development Environments"
        ),
    },
    # --- Cat/read sensitive credential files ---
    {
        "name": "read_secrets",
        "pattern": re.compile(
            r"(cat|less|more|head|tail|bat)\s+.*"
            r"(\.env\b|\.env\.|credentials|secret|private[_-]?key|\.pem\b|\.key\b"
            r"|seed\.txt|mnemonic|keystore|\.p12\b|\.pfx\b|id_rsa\b|id_ed25519\b)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] WARNING: Reading potential credential/secret file.\n"
            "Ensure this file is .gitignored and contents are not logged or exposed.\n"
            "Ref: SEAL Framework > Operational Security > Account Management"
        ),
    },
    # --- npm install without frozen lockfile (in CI-like context) ---
    {
        "name": "npm_install_unfrozen",
        "pattern": re.compile(r"\bnpm\s+install\b(?!.*--ignore-scripts)(?!.*--frozen)"),
        "message": (
            "[SEAL] WARNING: `npm install` without --ignore-scripts may execute arbitrary install scripts.\n"
            "For untrusted packages, use `npm ci` (frozen lockfile) or add --ignore-scripts.\n"
            "Ref: SEAL Framework > Supply Chain Security > Install Scripts"
        ),
    },
    # --- Installing from raw GitHub URL ---
    {
        "name": "install_github_url",
        "pattern": re.compile(
            r"(npm\s+install|pip\s+install|go\s+install)\s+.*github\.com/",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] WARNING: Installing directly from GitHub URL bypasses registry integrity checks.\n"
            "Prefer installing from official registries with pinned versions.\n"
            "Ref: SEAL Framework > Supply Chain Security > Dependency Awareness"
        ),
    },
    # --- sudo with sensitive operations ---
    {
        "name": "sudo_sensitive",
        "pattern": re.compile(
            r"sudo\s+.*(rm\s+-rf|chmod|chown|mv\s+/|cp\s+/|dd\s+|mkfs|fdisk|iptables|systemctl)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] WARNING: sudo with destructive/system-level command detected.\n"
            "Verify this is intentional and follows principle of least privilege.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation > Least Privilege"
        ),
    },
    # --- rm -rf with dangerous targets ---
    {
        "name": "rm_rf_dangerous",
        "pattern": re.compile(
            r"rm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+|.*-rf\s+|.*-fr\s+)"
            r"(/\s|/\*|~|/usr|/etc|/var|/home|/System|\$HOME/?\s|/root)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] BLOCKED: rm -rf targeting system/home directory.\n"
            "This could cause catastrophic data loss. Double-check the target path.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation"
        ),
    },
    # --- Disable SSL verification ---
    {
        "name": "disable_ssl",
        "pattern": re.compile(
            r"(--insecure|-k\b|--no-check-certificate|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"
            r"|PYTHONHTTPSVERIFY\s*=\s*0|verify\s*=\s*False)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] WARNING: SSL/TLS verification is being disabled.\n"
            "This enables MITM attacks. Only use in controlled dev environments, never in production.\n"
            "Ref: SEAL Framework > Infrastructure > Domain & DNS Security"
        ),
    },
    # --- Expose private keys via echo/cat ---
    {
        "name": "expose_private_key",
        "pattern": re.compile(
            r"(echo|printf|cat)\s+.*"
            r"(PRIVATE_KEY|SECRET_KEY|API_KEY|API_SECRET|MNEMONIC|SEED_PHRASE|SESSION_TOKEN)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] BLOCKED: Potential secret exposure via echo/print.\n"
            "Never print secrets to stdout — they may be captured in logs.\n"
            "Ref: SEAL Framework > Wallet Security > Seed Phrase Management — PROHIBITED: digital exposure"
        ),
    },
    # --- git clone from untrusted/unknown source ---
    {
        "name": "git_clone_warning",
        "pattern": re.compile(r"git\s+clone\s+(?!.*(github\.com|gitlab\.com|bitbucket\.org))"),
        "message": (
            "[SEAL] WARNING: Cloning from non-standard git host.\n"
            "Verify the repository source is trusted before cloning.\n"
            "Ref: SEAL Framework > Supply Chain Security > Dependency Awareness"
        ),
    },
    # --- Docker run with privileged or host network ---
    {
        "name": "docker_privileged",
        "pattern": re.compile(
            r"docker\s+run\s+.*(--privileged|--net=host|--network=host|-v\s+/:/)",
            re.IGNORECASE,
        ),
        "message": (
            "[SEAL] WARNING: Docker container with elevated privileges or host access.\n"
            "--privileged disables all container isolation. --net=host shares the host network stack.\n"
            "Mounting / gives full filesystem access. Use minimal, scoped permissions.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation — no --privileged, capability drops required"
        ),
    },
    # --- SSH with no host key checking ---
    {
        "name": "ssh_no_host_check",
        "pattern": re.compile(r"StrictHostKeyChecking\s*=\s*no", re.IGNORECASE),
        "message": (
            "[SEAL] WARNING: SSH host key verification disabled — vulnerable to MITM.\n"
            "Accept and pin host keys properly instead of disabling verification.\n"
            "Ref: SEAL Framework > Infrastructure"
        ),
    },
]


def check_command(command):
    """Check a Bash command against all security rules. Returns (rule_name, message) or (None, None)."""
    for rule in RULES:
        if rule["pattern"].search(command):
            return rule["name"], rule["message"]
    return None, None


def main():
    """Main hook entry point. Reads tool input from stdin, checks against rules."""
    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        debug_log(f"JSON parse error: {e}", DEBUG_LOG)
        sys.exit(0)  # allow on parse failure

    session_id = data.get("session_id", "default")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # Only process Bash tool calls
    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    debug_log(f"Checking command: {command[:200]}", DEBUG_LOG)

    rule_name, message = check_command(command)

    if rule_name and message:
        # Dedup: only show each rule+command combo once per session
        warning_key = f"{rule_name}:{hashlib.sha256(command.encode('utf-8')).hexdigest()}"
        shown = load_shown(session_id, STATE_PREFIX)

        if warning_key not in shown:
            shown.add(warning_key)
            save_shown(session_id, STATE_PREFIX, shown, DEBUG_LOG)

            print(message, file=sys.stderr)
            debug_log(f"BLOCKED: {rule_name} — {command[:100]}", DEBUG_LOG)

            # Exit 2 = block for BLOCKED rules, 0 = warn-only for WARNING rules
            if "BLOCKED" in message:
                sys.exit(2)
            else:
                # Warnings: show message but allow execution
                sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
