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
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from utils import debug_log, load_shown, read_hook_input, save_shown

# Debug log (opt-in via SEAL_DEBUG). Kept under the user-owned ~/.claude dir
# rather than a predictable /tmp path, which in a world-writable directory is a
# symlink/info-disclosure risk (CWE-377).
DEBUG_LOG = os.path.expanduser("~/.claude/seal-security-guard.log")
STATE_PREFIX = "seal_guard_state"

# State file tracks which warnings have been shown per session
# so we don't nag repeatedly for the same pattern in one session


# A single (already separator-free) target token that names a filesystem or HOME
# root. Specific files/subdirs (~/Downloads, /tmp, ~/.config, $HOME/file) are NOT
# roots and are intentionally allowed; home/filesystem/system roots are blocked.
_RM_ROOT_TOKEN = re.compile(
    r"^(?:"
    r"/\*?$"                                          # the filesystem root: "/" or "/*"
    r"|/(?:usr|etc|var|home|System|root)(?![\w.-])"   # a system dir (then /, brace, glob, EOL ...)
    r"|~[\w]*/?$"                                      # "~", "~user", "~/"
    r"|~[\w]*/\*"                                      # "~/*"
    r"|~[\w]*/[^/]*[*?]"                               # first-segment home glob: ~/.* ~/.??* ~/foo*
    r"|\$HOME/?$"                                      # "$HOME", "$HOME/"
    r"|\$HOME/\*"                                      # "$HOME/*"
    r"|\$HOME/[^/]*[*?]"                               # "$HOME/<glob>"
    r")",
    re.IGNORECASE,
)

def _split_subcommands(command):
    """Split a command line into sub-commands on UNQUOTED shell separators.

    Quote-aware: a separator inside a quoted string (`printf 'a; rm -rf /'`) is
    NOT treated as a new command, so quoted/example text isn't a false positive.
    Backslash escapes are tracked when unquoted and inside double quotes, so an
    escaped quote (`printf "x \\"; rm -rf /"`) does not prematurely close the
    string and split harmless text into a fake `rm` subcommand. Single quotes are
    literal in the shell (no escapes inside them). Heredoc bodies are not tracked
    — see _is_dangerous_rm's documented limits.
    """
    subs, buf, quote = [], [], None
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if quote == "'":
            buf.append(c)
            if c == "'":
                quote = None
        elif quote == '"':
            if c == "\\" and i + 1 < n:
                buf.append(c)
                buf.append(command[i + 1])  # keep escaped char; an escaped " stays open
                i += 2
                continue
            buf.append(c)
            if c == '"':
                quote = None
        elif c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])       # escaped separator/quote is literal text
            i += 2
            continue
        elif c in ("'", '"'):
            quote = c
            buf.append(c)
        elif c in ";&|\n()":
            subs.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    subs.append("".join(buf))
    return subs


def _collapse_path(token):
    """Resolve `.`/`..` components in a path-like target (best effort).

    `~/Downloads/../*` (which Bash expands to the home root) is seen as `~/*`.
    Climbing back to a root keeps the root anchor rather than collapsing to an
    unmatched empty/`~/..` form: an absolute path that walks back to `/`
    (`/etc/..`, `/usr/../..`) stays `/`, and climbing ABOVE a leading ~, ~user or
    $HOME anchor (`~/../*`, `~/.cache/../../*`, `~/..`) escapes home to its parent
    (`/home`, or `/` for root) — still a destructive root — and re-anchors to `/`.
    Cannot climb above an absolute `/`.
    """
    if "/" not in token:
        return token
    out = []
    escaped_root = False
    for part in token.split("/"):
        if part == ".":
            continue
        if part == "..":
            if out and out[-1] not in ("", "..") and not out[-1].startswith(("~", "$")):
                out.pop()                       # pop a normal component
            elif out and out[-1].startswith(("~", "$")):
                out.pop()                       # climbing above home escapes to a root
                escaped_root = True
            # else: at/above an absolute root or stacked `..` — cannot climb higher
            continue
        out.append(part)
    rest = [p for p in out if p]                       # drop empty segments
    if escaped_root or token.startswith("/"):
        # An absolute path, or a climb that escaped a home anchor, anchors at the
        # filesystem root. Collapsing back to the root must stay "/" (not "") so
        # _RM_ROOT_TOKEN still matches: /etc/.. -> /, /usr/../.. -> /, ~/../* ->
        # /*, ~/.. -> /.
        return "/" + "/".join(rest)
    return "/".join(out)


def _normalize_rm_target(token):
    """Undo the common, literal shell wrappers around an rm target token.

    Handles surrounding quotes (`"/"`), `${HOME}` brace syntax, repeated leading
    slashes (`//`), and `.`/`..` path components. Deliberately does NOT resolve
    variables, command substitution, or glob/brace expansion — see
    _is_dangerous_rm's docstring.
    """
    token = token.replace('"', "").replace("'", "")  # quotes are shell syntax, not path
    token = token.replace("${HOME}", "$HOME")
    token = re.sub(r"^/{2,}", "/", token)
    token = _collapse_path(token)
    return token


def _shell_split(segment):
    """Split one sub-command into shell WORDS on unquoted whitespace.

    Quote- and escape-aware, and performs quote removal, so `FOO="a b" rm -rf /etc`
    tokenizes to ['FOO=a b', 'rm', '-rf', '/etc'] — the assignment stays one word
    and the following rm is still seen in command position — instead of
    str.split()'s ['FOO="a', 'b"', 'rm', ...], which hid the rm. Quoted targets
    keep their spaces and lose their quotes, mirroring how the shell builds argv.
    Not a full shell parser (no variable/glob expansion).
    """
    words, buf, quote, had = [], [], None, False
    i, n = 0, len(segment)
    while i < n:
        c = segment[i]
        if quote == "'":
            if c == "'":
                quote = None
            else:
                buf.append(c)
        elif quote == '"':
            # Inside double quotes Bash only treats \ as an escape before " \ $ `.
            if c == "\\" and i + 1 < n and segment[i + 1] in ('"', "\\", "$", "`"):
                buf.append(segment[i + 1])
                i += 2
                continue
            if c == '"':
                quote = None
            else:
                buf.append(c)
        elif c == "\\" and i + 1 < n:
            buf.append(segment[i + 1])            # unquoted escape -> literal next char
            i += 2
            continue
        elif c in ("'", '"'):
            quote = c
            had = True                            # an (even empty) quoted section is a word
        elif c.isspace():
            if had or buf:
                words.append("".join(buf))
                buf, had = [], False
        else:
            buf.append(c)
        i += 1
    if had or buf:
        words.append("".join(buf))
    return words


def _is_rm_word(word):
    """True if `word` invokes rm: rm, /bin/rm, or a backslash-escaped \\rm."""
    word = word.lstrip("\\")
    return word == "rm" or word.endswith("/rm")


_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_]\w*=")
# Launchers (`sudo rm`, `time rm`, `eval rm ...`) that can precede the real rm in
# one segment. `eval` only transparently covers its UNQUOTED form (`eval rm -rf
# /etc`); `eval "<string>"` re-parses a quoted string and stays a documented miss.
_RM_WRAPPERS = ("sudo", "doas", "env", "nice", "nohup", "command", "exec", "time", "eval")
# Shell reserved words / group openers that precede a command in the same segment:
# leading compound-command keywords (`if rm ...; then`, `while rm ...; do`,
# `until rm ...; do`) run their COMMANDS list before the construct resolves, the
# body keywords continue it, `{` opens a group, and `!` negates the next command's
# exit status — in every case the rm still executes.
_RM_PREFIX_KEYWORDS = ("if", "while", "until", "then", "do", "else", "elif", "{", "!")


def _rm_invocation_index(words):
    """Index of an rm in COMMAND position (else None).

    rm only counts when it is first, or follows known launchers / reserved words /
    `VAR=val` assignments — so `echo rm -rf /` (rm in argument position) is not
    treated as a delete, while `sudo rm`, `time rm`, and `if x; then rm` are.
    """
    i = 0
    while i < len(words):
        w = words[i]
        if _is_rm_word(w):
            return i
        if w in _RM_WRAPPERS or w in _RM_PREFIX_KEYWORDS or _ENV_ASSIGNMENT.match(w):
            i += 1
            continue
        return None
    return None


def _is_dangerous_rm(command):
    """True if `command` recursively force-deletes a filesystem/home root.

    A HEURISTIC for catching common and accidental destructive deletes, NOT a
    security boundary. It parses each sub-command's flags and targets, so shell
    separators, brace/split/long flags, `--`, quoted or `${HOME}` targets, and
    repeated slashes don't hide the target. It CANNOT see through — and will miss
    — forms that require evaluating the shell: variable indirection
    (`R=/; rm -rf $R`), command substitution, `bash -c "..."` / `eval "..."`
    string re-evaluation, indirect deletes
    (`... | xargs rm -rf`, `find / -exec rm -rf {} \\;`), glob/brace expansion
    that resolves to a root (`rm -rf /{etc,var}`, `/e?c`), launcher-specific
    options before the command (`sudo -u user rm ...`), and heredoc bodies.
    Specific files and subdirs under home are allowed; only roots are blocked.
    """
    for sub in _split_subcommands(command):
        words = _shell_split(sub)
        rm_at = _rm_invocation_index(words)
        if rm_at is None:
            continue
        recursive = force = options_ended = False
        targets = []
        for w in words[rm_at + 1:]:
            if not options_ended and w == "--":
                options_ended = True  # everything after `--` is an operand
            elif not options_ended and w.startswith("--") and len(w) > 2:
                # GNU rm accepts unambiguous abbreviations (--rec == --recursive),
                # but --recursive/--force take NO value: --force=no and --=x are
                # option errors that abort before deleting, so they must not set
                # the flags (an empty prefix would otherwise match every option).
                opt = w[2:]
                if opt and "=" not in opt:
                    recursive |= "recursive".startswith(opt)
                    force |= "force".startswith(opt)
            elif not options_ended and w.startswith("-") and len(w) > 1:
                recursive |= "r" in w or "R" in w
                force |= "f" in w
            else:
                targets.append(_normalize_rm_target(w))
        if recursive and force and any(_RM_ROOT_TOKEN.match(t) for t in targets):
            return True
    return False


# Each rule: name, a compiled `pattern` (or a `check` callable for non-regex
# logic), message, and an explicit `block` flag.
# block=True -> exit 2 (hard block); omitted/False -> exit 0 (warn-only).
# Enforcement reads this flag, never the message text, so re-wording a message
# can't change the security boundary. Rules are checked in order; a BLOCK match
# wins immediately, otherwise the first WARNING is returned (see check_command).

RULES = [
    # --- Pipe-to-shell: remote code execution ---
    {
        "name": "pipe_to_shell",
        "block": True,
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
        "block": True,
        "pattern": re.compile(r"chmod(?:\s+-[a-zA-Z]+)*\s+777\b"),
        "message": (
            "[SEAL] BLOCKED: chmod 777 grants read/write/execute to everyone.\n"
            "Use least-privilege permissions: chmod 755 for dirs, 644 for files, 600 for secrets.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation & Sandboxing > Least Privilege"
        ),
    },
    # --- chmod world-writable ---
    {
        "name": "chmod_world_writable",
        "block": True,
        "pattern": re.compile(r"chmod\s+(-[a-zA-Z]+\s+)*o\+w\b"),
        "message": (
            "[SEAL] BLOCKED: Making files world-writable violates least-privilege.\n"
            "Ref: SEAL Framework > DevSecOps > Isolation"
        ),
    },
    # --- Force push to main/master ---
    {
        "name": "force_push_main",
        "block": True,
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
        "block": True,
        # Parsed rather than regex-matched (see _is_dangerous_rm) so shell
        # separators, brace expansion, split/long flags and `--` can't hide the
        # target, while specific files/subdirs under home stay allowed.
        "check": _is_dangerous_rm,
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
        "block": True,
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
    """Check a Bash command against the rules.

    Returns (rule_name, message, block), else (None, None, False). A BLOCK rule
    always wins over a WARNING rule, so e.g. `sudo rm -rf /` (which also matches
    the sudo *warning*) is still hard-blocked rather than merely warned. `block`
    is the rule's explicit flag (default False); enforcement never depends on the
    message wording.
    """
    if not isinstance(command, str):
        return None, None, False  # never-crash: only string commands are scannable
    warning = None
    for rule in RULES:
        check = rule.get("check")
        pattern = rule.get("pattern")
        matched = check(command) if check else (pattern.search(command) if pattern else None)
        if not matched:
            continue
        if rule.get("block", False):
            return rule["name"], rule["message"], True  # a block beats any pending warning
        if warning is None:
            warning = (rule["name"], rule["message"], False)
    return warning if warning is not None else (None, None, False)


def main():
    """Main hook entry point. Reads tool input from stdin, checks against rules."""
    data = read_hook_input(DEBUG_LOG)

    session_id = data.get("session_id", "default")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})  # read_hook_input guarantees a dict

    # Only process Bash tool calls
    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    # A non-string command (list/number/null) must not crash the hook downstream.
    if not isinstance(command, str) or not command:
        sys.exit(0)

    # Log the length, never the command text: a command may carry a pasted
    # secret and the debug log is a durable plaintext file.
    debug_log(f"Checking command (length: {len(command)})", DEBUG_LOG)

    rule_name, message, should_block = check_command(command)

    if rule_name and message:
        # BLOCK rules must enforce on EVERY occurrence. Enforcement must never
        # sit behind the once-per-session dedup, or a dangerous command would be
        # allowed just by repeating it. Dedup applies only to WARNING text.
        if should_block:
            print(message, file=sys.stderr)
            debug_log(f"BLOCKED: {rule_name}", DEBUG_LOG)
            sys.exit(2)

        # Warning: show each rule+command combo once per session, then allow.
        warning_key = f"{rule_name}:{hashlib.sha256(command.encode('utf-8', errors='replace')).hexdigest()}"
        shown = load_shown(session_id, STATE_PREFIX)
        if warning_key not in shown:
            shown.add(warning_key)
            save_shown(session_id, STATE_PREFIX, shown, DEBUG_LOG)
            print(message, file=sys.stderr)
            debug_log(f"WARNED: {rule_name}", DEBUG_LOG)

    sys.exit(0)


if __name__ == "__main__":
    main()
