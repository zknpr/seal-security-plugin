# SEAL Security Plugin Maintainer Guide

## Supported Clients

This repository ships one shared implementation for Claude Code and Codex CLI:

- `.claude-plugin/plugin.json` is the Claude package manifest.
- `.codex-plugin/plugin.json` is the Codex package manifest and points to `./skills/`.
- `.agents/plugins/marketplace.json` makes the repository itself a Codex marketplace and must keep `source.path` set to `./`.
- `hooks/hooks.json`, `hooks/*.py`, and `skills/` are shared assets. Do not fork their behavior by client unless the clients expose irreconcilable protocol differences.

The Claude and Codex manifest versions must remain synchronized. The current shared release is `1.1.0`.

## Hook State Machine

The hook lifecycle is security-sensitive core logic. Preserve this state machine whenever it changes:

1. `read_hook_input()` parses one JSON object from standard input. Invalid JSON and non-object top-level values exit successfully without enforcement; non-object `tool_input` values are normalized to an empty object. Hook code must not crash on malformed input.
2. `security_guard.py` handles the shared `Bash` payload and scans `tool_input.command` without executing it.
3. `secret_scanner.py` normalizes client-specific file edits into ordered `(file_path, content)` targets:
   - Claude `Write/Edit` payloads scan `content` or `new_string` for the supplied `file_path`.
   - Codex `apply_patch` payloads parse `tool_input.command`, group added lines by destination file, honor `Move to` destinations, and ignore removed lines and unchanged context.
   - Added lines outside a recognized file section use the neutral `<apply_patch>` path so malformed-but-readable additions are still scanned without resolving or opening an input-controlled path.
4. Every normalized target is scanned in patch order. A clean first target must never suppress a finding in a later target.
5. Blocking findings write a diagnostic to standard error and return exit status 2 on every occurrence. Blocking decisions never depend on warning-dedup state.
6. Findings in expected secret containers such as `.env.local` are downgraded to a non-blocking note.
7. Other warnings are keyed by rule and destination, then shown once per session. State write failures are explicit in debug logs but must not disable enforcement.
8. A `seal-allow-secret` marker suppresses only a match on that same added line.

Codex hook matchers expose the canonical file edit as `tool_name: "apply_patch"`, even though `hooks/hooks.json` uses the compatibility matcher alias `Edit|Write`. Codex also provides `CLAUDE_PLUGIN_ROOT` and `CLAUDE_PLUGIN_DATA` compatibility variables for shared plugins.

## Storage and Logging

Plugin data selection follows this precedence: `PLUGIN_DATA`, then `CLAUDE_PLUGIN_DATA`, then the legacy `~/.claude` fallback. Session identifiers are sanitized before becoming state filenames.

Debug logging is disabled unless `SEAL_DEBUG` is truthy. Logs contain rule names, target paths, command categories, and content lengths; never add matched secret values or full file contents to logs.

## Security Boundaries

These hooks are defense in depth. Codex `PreToolUse` does not intercept every file write that an arbitrary shell command or external program can perform. Maintain independent pre-commit and CI secret scanning, branch protection, and credential controls.

Never open, resolve, or read a path extracted from a hook payload. Scan only the content already supplied by the client. Keep parser inputs type-checked and preserve explicit error handling.

## Required Verification

Use the repository virtual environment when available:

```bash
python -m pytest -q
python3 ~/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
python -m json.tool .claude-plugin/plugin.json >/dev/null
python -m json.tool .codex-plugin/plugin.json >/dev/null
python -m json.tool .agents/plugins/marketplace.json >/dev/null
python -m json.tool hooks/hooks.json >/dev/null
```

Tests must cover every behavior change before implementation, including malformed inputs, multi-target patches, deletion-only cleanup, environment-file downgrades, warning deduplication, and blocking exit status. Code comments must explain the factual behavior and security invariant they protect, not the author's reasoning process.
