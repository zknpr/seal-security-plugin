# Codex CLI Full-Parity Design

**Date:** 2026-07-15
**Status:** Approved architecture; implementation pending written-spec review

## Context

SEAL Security is currently packaged for Claude Code. It provides two reusable
security skills plus two `PreToolUse` hooks:

- `security-guard` checks shell commands and blocks dangerous operations.
- `secret-scanner` checks file writes and edits for credentials and other
  sensitive material.

Codex CLI 0.144.4 supports plugin manifests, skills, and plugin-bundled
`PreToolUse` hooks. Its Bash hook payload is compatible with the existing shell
guard. Its file-edit payload differs: Claude reports `Write` or `Edit` with
dedicated content fields, while Codex reports `apply_patch` with the patch text
in `tool_input.command`.

## Goals

1. Preserve the existing Claude Code installation and behavior.
2. Package the same skills and hooks as a native Codex plugin.
3. Make skill instructions portable by removing runtime dependencies on
   Claude-only absolute paths.
4. Give Codex file edits the same secret-detection coverage as Claude file
   writes and edits, within Codex's supported hook surface.
5. Install the plugin in the existing personal `zero-local` Codex marketplace.
6. Verify both client payload shapes, plugin metadata, installation state, and
   the complete existing Python test suite.

## Non-goals

- Replacing Codex's sandbox, approvals, or command rules.
- Claiming the hooks form a complete security boundary. Codex currently notes
  that `PreToolUse` interception does not cover every shell execution path.
- Adding MCP servers, apps, connectors, network services, or new detection
  rules.
- Removing or renaming the existing Claude plugin manifest.
- Publishing the plugin to a remote marketplace as part of this change.

## Chosen Approach

Use one shared implementation with a small client-compatibility boundary.
Claude and Codex payloads will be converted into the same internal collection
of `(file_path, added_content)` scan targets before the existing detection
rules run.

This avoids separate Codex scanner processes or duplicated rule sets. A single
security fix will continue to protect both clients.

## Package Layout

The repository will retain its Claude package and add a Codex manifest:

```text
.claude-plugin/plugin.json       Claude Code manifest
.codex-plugin/plugin.json        Codex plugin manifest
hooks/hooks.json                 Shared lifecycle-hook configuration
hooks/security_guard.py          Shared Bash command guard
hooks/secret_scanner.py          Shared secret scanner and payload adapter
hooks/utils.py                   Shared input, state, and data-path helpers
skills/                          Shared Codex/Claude skills
tests/                           Cross-client regression tests
AGENTS.md                        Hook compatibility state-machine notes
```

The Codex manifest will declare name `seal-security`, version `1.1.0`, the
existing `./skills/` directory, and interface metadata identifying the plugin
as **SEAL Security**, developed by **zero**, in the **Security** category with
read/write capabilities. It will omit apps and MCP fields because the plugin
contains neither. It will rely on Codex's default discovery of
`hooks/hooks.json`, avoiding a second hook configuration.

The Claude manifest will also move to version `1.1.0`, keeping both packages on
one release version. Adding Codex support is a backward-compatible feature, so
a minor version increment is appropriate.

## Skill Portability

The current skill instructions contain two Claude-specific dependencies:

- `${CLAUDE_PLUGIN_ROOT}/skills/security-guidance/references/`
- `~/.claude/seal-security-framework.md`

The first will become the skill-relative `references/` directory. The second
is not part of this plugin and will be removed. General reviews will select all
relevant bundled references instead of depending on an external home-directory
file.

`security-checklist` is self-contained for quick checks. When deeper context is
needed, it will direct the agent to the bundled sibling directory
`../security-guidance/references/`. No skill instruction may require a Claude-
or Codex-specific home path. The shared hook configuration is the deliberate
exception because Codex supplies `CLAUDE_PLUGIN_ROOT` specifically for hook
compatibility.

## Hook Compatibility

### Bash guard

Both clients report shell hooks as `tool_name: "Bash"` with the command at
`tool_input.command`. The existing guard and its exit-code-2 blocking contract
will remain unchanged.

The shared hook configuration currently invokes scripts through
`CLAUDE_PLUGIN_ROOT`. Codex intentionally provides that variable for existing
plugin-hook compatibility, so the same command remains valid in both clients.

### Secret scanner

The scanner will expose one target-extraction function with these transitions:

| Input state | Accepted payload | Result |
|---|---|---|
| Claude write | `tool_name == "Write"` and string `content` | One target containing the complete new file content |
| Claude edit | `tool_name == "Edit"` and string `new_string` | One target containing only replacement content |
| Codex patch | `tool_name == "apply_patch"` and string `command` | Zero or more targets containing only added patch lines |
| Unsupported or malformed input | Any other shape | No target; preserve the existing never-crash behavior |

The Codex patch parser will recognize `*** Add File:`, `*** Update File:`,
`*** Delete File:`, and `*** Move to:` sections. It will buffer one file section
at a time so a `*** Move to:` marker sets the destination for every addition in
that section, regardless of where the move marker appears. It will:

1. Track the current destination path.
2. Ignore deleted and unchanged context lines.
3. Strip exactly one patch prefix from added lines and retain the remaining
   content verbatim.
4. Group added lines by destination file so path-sensitive behavior such as
   `.env` warning-only handling remains correct.
5. Scan additions under a neutral `<apply_patch>` target if added lines exist
   but a usable file marker cannot be recovered. This avoids silently skipping
   plausible secret additions in an otherwise unexpected patch shape.
6. Produce no scan target for a deletion-only patch, allowing users to remove
   existing secrets.

A patch that affects multiple files will scan every resulting target. Any
blocking finding exits with status 2 before the edit runs. Warning findings
retain the existing once-per-session, per-file deduplication semantics.

The parser will not open target files or resolve paths. Paths are untrusted
labels used only for policy selection and warning messages, which avoids
introducing filesystem traversal or time-of-check/time-of-use behavior.

## State and Debug Data

Runtime data will use the first available directory in this order:

1. `PLUGIN_DATA`, supplied by Codex plugin execution.
2. `CLAUDE_PLUGIN_DATA`, when supplied by the host client.
3. The existing `~/.claude` fallback for backward compatibility.

State and debug files will remain owner-only. Session identifiers will continue
to be sanitized before they become filenames. Failure to read or persist
warning-deduplication state will not disable blocking checks; the scanner may
repeat a warning, but enforcement still runs. Debug output remains opt-in via
`SEAL_DEBUG=1` and must not include detected secret values.

## Failure Handling

- Invalid JSON, non-object hook input, and non-object `tool_input` retain the
  current explicit fail-open, never-crash behavior.
- A non-string Codex patch command produces no target rather than raising a
  type error.
- Recognized added lines without a recoverable path are scanned using the
  neutral target instead of being discarded.
- State-file I/O failures are reported only through opt-in debug logging.
- Blocking findings remain fail-closed through exit status 2 and a sanitized
  reason on standard error.
- No hook may print the matched secret itself.

## Documentation

`README.md` will become client-neutral and include:

- Claude Code installation.
- Codex plugin installation from the local marketplace.
- The required Codex `/hooks` review-and-trust step.
- Which features are shared and how Codex `apply_patch` is scanned.
- An explicit warning that hooks are defense in depth and inherit each
  client's hook coverage limitations.

`AGENTS.md` will document the cross-client hook state machine, test command,
version synchronization requirement, and the invariant that only newly added
patch content is scanned. It will contain project-specific facts only.

## Local Codex Installation

After repository validation:

1. Expose this repository as the `seal-security` source in the existing
   personal `zero-local` marketplace without overwriting unrelated entries.
2. Use the supported Codex plugin update/install flow so Codex creates its
   cache entry and enablement state.
3. Confirm `seal-security@zero-local` appears installed and enabled.
4. Confirm the cached plugin contains the Codex manifest, shared skills, hooks,
   scanner data, and updated documentation.
5. Leave hook trust to Codex's explicit `/hooks` review flow; installation alone
   must not be reported as active hook enforcement until the hook is trusted.

## Test Strategy

Implementation will follow red-green-refactor. Tests will be written and
observed failing before production changes.

### Unit and integration coverage

- Claude `Write` extraction remains unchanged.
- Claude `Edit` extraction remains unchanged.
- Codex `apply_patch` extracts added content for updated and added files.
- Removed secret text is not scanned and does not block its own deletion.
- Multiple-file patches preserve each file path and scan all additions.
- Move destinations use the destination path.
- Added content without a recoverable path is still scanned.
- Non-string and malformed patch inputs do not crash.
- Existing `seal-allow-secret` behavior works in added patch lines.
- `.env` additions warn rather than block under the existing policy.
- A Codex patch containing a blocking secret exits with status 2.
- Codex plugin data paths take precedence without changing Claude fallback
  behavior.
- Claude and Codex manifest versions stay synchronized.
- Skill instructions contain no client-specific absolute path; the shared hook
  root variable remains the documented compatibility exception.

### Verification commands

The final implementation plan will resolve exact command syntax, but completion
requires fresh evidence from all of these classes:

1. Focused red-green pytest runs for each new behavior.
2. The complete repository test suite.
3. Codex plugin-manifest validation.
4. JSON parsing/structural checks for both manifests and hook configuration.
5. Direct hook invocations using representative Claude and Codex payloads.
6. `codex plugin list` confirmation after local installation.
7. `git diff --check`, `git status --short`, and a changed-file review.

## Success Criteria

The work is complete only when:

- Claude Code behavior remains covered by passing tests.
- Codex loads the same two skills from a valid native manifest.
- Both skills resolve all deep guidance from bundled, plugin-relative files.
- Codex Bash payloads use the existing guard.
- Codex file patches scan only newly added content across all affected files.
- A representative Codex patch secret is blocked and a deletion-only patch is
  allowed.
- Both manifests report version `1.1.0`.
- The plugin is listed as installed and enabled in `zero-local`.
- The README explains installation, hook trust, and enforcement limitations.
- No unrelated repository or personal-marketplace entries are changed.
