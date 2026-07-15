# Codex CLI Full-Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve Claude Code behavior while adding a native, locally installed Codex plugin with portable skills and equivalent supported lifecycle-hook behavior.

**Architecture:** One shared Python implementation accepts Claude `Write`/`Edit` payloads and Codex `apply_patch` payloads. A narrow target-extraction boundary converts them into `(file_path, added_content)` tuples, after which the existing detection rules and exit-code contract remain authoritative. Codex uses its own manifest and runtime data directory while sharing skills, hook configuration, and scanner assets with Claude.

**Tech Stack:** Python 3.11+, pytest 9.0.3, JSON plugin manifests, Claude/Codex `PreToolUse` hooks, Codex CLI 0.144.4.

## Global Constraints

- Preserve Claude Code installation and behavior.
- Use plugin version `1.1.0` in both committed manifests.
- Scan only newly added Codex patch content; never block deletion of an existing secret.
- Treat file paths as untrusted labels and never open target files from the hook.
- Keep hook parsing fail-open on malformed envelopes, but keep matched blocking rules fail-closed through exit status 2.
- Never print or persist matched secret values.
- Keep runtime dependencies stdlib-only.
- Do not add MCP servers, apps, connectors, network services, or new detection rules.
- Use `PLUGIN_DATA`, then `CLAUDE_PLUGIN_DATA`, then `~/.claude` for state and debug data.
- Preserve unrelated repository changes and unrelated personal-marketplace entries.
- Do not commit: the user has not authorized commits. Each task ends with a review checkpoint instead.

---

## File Map

- Create `.codex-plugin/plugin.json`: native Codex package metadata and shared skill discovery.
- Modify `.claude-plugin/plugin.json`: synchronize the release version.
- Modify `skills/security-guidance/SKILL.md`: use bundled, relative references.
- Modify `skills/security-checklist/SKILL.md`: remove the external Claude-home dependency.
- Modify `hooks/utils.py`: select the host-provided writable plugin-data directory.
- Modify `hooks/security_guard.py`: write debug data through the shared directory selector.
- Modify `hooks/secret_scanner.py`: extract scan targets from both client payloads and scan every target.
- Modify `tests/test_utils.py`: cover plugin-data precedence and fallback.
- Modify `tests/test_secret_scanner.py`: cover patch parsing and Codex hook integration.
- Create `tests/test_plugin_package.py`: validate manifests, skill portability, and cross-client documentation.
- Modify `README.md`: document both clients, installation, hook trust, and limitations.
- Create `AGENTS.md`: record the compatibility state machine and project invariants.
- Retain `hooks/hooks.json` unchanged: both hosts can use it, and Codex supplies `CLAUDE_PLUGIN_ROOT` for compatibility.

---

### Task 1: Codex Package and Portable Skills

**Files:**
- Create: `tests/test_plugin_package.py`
- Create: `.codex-plugin/plugin.json`
- Modify: `.claude-plugin/plugin.json:1-8`
- Modify: `skills/security-guidance/SKILL.md:10-30`
- Modify: `skills/security-checklist/SKILL.md:7-9`

**Interfaces:**
- Consumes: existing `skills/` and default `hooks/hooks.json` discovery.
- Produces: a validation-ready Codex manifest and skill instructions containing no client-specific absolute paths.

- [ ] **Step 1: Write the failing package tests**

Create `tests/test_plugin_package.py` with:

```python
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLAUDE_MANIFEST = ROOT / ".claude-plugin" / "plugin.json"
CODEX_MANIFEST = ROOT / ".codex-plugin" / "plugin.json"


def _load_json(path):
    """Load a repository JSON object so package assertions use real manifests."""
    return json.loads(path.read_text(encoding="utf-8"))


def test_codex_manifest_exposes_shared_skills_and_default_hooks():
    """Codex must discover the bundled skills and default lifecycle hook file."""
    manifest = _load_json(CODEX_MANIFEST)

    assert manifest["name"] == "seal-security"
    assert manifest["version"] == "1.1.0"
    assert manifest["skills"] == "./skills/"
    assert manifest["interface"]["displayName"] == "SEAL Security"
    assert manifest["interface"]["category"] == "Security"
    assert (ROOT / manifest["skills"]).is_dir()
    assert (ROOT / "hooks" / "hooks.json").is_file()
    assert "apps" not in manifest
    assert "mcpServers" not in manifest


def test_claude_and_codex_manifest_versions_stay_synchronized():
    """A release must not expose different versions to Claude and Codex."""
    claude = _load_json(CLAUDE_MANIFEST)
    codex = _load_json(CODEX_MANIFEST)

    assert claude["version"] == codex["version"] == "1.1.0"


def test_skill_instructions_use_only_bundled_relative_references():
    """Installed skills must not depend on either client's home directory."""
    skill_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "skills").glob("*/SKILL.md"))
    )

    assert "~/.claude" not in skill_text
    assert "${CLAUDE_PLUGIN_ROOT}" not in skill_text
    assert "references/" in skill_text
```

- [ ] **Step 2: Run the package tests and verify red**

Run:

```bash
.venv/bin/python -m pytest tests/test_plugin_package.py -q
```

Expected: three failures. The Codex manifest is missing, the manifest versions are not `1.1.0`, and both skill files still contain Claude-specific paths.

- [ ] **Step 3: Add the Codex manifest and synchronize versions**

Create `.codex-plugin/plugin.json`:

```json
{
  "name": "seal-security",
  "version": "1.1.0",
  "description": "SEAL-aligned Web3 security guidance with command guardrails and secret scanning.",
  "author": {
    "name": "zero",
    "url": "https://github.com/zknpr"
  },
  "homepage": "https://github.com/zknpr/seal-security-plugin#readme",
  "repository": "https://github.com/zknpr/seal-security-plugin",
  "license": "MIT",
  "keywords": [
    "web3",
    "security",
    "devsecops",
    "secret-scanning",
    "guardrails"
  ],
  "skills": "./skills/",
  "interface": {
    "displayName": "SEAL Security",
    "shortDescription": "Web3 security guidance and local guardrails",
    "longDescription": "SEAL-aligned skills and lifecycle hooks that guide security work, flag dangerous commands, and scan added file content for secrets.",
    "developerName": "zero",
    "category": "Security",
    "capabilities": [
      "Read",
      "Write"
    ],
    "defaultPrompt": [
      "Review this project using the SEAL security framework.",
      "Give me a hardening checklist for this service.",
      "Check this change for dangerous commands and secrets."
    ]
  }
}
```

Change `.claude-plugin/plugin.json` from version `1.0.7` to `1.1.0`. Do not alter its Claude-specific metadata shape.

- [ ] **Step 4: Replace Claude-only skill paths**

In `skills/security-guidance/SKILL.md`, replace the three-step “How to Use” block with:

```markdown
1. **Identify the security domain** from the user's context (infrastructure, wallets, DevSecOps, monitoring, incident response, supply chain, AI security)
2. **Read the relevant bundled reference file** from `references/` for deep details
3. **For cross-cutting reviews, read every relevant bundled reference** instead of relying on an external framework file
4. **Provide specific, prioritized recommendations** — not generic advice
5. **Flag critical violations immediately** using severity levels (P1-P5)
```

Replace the “General security review” decision-tree line with:

```text
└── General security review → Read every relevant file under references/
```

In `skills/security-checklist/SKILL.md`, replace the opening instruction with:

```markdown
Provide the specific checklist for the platform or service the user asks about. For deeper cross-cutting guidance, read the relevant bundled files under `../security-guidance/references/`, but deliver a focused, actionable checklist.
```

- [ ] **Step 5: Verify green and validate the plugin**

Run:

```bash
.venv/bin/python -m pytest tests/test_plugin_package.py -q
python3 /Users/zero/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```

Expected:

```text
3 passed
Plugin validation passed: /Users/zero/dev/seal-security-plugin
```

- [ ] **Step 6: Review checkpoint**

Run `git diff -- .codex-plugin/plugin.json .claude-plugin/plugin.json skills tests/test_plugin_package.py` and confirm only package portability changed. Do not commit.

---

### Task 2: Host-Specific Runtime Data Directory

**Files:**
- Modify: `tests/test_utils.py:1-36`
- Modify: `hooks/utils.py:13-120`
- Modify: `hooks/security_guard.py:20-27`
- Modify: `hooks/secret_scanner.py:27-34`

**Interfaces:**
- Produces: `get_plugin_data_dir() -> str`.
- Consumed by: `get_state_file()` and both hook `DEBUG_LOG` constants.

- [ ] **Step 1: Write failing data-directory tests**

Add `get_plugin_data_dir` to the import on `tests/test_utils.py:9`. Add an autouse fixture and these tests after `mock_expanduser`:

```python
@pytest.fixture(autouse=True)
def clear_plugin_data_environment(monkeypatch):
    """Keep host plugin-data variables from leaking into path-unit tests."""
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)


def test_plugin_data_dir_prefers_codex_directory(tmp_path, monkeypatch):
    """Codex's writable data directory has precedence when both hosts are set."""
    codex_dir = tmp_path / "codex-data"
    claude_dir = tmp_path / "claude-data"
    monkeypatch.setenv("PLUGIN_DATA", str(codex_dir))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(claude_dir))

    assert get_plugin_data_dir() == str(codex_dir)


def test_plugin_data_dir_uses_claude_directory_when_codex_is_absent(
    tmp_path, monkeypatch
):
    """Claude's writable plugin directory is the second supported host path."""
    claude_dir = tmp_path / "claude-data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(claude_dir))

    assert get_plugin_data_dir() == str(claude_dir)


def test_plugin_data_dir_falls_back_to_claude_home(mock_expanduser):
    """Older Claude installations retain the established home-directory path."""
    assert get_plugin_data_dir() == os.path.expanduser("~/.claude")


def test_state_file_uses_selected_plugin_data_directory(tmp_path, monkeypatch):
    """Warning state follows the host-selected writable data directory."""
    data_dir = tmp_path / "plugin-data"
    monkeypatch.setenv("PLUGIN_DATA", str(data_dir))

    assert get_state_file("abc/123", "seal") == str(
        data_dir / ".seal_abc_123.json"
    )
```

- [ ] **Step 2: Run the focused tests and verify red**

Run:

```bash
.venv/bin/python -m pytest tests/test_utils.py -q
```

Expected: collection fails because `get_plugin_data_dir` does not exist.

- [ ] **Step 3: Implement the directory selector**

Add this function above `get_state_file` in `hooks/utils.py`:

```python
def get_plugin_data_dir():
    """Return the current host's writable plugin-data directory.

    Codex provides PLUGIN_DATA and also compatibility variables. Native host
    variables take precedence so Codex state never leaks into ~/.claude.
    Older Claude installations that provide neither variable retain the
    historical ~/.claude location.
    """
    for variable in ("PLUGIN_DATA", "CLAUDE_PLUGIN_DATA"):
        value = os.environ.get(variable)
        if value:
            return os.path.abspath(os.path.expanduser(value))
    return os.path.expanduser("~/.claude")
```

Replace `get_state_file` with:

```python
def get_state_file(session_id, prefix):
    """Build a sanitized per-session state path in the host's data directory."""
    safe = _SAFE_SESSION_ID_RE.sub("_", str(session_id))
    filename = f".{prefix}_{safe}.json"
    return os.path.join(get_plugin_data_dir(), filename)
```

Update the comments on `save_shown` so they describe the host plugin-data directory rather than `~/.claude`.

- [ ] **Step 4: Route both debug logs through the selector**

Import `get_plugin_data_dir` in both hook modules and define:

```python
DEBUG_LOG = os.path.join(get_plugin_data_dir(), "seal-security-guard.log")
```

in `hooks/security_guard.py`, and:

```python
DEBUG_LOG = os.path.join(get_plugin_data_dir(), "seal-secret-scanner.log")
```

in `hooks/secret_scanner.py`. Update the adjacent factual comments to state that the host supplies the writable directory and files remain owner-only.

- [ ] **Step 5: Verify green and run affected suites**

Run:

```bash
.venv/bin/python -m pytest tests/test_utils.py tests/test_security_guard.py tests/test_secret_scanner.py -q
```

Expected: all selected tests pass with zero failures.

- [ ] **Step 6: Review checkpoint**

Run `git diff -- hooks/utils.py hooks/security_guard.py hooks/secret_scanner.py tests/test_utils.py`. Confirm state-file sanitization and `0o600` file handling remain intact. Do not commit.

---

### Task 3: Codex Apply-Patch Target Extraction

**Files:**
- Modify: `tests/test_secret_scanner.py:1-75`
- Modify: `hooks/secret_scanner.py:271-297`

**Interfaces:**
- Produces: `extract_patch_targets(command: object) -> list[tuple[str, str]]`.
- Produces: `extract_scan_targets(tool_name: str, tool_input: dict) -> list[tuple[str, str]]`.
- Preserves: `extract_content(tool_name, tool_input) -> object` for existing callers/tests.

- [ ] **Step 1: Write failing target-extraction tests**

Add `extract_patch_targets` and `extract_scan_targets` to the imports in `tests/test_secret_scanner.py`. Add:

```python
def test_extract_scan_targets_preserves_claude_payloads():
    """Claude Write/Edit payloads retain their current content semantics."""
    assert extract_scan_targets(
        "Write", {"file_path": "/repo/new.py", "content": "new file"}
    ) == [("/repo/new.py", "new file")]
    assert extract_scan_targets(
        "Edit", {"file_path": "/repo/app.py", "new_string": "replacement"}
    ) == [("/repo/app.py", "replacement")]


def test_extract_patch_targets_groups_added_lines_by_destination_file():
    """Codex additions are grouped per path while removals and context are ignored."""
    command = """*** Begin Patch
*** Update File: src/app.py
@@
-private_key = "removed"
+print("safe")
 unchanged
*** Add File: config/new.txt
+first
+second
*** End Patch"""

    assert extract_patch_targets(command) == [
        ("src/app.py", 'print("safe")'),
        ("config/new.txt", "first\nsecond"),
    ]


def test_extract_patch_targets_applies_move_destination_to_whole_section():
    """A move marker changes the path for additions buffered in that section."""
    command = """*** Begin Patch
*** Update File: old.txt
+moved content
*** Move to: new.txt
*** End Patch"""

    assert extract_patch_targets(command) == [("new.txt", "moved content")]


def test_extract_patch_targets_allows_deletion_only_patch():
    """Removed secrets are not rescanned and therefore cannot block cleanup."""
    command = """*** Begin Patch
*** Delete File: leaked.txt
-private_key = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
*** End Patch"""

    assert extract_patch_targets(command) == []


def test_extract_patch_targets_scans_orphan_additions_under_neutral_path():
    """Unexpected added lines still receive content scanning without path access."""
    assert extract_patch_targets("+api_key = secret") == [
        ("<apply_patch>", "api_key = secret")
    ]


@pytest.mark.parametrize("command", [None, 123, ["+secret"], {"command": "+secret"}])
def test_extract_patch_targets_handles_non_string_commands(command):
    """Malformed Codex command values preserve the hook's never-crash contract."""
    assert extract_patch_targets(command) == []
```

- [ ] **Step 2: Run target tests and verify red**

Run:

```bash
.venv/bin/python -m pytest tests/test_secret_scanner.py -k 'extract_patch_targets or extract_scan_targets_preserves' -q
```

Expected: collection fails because both new extraction functions are missing.

- [ ] **Step 3: Implement the patch parser**

Add these constants and functions after `extract_content` in `hooks/secret_scanner.py`:

```python
_PATCH_FILE_MARKER = re.compile(
    r"^\*\*\* (Add|Update|Delete) File:\s*(.*)$"
)
_PATCH_MOVE_MARKER = re.compile(r"^\*\*\* Move to:\s*(.*)$")
_NEUTRAL_PATCH_PATH = "<apply_patch>"


def _merge_patch_lines(grouped_lines, file_path, added_lines):
    """Merge one buffered file section into ordered per-destination content."""
    if not added_lines:
        return
    destination = file_path or _NEUTRAL_PATCH_PATH
    grouped_lines.setdefault(destination, []).extend(added_lines)


def extract_patch_targets(command):
    """Extract only newly added content from a Codex apply_patch command.

    File sections remain buffered until the next section or patch end so a
    later Move to marker can select the destination for every addition in the
    section. Unrecognized additions use a neutral path and are still scanned.
    """
    if not isinstance(command, str) or not command:
        return []

    grouped_lines = {}
    current_path = None
    added_lines = []

    for line in command.splitlines():
        file_marker = _PATCH_FILE_MARKER.match(line)
        if file_marker:
            _merge_patch_lines(grouped_lines, current_path, added_lines)
            operation, raw_path = file_marker.groups()
            current_path = raw_path.strip() if operation != "Delete" else None
            added_lines = []
            continue

        move_marker = _PATCH_MOVE_MARKER.match(line)
        if move_marker:
            destination = move_marker.group(1).strip()
            if destination:
                current_path = destination
            continue

        if line == "*** End Patch":
            _merge_patch_lines(grouped_lines, current_path, added_lines)
            current_path = None
            added_lines = []
            continue

        if line.startswith("+"):
            added_lines.append(line[1:])

    _merge_patch_lines(grouped_lines, current_path, added_lines)
    return [
        (file_path, "\n".join(lines))
        for file_path, lines in grouped_lines.items()
    ]


def extract_scan_targets(tool_name, tool_input):
    """Normalize Claude and Codex edit payloads into scan-target tuples."""
    if not isinstance(tool_input, dict):
        return []

    if tool_name in ("Write", "Edit"):
        file_path = tool_input.get("file_path", "")
        content = extract_content(tool_name, tool_input)
        if not isinstance(file_path, str):
            file_path = ""
        if not isinstance(content, str) or not content:
            return []
        return [(file_path, content)]

    if tool_name == "apply_patch":
        return extract_patch_targets(tool_input.get("command"))

    return []
```

- [ ] **Step 4: Verify green and parser edge cases**

Run:

```bash
.venv/bin/python -m pytest tests/test_secret_scanner.py -k 'extract_content or extract_patch_targets or extract_scan_targets_preserves' -q
```

Expected: all selected tests pass.

- [ ] **Step 5: Review checkpoint**

Review the parser for off-by-one errors: exactly one leading `+` is removed, `-` lines are ignored, empty paths fall back to `<apply_patch>`, and a move marker is applied before the section flushes. Do not commit.

---

### Task 4: Multi-Target Scanner Enforcement

**Files:**
- Modify: `tests/test_secret_scanner.py:317-432`
- Modify: `hooks/secret_scanner.py:350-398`

**Interfaces:**
- Consumes: `extract_scan_targets(tool_name, tool_input)` from Task 3.
- Preserves: `scan_content(content, file_path)` and exit status `2` for blocking findings.

- [ ] **Step 1: Write failing Codex integration tests**

Add:

```python
def _codex_patch_payload(command, session_id="codex-test"):
    """Build the released Codex PreToolUse apply_patch envelope."""
    return json.dumps(
        {
            "session_id": session_id,
            "tool_name": "apply_patch",
            "tool_input": {"command": command},
        }
    )


def test_main_blocks_secret_added_by_codex_patch():
    """A blocking secret in added patch content must stop apply_patch."""
    command = (
        "*** Begin Patch\n"
        "*** Add File: app.py\n"
        "+private_key = '0x" + "a" * 64 + "'\n"
        "*** End Patch"
    )

    with patch("sys.stdin.read", return_value=_codex_patch_payload(command)), \
         patch("sys.stderr.write") as mock_stderr:
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2
    mock_stderr.assert_called()


def test_main_allows_codex_patch_that_only_removes_secret():
    """Cleaning an existing leak must not be blocked by the removed text."""
    command = (
        "*** Begin Patch\n"
        "*** Update File: app.py\n"
        "@@\n"
        "-private_key = '0x" + "a" * 64 + "'\n"
        "+private_key = os.environ['PRIVATE_KEY']\n"
        "*** End Patch"
    )

    with patch("sys.stdin.read", return_value=_codex_patch_payload(command)):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0


def test_main_scans_every_codex_patch_target():
    """A clean first file must not prevent a later file from being blocked."""
    command = (
        "*** Begin Patch\n"
        "*** Add File: clean.py\n"
        "+print('safe')\n"
        "*** Add File: leaked.py\n"
        "+private_key = '0x" + "a" * 64 + "'\n"
        "*** End Patch"
    )

    with patch("sys.stdin.read", return_value=_codex_patch_payload(command)), \
         patch("sys.stderr.write"):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 2


def test_main_codex_env_addition_warns_without_blocking():
    """Path-sensitive env policy remains warning-only for Codex patches."""
    command = (
        "*** Begin Patch\n"
        "*** Add File: .env.local\n"
        "+private_key = '0x" + "a" * 64 + "'\n"
        "*** End Patch"
    )

    with patch("sys.stdin.read", return_value=_codex_patch_payload(command)), \
         patch("sys.stderr.write"), \
         patch.object(secret_scanner, "load_shown", return_value=set()), \
         patch.object(secret_scanner, "save_shown") as mock_save:
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
    mock_save.assert_called_once()


def test_main_codex_allow_marker_suppresses_known_fake_secret():
    """The existing per-line opt-out applies after the patch prefix is removed."""
    command = (
        "*** Begin Patch\n"
        "*** Add File: fixture.py\n"
        "+private_key = '0x" + "a" * 64 + "'  # seal-allow-secret\n"
        "*** End Patch"
    )

    with patch("sys.stdin.read", return_value=_codex_patch_payload(command)):
        with pytest.raises(SystemExit) as exc:
            main()

    assert exc.value.code == 0
```

- [ ] **Step 2: Run Codex integration tests and verify red**

Run:

```bash
.venv/bin/python -m pytest tests/test_secret_scanner.py -k 'main_ and codex' -q
```

Expected: the blocking and warning assertions fail because the current `main()` ignores `apply_patch`.

- [ ] **Step 3: Replace the single-target main flow**

Replace `main()` in `hooks/secret_scanner.py` with:

```python
def main():
    """Read one hook event and enforce secret policy on every added target."""
    data = read_hook_input(DEBUG_LOG)

    session_id = data.get("session_id", "default")
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})  # read_hook_input guarantees a dict
    targets = extract_scan_targets(tool_name, tool_input)

    if not targets:
        sys.exit(0)

    shown = None
    for file_path, content in targets:
        # Log only metadata. Added content can contain the exact secret that the
        # scanner exists to prevent from reaching durable storage.
        debug_log(
            f"Scanning {tool_name} on {file_path} ({len(content)} chars)",
            DEBUG_LOG,
        )
        rule_name, message, should_block = scan_content(content, file_path)
        if not rule_name:
            continue

        # Expected secret files remain warning-only in both clients.
        if is_env_file(file_path):
            message = message.replace("BLOCKED", "NOTE (env file)")
            should_block = False

        # Blocking rules enforce on every occurrence and never consult warning
        # deduplication state.
        if should_block:
            print(message, file=sys.stderr)
            debug_log(f"BLOCKED: {rule_name} in {file_path}", DEBUG_LOG)
            sys.exit(2)

        # Warning state is loaded lazily because clean and blocking calls do not
        # need persistence. One set is shared across every target in this event.
        if shown is None:
            shown = load_shown(session_id, STATE_PREFIX)
        warning_key = f"{rule_name}:{file_path}"
        if warning_key not in shown:
            shown.add(warning_key)
            save_shown(session_id, STATE_PREFIX, shown, DEBUG_LOG)
            print(message, file=sys.stderr)
            debug_log(f"WARNED: {rule_name} in {file_path}", DEBUG_LOG)

    sys.exit(0)
```

- [ ] **Step 4: Verify green and preserve Claude behavior**

Run:

```bash
.venv/bin/python -m pytest tests/test_secret_scanner.py -q
```

Expected: all scanner tests pass, including existing Claude `Write` tests and new Codex `apply_patch` tests.

- [ ] **Step 5: Run adjacent hook suites**

Run:

```bash
.venv/bin/python -m pytest tests/test_security_guard.py tests/test_utils.py -q
```

Expected: all adjacent tests pass with zero failures or warnings.

- [ ] **Step 6: Review checkpoint**

Inspect the main loop for type mismatches and control-flow errors. Confirm a warning in one target does not stop later targets, a later block exits 2, and warning state is never consulted for blocking rules. Do not commit.

---

### Task 5: Cross-Client Documentation and State-Machine Guidance

**Files:**
- Modify: `tests/test_plugin_package.py`
- Modify: `README.md:1-38`
- Create: `AGENTS.md`

**Interfaces:**
- Consumes: the final manifest names, hook behavior, and installation command.
- Produces: accurate user installation instructions and durable contributor invariants.

- [ ] **Step 1: Write failing documentation contract tests**

Append to `tests/test_plugin_package.py`:

```python
def test_readme_documents_both_clients_and_codex_hook_trust():
    """Installation docs must state both supported clients and trust boundary."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "claude plugin install seal-security@github:zknpr/seal-security-plugin" in readme
    assert "codex plugin add" in readme
    assert "/hooks" in readme
    assert "apply_patch" in readme
    assert "defense in depth" in readme


def test_agents_documents_cross_client_state_machine():
    """Contributor guidance must preserve the security-critical parser states."""
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "Write/Edit" in agents
    assert "apply_patch" in agents
    assert "added lines" in agents
    assert "exit status 2" in agents
    assert "1.1.0" in agents
    assert "python -m pytest -q" in agents
```

- [ ] **Step 2: Run documentation tests and verify red**

Run:

```bash
.venv/bin/python -m pytest tests/test_plugin_package.py -q
```

Expected: the README assertion fails and `AGENTS.md` is missing.

- [ ] **Step 3: Rewrite the README introduction and installation section**

Replace the title, introduction, installation section, and hook description through the existing “Hook Behavior” bullets with client-neutral text that includes this content:

````markdown
# SEAL Security Plugin

Comprehensive Web3 security framework plugin for Claude Code and Codex CLI, based on the [SEAL (Security Alliance) Frameworks](https://frameworks.securityalliance.org). It provides security guidance, platform hardening checklists, and lifecycle hooks that flag dangerous commands and secret exposure.

## Install

### Claude Code

```bash
claude plugin install seal-security@github:zknpr/seal-security-plugin
```

### Codex CLI

Codex installs plugins from a marketplace. For local development, expose the clone at `~/plugins/seal-security` and add this entry to `~/.agents/plugins/marketplace.json` without replacing existing entries:

```json
{
  "name": "seal-security",
  "source": {
    "source": "local",
    "path": "./plugins/seal-security"
  },
  "policy": {
    "installation": "AVAILABLE",
    "authentication": "ON_INSTALL"
  },
  "category": "Security"
}
```

Then read the marketplace name and install:

```bash
MARKETPLACE_NAME="$(python3 -c 'import json, pathlib; print(json.loads((pathlib.Path.home() / ".agents/plugins/marketplace.json").read_text())["name"])')"
codex plugin add "seal-security@${MARKETPLACE_NAME}"
```

Start a new Codex thread, open `/hooks`, review the two SEAL command hooks, and trust them before relying on enforcement.

## What's Included

### Skills

| Skill | Trigger | Description |
|---|---|---|
| `security-guidance` | “security review”, “audit”, “harden”, “opsec”, or work touching infrastructure, wallets, or CI/CD | Comprehensive security advisor with bundled references for every SEAL domain |
| `security-checklist` | “checklist”, “harden [platform]”, or “lock down” | More than 20 platform-specific hardening checklists |

### Hooks

| Hook | Claude trigger | Codex trigger | Behavior |
|---|---|---|---|
| `security-guard` | Every `Bash` command | Supported `Bash` `PreToolUse` calls | Catches pipe-to-shell, chmod 777, force push, secret exposure, privileged containers, SSL disabling, and related dangerous patterns |
| `secret-scanner` | Every `Write`/`Edit` operation | `apply_patch` added lines | Detects private keys, mnemonics, cloud credentials, SSH keys, JWTs, webhooks, and database connection strings |

#### Hook Behavior

- **BLOCKED** actions include private keys, mnemonics, AWS keys, SSH keys, PGP keys, pipe-to-shell execution, chmod 777, force push to main, and recursive removal of system roots.
- **WARNING** actions include API-key assignments, JWTs, webhooks, npm installs without `--ignore-scripts`, environment dumps, and disabled SSL verification.
- `.env` files are warned but never blocked because they are expected to contain secrets.
- Each warning is shown once per session per file or command; blocked actions are enforced every time.
- Add a `seal-allow-secret` comment to opt a known-fake line out of secret scanning.
- Debug logging is opt-in through `SEAL_DEBUG=1` and writes owner-only files in the host plugin-data directory.

The hooks are defense in depth, not a complete security boundary. Codex currently documents that `PreToolUse` does not intercept every shell execution path. The scanner examines newly added `apply_patch` lines and deliberately ignores removed lines so cleaning an existing secret is never blocked.
````

Keep the existing covered domains, checklists, principles, sources, and license sections unchanged.

- [ ] **Step 4: Create project `AGENTS.md`**

Create:

````markdown
# SEAL Security Plugin Contributor Instructions

## Compatibility State Machine

1. Claude `Write/Edit` events provide `file_path` plus `content` or `new_string`.
2. Codex `apply_patch` events provide patch text in `tool_input.command`.
3. Normalize both forms into `(file_path, added_content)` targets.
4. For Codex patches, collect only added lines, group them by destination path, and ignore removed/context lines.
5. Scan every target with the shared rule table.
6. A blocking match writes a sanitized reason to stderr and exits with exit status 2.
7. A warning is deduplicated per session and file; it never bypasses a later blocking target.

## Security Invariants

- Never scan removed patch lines; users must be able to delete leaked material.
- Never open a path obtained from hook input.
- Never write matched secret values to logs or state.
- Preserve fail-open parsing for malformed hook envelopes and fail-closed handling for matched blocking rules.
- Keep `hooks/hooks.json` compatible with both clients. Codex supplies `CLAUDE_PLUGIN_ROOT` for existing hook commands.
- Use `PLUGIN_DATA`, then `CLAUDE_PLUGIN_DATA`, then `~/.claude` for writable runtime data.

## Release Invariants

- Keep `.claude-plugin/plugin.json` and `.codex-plugin/plugin.json` on version `1.1.0` for this release.
- Keep skill references plugin-relative; do not add client-home paths to skill instructions.
- Update this state machine whenever core hook transitions change.

## Verification

Run:

```bash
python -m pytest -q
python3 /Users/zero/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
```
````

- [ ] **Step 5: Verify documentation contracts**

Run:

```bash
.venv/bin/python -m pytest tests/test_plugin_package.py -q
```

Expected: five package/documentation tests pass.

- [ ] **Step 6: Review checkpoint**

Read `README.md` and `AGENTS.md` end to end. Confirm the public README does not claim complete interception and `AGENTS.md` contains project facts only. Do not commit.

---

### Task 6: Full Verification and Local Codex Installation

**Files:**
- Read/verify: every changed repository file.
- Create outside repository through supported tooling: personal marketplace entry for `seal-security`.
- Create outside repository: `/Users/zero/plugins/seal-security` symlink.
- Create outside repository through Codex CLI: installed cache and enablement state.
- Create memory update note: `/Users/zero/.codex/memories/extensions/ad_hoc/notes/2026-07-15-seal-security-plugin-codex.md`.

**Interfaces:**
- Consumes: validated plugin root at `/Users/zero/dev/seal-security-plugin`.
- Produces: installed and enabled `seal-security@zero-local` plus an explicit pending hook-trust handoff.

- [ ] **Step 1: Run complete repository verification**

Run:

```bash
.venv/bin/python -m pytest -q
python3 /Users/zero/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py .
python3 -m json.tool .claude-plugin/plugin.json
python3 -m json.tool .codex-plugin/plugin.json
python3 -m json.tool hooks/hooks.json
```

Expected: pytest reports zero failures, plugin validation prints `Plugin validation passed: /Users/zero/dev/seal-security-plugin`, and each JSON command exits 0.

- [ ] **Step 2: Directly verify both blocking hook contracts**

Run the Bash guard:

```bash
printf '%s' '{"session_id":"verify-bash","tool_name":"Bash","tool_input":{"command":"chmod 777 /tmp/seal-test"}}' | python3 hooks/security_guard.py
```

Expected: exit status 2 and a sanitized `[SEAL] BLOCKED` message.

Run the Codex patch scanner:

```bash
printf '%s' '{"session_id":"verify-patch","tool_name":"apply_patch","tool_input":{"command":"*** Begin Patch\n*** Add File: leaked.py\n+private_key = \"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n*** End Patch"}}' | python3 hooks/secret_scanner.py
```

Expected: exit status 2 and a sanitized `[SEAL] BLOCKED` message. Neither output may contain the detected private-key value.

- [ ] **Step 3: Preflight the personal marketplace**

Run:

```bash
test ! -e /Users/zero/plugins/seal-security
test ! -L /Users/zero/plugins/seal-security
rg -n '"name": "seal-security"' /Users/zero/.agents/plugins/marketplace.json
```

Expected: both `test` commands exit 0 and `rg` prints no match. If either path or entry already exists, stop and inspect it; do not use `--force` and do not overwrite it.

- [ ] **Step 4: Add the marketplace entry through the plugin-creator helper**

Run:

```bash
python3 /Users/zero/.codex/skills/.system/plugin-creator/scripts/create_basic_plugin.py seal-security --with-marketplace --category Security
```

Expected: the helper appends one `AVAILABLE`/`ON_INSTALL` entry while preserving marketplace name `zero-local` and creates only a temporary scaffold at `/Users/zero/plugins/seal-security`.

Delete the helper-generated stub manifest with `apply_patch`, then remove its now-empty directories:

```diff
*** Begin Patch
*** Delete File: /Users/zero/plugins/seal-security/.codex-plugin/plugin.json
*** End Patch
```

```bash
rmdir /Users/zero/plugins/seal-security/.codex-plugin
rmdir /Users/zero/plugins/seal-security
ln -s /Users/zero/dev/seal-security-plugin /Users/zero/plugins/seal-security
```

Verify:

```bash
readlink /Users/zero/plugins/seal-security
```

Expected: `/Users/zero/dev/seal-security-plugin`.

- [ ] **Step 5: Install and verify through Codex CLI**

Run:

```bash
codex plugin add seal-security@zero-local --json
codex plugin list --marketplace zero-local --available --json | python3 -c 'import json, sys; data=json.load(sys.stdin); rows=data["installed"] + data["available"]; plugin=next(row for row in rows if row["pluginId"] == "seal-security@zero-local"); assert plugin["installed"] is True; assert plugin["enabled"] is True; assert plugin["version"] == "1.1.0"; print(json.dumps(plugin, indent=2))'
```

Expected: the printed plugin object contains `"installed": true`, `"enabled": true`, `"version": "1.1.0"`, and source path `/Users/zero/plugins/seal-security`.

Inspect the installed cache:

```bash
find /Users/zero/.codex/plugins/cache/zero-local/seal-security -maxdepth 4 -type f | sort
```

Expected: the cache contains `.codex-plugin/plugin.json`, both skill manifests and references, `hooks/hooks.json`, all three Python hook modules, and `hooks/bip39_english.txt`.

- [ ] **Step 6: Record persistent cross-agent facts**

Create `/Users/zero/.codex/memories/extensions/ad_hoc/notes/2026-07-15-seal-security-plugin-codex.md` with:

```markdown
# SEAL Security plugin Codex parity

- Repository: `/Users/zero/dev/seal-security-plugin`.
- Claude and Codex release version: `1.1.0`.
- Codex manifest: `.codex-plugin/plugin.json`; bundled hooks use default `hooks/hooks.json` discovery.
- Codex `apply_patch` compatibility scans only added lines and groups them by destination file; deletion-only patches are allowed.
- Runtime data precedence is `PLUGIN_DATA`, `CLAUDE_PLUGIN_DATA`, then `~/.claude`.
- Personal marketplace plugin id: `seal-security@zero-local`.
- Local source alias: `/Users/zero/plugins/seal-security -> /Users/zero/dev/seal-security-plugin`.
- Codex hook commands require explicit review and trust through `/hooks` after installation or hook changes.
- Repository verification: `.venv/bin/python -m pytest -q` plus the plugin-creator `validate_plugin.py .` command.
```

- [ ] **Step 7: Final diff and scope review**

Run:

```bash
git diff --check
git status --short
git diff --stat
git diff -- . ':(exclude)docs/superpowers/specs/2026-07-15-codex-cli-full-parity-design.md' ':(exclude)docs/superpowers/plans/2026-07-15-codex-cli-full-parity.md'
```

Expected: no whitespace errors; only the planned repository files are changed or created. Confirm personal marketplace changes are limited to one appended `seal-security` entry and no unrelated plugin entry changed.

- [ ] **Step 8: Handoff**

Report exact pytest and validator summary lines, installed plugin JSON, changed-file scope, and the remaining user action: start a new Codex thread and trust the reviewed SEAL hooks with `/hooks`. Do not claim hook enforcement is active before that trust step.
