import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CLAUDE_MANIFEST = ROOT / ".claude-plugin" / "plugin.json"
CODEX_MANIFEST = ROOT / ".codex-plugin" / "plugin.json"
CODEX_MARKETPLACE = ROOT / ".agents" / "plugins" / "marketplace.json"


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


def test_codex_marketplace_installs_this_repository_as_the_plugin_root():
    """The repository must be directly addable as a Codex marketplace source."""
    marketplace = _load_json(CODEX_MARKETPLACE)

    assert marketplace["name"] == "seal-security"
    assert marketplace["interface"]["displayName"] == "SEAL Security"
    assert marketplace["plugins"] == [{
        "name": "seal-security",
        "source": {"source": "local", "path": "./"},
        "policy": {
            "installation": "AVAILABLE",
            "authentication": "ON_INSTALL",
        },
        "category": "Security",
    }]


def test_skill_instructions_use_only_bundled_relative_references():
    """Installed skills must not depend on either client's home directory."""
    skill_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "skills").glob("*/SKILL.md"))
    )

    assert "~/.claude" not in skill_text
    assert "${CLAUDE_PLUGIN_ROOT}" not in skill_text
    assert "references/" in skill_text
    assert (ROOT / "skills" / "security-guidance" / "references").is_dir()


def test_readme_documents_both_clients_and_codex_hook_limits():
    """User documentation must cover install, trust, payload, and coverage semantics."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "claude plugin install seal-security@github:zknpr/seal-security-plugin" in readme
    assert "codex plugin marketplace add zknpr/seal-security-plugin" in readme
    assert "codex plugin add seal-security@seal-security" in readme
    assert "/hooks" in readme
    assert "apply_patch" in readme
    assert "defense in depth" in readme.lower()


def test_agents_documents_the_cross_client_hook_state_machine():
    """Maintainers need one explicit contract for parity-sensitive core behavior."""
    agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

    assert "Write/Edit" in agents
    assert "apply_patch" in agents
    assert "added lines" in agents
    assert "exit status 2" in agents
    assert "1.1.0" in agents
    assert "python -m pytest -q" in agents
