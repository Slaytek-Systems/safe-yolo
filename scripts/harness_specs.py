"""Declarative harness identities and lifecycle-support levels."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HarnessSpec:
    id: str
    name: str
    status: str
    entry: str
    binary: str
    config_dir: str
    config_file: str
    lifecycle_supported: bool


HARNESSES = (
    HarnessSpec("codex", "Codex", "supported", "codex_v3", "codex", ".codex", "hooks.json", True),
    HarnessSpec(
        "claude-code",
        "Claude Code",
        "beta",
        "claude_code_v3",
        "claude",
        ".claude",
        "settings.json",
        True,
    ),
    HarnessSpec("cursor", "Cursor", "beta", "cursor_v3", "cursor", ".cursor", "hooks.json", True),
    HarnessSpec(
        "grok", "Grok", "adapter-only", "grok_v3", "grok", ".grok", "hooks/safe-yolo.json", False
    ),
    HarnessSpec(
        "opencode",
        "OpenCode",
        "adapter-only",
        "opencode_v3",
        "opencode",
        ".config/opencode",
        "plugins/safe-yolo.js",
        False,
    ),
    HarnessSpec(
        "antigravity",
        "Antigravity",
        "adapter-only",
        "antigravity_v3",
        "agy",
        ".gemini",
        "config/hooks.json",
        False,
    ),
    HarnessSpec("devin", "Devin", "adapter-only", "devin_v3", "devin", ".devin", "", False),
)

HARNESS_BY_ID = {spec.id: spec for spec in HARNESSES}

HARNESS_HOME_ENV = {
    "codex": "CODEX_HOME",
    "claude-code": "CLAUDE_CONFIG_DIR",
}
