from __future__ import annotations

import json
from pathlib import Path
import tomllib
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_manifest import ENTRYPOINTS, verify_manifest


def inspect_release(release_dir: str | Path, expected_manifest_hash: str | None = None) -> dict[str, Any]:
    release = Path(release_dir).resolve()
    problems = verify_manifest(release, expected_manifest_hash)
    version_path = release / "VERSION"
    version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else "unknown"
    for entry in ENTRYPOINTS.values():
        if not (release / entry).is_file() and f"missing: {entry}" not in problems:
            problems.append(f"missing: {entry}")
    return {"release": str(release), "version": version, "healthy": not problems, "problems": problems}


def inspect_codex_wiring(
    config_path: str | Path,
    hooks_path: str | Path,
    bootstrap_path: str | Path,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Read-only check that Codex is wired to exactly one pinned PreTool bootstrap."""
    problems: list[str] = []
    try:
        config = tomllib.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        return {"healthy": False, "problems": [f"config unreadable: {type(error).__name__}"]}
    if config.get("approval_policy") != "never":
        problems.append("approval_policy must be never")
    if config.get("sandbox_mode") != "danger-full-access":
        problems.append("sandbox_mode must be danger-full-access")
    try:
        hooks = json.loads(Path(hooks_path).read_text(encoding="utf-8")).get("hooks", {})
    except (OSError, json.JSONDecodeError) as error:
        return {"healthy": False, "problems": [*problems, f"hooks unreadable: {type(error).__name__}"]}
    groups = hooks.get("PreToolUse", [])
    commands = [hook.get("command", "") for group in groups if isinstance(group, dict) for hook in group.get("hooks", []) if isinstance(hook, dict) and hook.get("type") == "command"]
    if len(commands) != 1:
        problems.append("exactly one PreToolUse command hook is required")
    elif str(bootstrap_path) not in commands[0] or f"--manifest-sha256 {manifest_sha256}" not in commands[0] or "--entry codex" not in commands[0]:
        problems.append("PreToolUse hook is not pinned to the expected Safe YOLO bootstrap release")
    return {"healthy": not problems, "problems": problems}


def inspect_cursor_wiring(
    hooks_path: str | Path,
    bootstrap_path: str | Path,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Read-only check for fail-closed, manifest-pinned Cursor consequence hooks."""
    problems: list[str] = []
    try:
        document = json.loads(Path(hooks_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"healthy": False, "problems": [f"hooks unreadable: {type(error).__name__}"]}
    if document.get("version") != 1:
        problems.append("Cursor hooks version must be 1")
    hooks = document.get("hooks") or {}
    expected = {
        "beforeShellExecution": "cursor",
        "beforeMCPExecution": "cursor",
        "preToolUse": "cursor",
        "beforeSubmitPrompt": "cursor_prompt",
    }
    for event, entry in expected.items():
        groups = hooks.get(event) or []
        if len(groups) != 1 or not isinstance(groups[0], dict):
            problems.append(f"exactly one {event} hook is required")
            continue
        hook = groups[0]
        command = str(hook.get("command") or "")
        if hook.get("failClosed") is not True:
            problems.append(f"{event} must set failClosed true")
        if (
            str(bootstrap_path) not in command
            or f"--manifest-sha256 {manifest_sha256}" not in command
            or f"--entry {entry}" not in command
        ):
            problems.append(f"{event} is not pinned to the expected Safe YOLO entry")
    return {"healthy": not problems, "problems": problems}


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Read-only Safe YOLO release health check.")
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--manifest-sha256")
    args = parser.parse_args()
    print(json.dumps(inspect_release(args.release, args.manifest_sha256), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
