from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tomllib
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_manifest import ENTRYPOINTS, verify_manifest


def inspect_macos_asset_recovery(
    safe_yolo_home: str | Path,
    *,
    run: Any = subprocess.run,
) -> dict[str, Any]:
    """Report recovery facts without exposing backup destinations or file contents."""
    problems: list[str] = []

    def tmutil(*args: str) -> subprocess.CompletedProcess[str]:
        try:
            return run(["tmutil", *args], capture_output=True, text=True, check=False, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as error:
            return subprocess.CompletedProcess(["tmutil", *args], 1, "", type(error).__name__)

    destination = tmutil("destinationinfo")
    destination_text = f"{destination.stdout}\n{destination.stderr}"
    destination_configured = (
        destination.returncode == 0
        and bool(destination.stdout.strip())
        and "No destinations configured" not in destination_text
    )
    if not destination_configured:
        problems.append("no macOS backup destination is configured")

    latest = tmutil("latestbackup")
    completed_backup = latest.returncode == 0 and bool(latest.stdout.strip())
    if not completed_backup:
        problems.append("no completed macOS backup is available")

    snapshots = tmutil("listlocalsnapshots", "/")
    data_snapshots = [
        line.strip()
        for line in snapshots.stdout.splitlines()
        if line.strip().startswith("com.apple.TimeMachine.")
    ]

    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    private_state = True
    for name in ("state", "backups", "releases"):
        directory = home / name
        if not directory.is_dir() or directory.stat().st_mode & 0o077:
            private_state = False
            problems.append(f"Safe YOLO {name} must exist and be private to the host user")

    return {
        "healthy": not problems,
        "backup_destination_configured": destination_configured,
        "completed_backup_present": completed_backup,
        "local_data_snapshot_count": len(data_snapshots),
        "safe_yolo_state_private": private_state,
        "problems": problems,
    }


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
    parser.add_argument("--macos-asset-recovery-home", type=Path)
    args = parser.parse_args()
    report = inspect_release(args.release, args.manifest_sha256)
    if args.macos_asset_recovery_home is not None:
        report["asset_recovery"] = inspect_macos_asset_recovery(args.macos_asset_recovery_home)
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
