from __future__ import annotations

import json
from pathlib import Path
import shlex
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
    *,
    release_path: str | Path,
    entry: str = "codex",
    approval_post_tool: bool = False,
) -> dict[str, Any]:
    """Read-only check for the pinned Codex hook lifecycle of one release entry."""
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
        document = json.loads(Path(hooks_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"healthy": False, "problems": [*problems, f"hooks unreadable: {type(error).__name__}"]}
    hooks = document.get("hooks", {}) if isinstance(document, dict) else {}
    pretool = _command_hooks(hooks, "PreToolUse")
    if len(pretool) != 1:
        problems.append("exactly one PreToolUse command hook is required")
    elif pretool[0][0] != "*" or not _command_is_pinned(
        pretool[0][1],
        bootstrap_path=bootstrap_path,
        release_path=release_path,
        manifest_sha256=manifest_sha256,
        entry=entry,
    ):
        problems.append("PreToolUse hook is not pinned to the expected Safe YOLO bootstrap release")
    if approval_post_tool:
        posttool = _command_hooks(hooks, "PostToolUse")
        if len(posttool) != 1 or posttool[0][0] != "request_user_input":
            problems.append(
                "exactly one request_user_input PostToolUse command hook is required"
            )
        elif not _command_is_pinned(
            posttool[0][1],
            bootstrap_path=bootstrap_path,
            release_path=release_path,
            manifest_sha256=manifest_sha256,
            entry=entry,
        ):
            problems.append(
                "PostToolUse hook is not pinned to the expected Safe YOLO bootstrap release"
            )
    return {"healthy": not problems, "problems": problems}


def _command_hooks(hooks: Any, event: str) -> list[tuple[str, str]]:
    if not isinstance(hooks, dict):
        return []
    found: list[tuple[str, str]] = []
    groups = hooks.get(event, [])
    if not isinstance(groups, list):
        return found
    for group in groups:
        if not isinstance(group, dict):
            continue
        matcher = str(group.get("matcher") or "")
        entries = group.get("hooks", [])
        if not isinstance(entries, list):
            continue
        for hook in entries:
            if (
                isinstance(hook, dict)
                and hook.get("type") == "command"
                and isinstance(hook.get("command"), str)
            ):
                found.append((matcher, hook["command"]))
    return found


def _command_is_pinned(
    command: str,
    *,
    bootstrap_path: str | Path,
    release_path: str | Path,
    manifest_sha256: str,
    entry: str,
) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False

    if len(tokens) < 2 or Path(tokens[0]).name != "python3":
        return False
    if tokens[1] != str(bootstrap_path):
        return False
    values: dict[str, str] = {}
    booleans: set[str] = set()
    value_flags = {
        "--release",
        "--manifest-sha256",
        "--entry",
        "--host-contract",
        "--state-dir",
    }
    boolean_flags = {"--audit-only"}
    index = 2
    while index < len(tokens):
        flag = tokens[index]
        if flag in value_flags:
            if flag in values or index + 1 >= len(tokens):
                return False
            values[flag] = tokens[index + 1]
            index += 2
            continue
        if flag in boolean_flags:
            if flag in booleans:
                return False
            booleans.add(flag)
            index += 1
            continue
        return False
    if entry == "codex_v2" and (
        "--host-contract" in values or "--audit-only" in booleans
    ):
        return False
    return (
        values.get("--release") == str(release_path)
        and values.get("--manifest-sha256") == manifest_sha256
        and values.get("--entry") == entry
    )


def inspect_cursor_wiring(
    hook_paths: tuple[Path, ...],
    manifest_sha256: str,
) -> dict[str, Any]:
    """Check every installed Cursor hook against the active manifest and entrypoint."""
    problems: list[str] = []
    for path in hook_paths:
        if not path.is_file():
            continue
        try:
            command = path.read_text(encoding="utf-8")
        except OSError as error:
            problems.append(f"{path.name} unreadable: {type(error).__name__}")
            continue
        expected_entry = "cursor_prompt" if "prompt" in path.name else "cursor"
        if (
            f"--manifest-sha256 {manifest_sha256}" not in command
            or f"--entry {expected_entry}" not in command
        ):
            problems.append(f"{path.name} is not pinned to the expected Safe YOLO release")
    return {"healthy": not problems, "problems": problems}


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Read-only Safe YOLO release health check.")
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--codex-config", type=Path)
    parser.add_argument("--codex-hooks", type=Path)
    parser.add_argument("--bootstrap", type=Path)
    parser.add_argument("--entry", choices=("codex", "codex_v2"), default="codex")
    args = parser.parse_args()
    report = inspect_release(args.release, args.manifest_sha256)
    wiring_values = (args.codex_config, args.codex_hooks, args.bootstrap)
    if any(value is not None for value in wiring_values):
        if not all(value is not None for value in wiring_values):
            parser.error("--codex-config, --codex-hooks, and --bootstrap must be used together")
        if not args.manifest_sha256:
            parser.error("--manifest-sha256 is required when checking Codex wiring")
        wiring = inspect_codex_wiring(
            args.codex_config,
            args.codex_hooks,
            args.bootstrap,
            str(args.manifest_sha256 or ""),
            release_path=args.release,
            entry=args.entry,
            approval_post_tool=args.entry == "codex_v2",
        )
        report["codex_wiring"] = wiring
        report["healthy"] = bool(report["healthy"] and wiring["healthy"])
        report["problems"].extend(
            f"codex wiring: {problem}" for problem in wiring["problems"]
        )
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
