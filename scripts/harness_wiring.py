"""Native harness configuration and immutable bootstrap command wiring."""

from __future__ import annotations

import json
import re
from pathlib import Path
import shlex
import sys
from typing import Any


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"JSON file is unreadable: {path} ({type(error).__name__})") from error
    if not isinstance(document, dict):
        raise RuntimeError(f"JSON document must be an object: {path}")
    return document


def is_safe_yolo_command(command: Any, home: Path, entry: str = "codex_v3") -> bool:
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    if len(tokens) < 2 or not re.fullmatch(r"python3(\.\d+)?", Path(tokens[0]).name):
        return False
    bootstrap = Path(tokens[1])
    release_bootstrap = (
        bootstrap.name == "bootstrap.py"
        and bootstrap.parent.name == "scripts"
        and bootstrap.parent.parent.parent == home / "releases"
    )
    if bootstrap != home / "bootstrap.py" and not release_bootstrap:
        return False
    required_flags = {"--release", "--manifest-sha256", "--entry", "--state-dir"}
    context_flags = {"--safe-yolo-home", "--user-home", "--harness-home"}
    value_flags = required_flags | context_flags
    values: dict[str, str] = {}
    index = 2
    while index < len(tokens):
        flag = tokens[index]
        if flag not in value_flags or flag in values or index + 1 >= len(tokens):
            return False
        values[flag] = tokens[index + 1]
        index += 2
    return required_flags <= set(values) <= value_flags and values["--entry"] == entry


def prepare_command_hooks(
    path: Path,
    home: Path,
    command: str,
    *,
    entry: str = "codex_v3",
    label: str = "Codex",
) -> tuple[dict[str, Any], bytes | None, int]:
    original_bytes: bytes | None = None
    mode = 0o600
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"{label} configuration path is unavailable or unsafe.")
        original_bytes = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        document = read_json_object(path)
    else:
        document = {}
    hooks = document.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise RuntimeError(f"{label} hooks field must be an object.")
    existing_pretool = hooks.get("PreToolUse", [])
    recognized_pretool = (
        isinstance(existing_pretool, list)
        and bool(existing_pretool)
        and all(
            isinstance(group, dict)
            and group.get("matcher") == "*"
            and isinstance(group.get("hooks"), list)
            and bool(group["hooks"])
            and all(
                isinstance(hook, dict)
                and hook.get("type") == "command"
                and is_safe_yolo_command(hook.get("command"), home, entry)
                for hook in group["hooks"]
            )
            for group in existing_pretool
        )
    )
    if existing_pretool and not recognized_pretool:
        raise RuntimeError(
            f"{label} already has an existing PreToolUse command hook. "
            "Safe YOLO will not replace a foreign enforcement surface."
        )
    if hooks.get("PostToolUse", []):
        raise RuntimeError(f"{label} has a non-empty PostToolUse lifecycle; Safe YOLO will not replace it.")
    hooks["PreToolUse"] = [
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": command,
                    "timeout": 10,
                    "statusMessage": "Checking explicit Safe YOLO restrictions",
                }
            ],
        }
    ]
    if entry == "codex_v3":
        document["description"] = (
            "Safe YOLO v3 default-open policy with explicit hard denials and no approval path."
        )
    return document, original_bytes, mode


def prepare_cursor_hooks(
    path: Path, home: Path, command: str
) -> tuple[dict[str, Any], bytes | None, int]:
    original_bytes: bytes | None = None
    mode = 0o600
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("Cursor hooks path is unavailable or unsafe.")
        original_bytes = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        document = read_json_object(path)
    else:
        document = {"version": 1}
    hooks = document.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise RuntimeError("Cursor hooks field must be an object.")
    existing = hooks.get("preToolUse", [])
    if existing and (
        not isinstance(existing, list)
        or not all(
            isinstance(item, dict)
            and is_safe_yolo_command(item.get("command"), home, "cursor_v3")
            for item in existing
        )
    ):
        raise RuntimeError(
            "Cursor already has an existing preToolUse hook. "
            "Safe YOLO will not replace a foreign enforcement surface."
        )
    hooks["preToolUse"] = [
        {
            "command": command,
            "matcher": "*",
            "timeout": 10,
            "failClosed": True,
        }
    ]
    document["version"] = 1
    return document, original_bytes, mode


def pinned_command(
    home: Path,
    release: Path,
    digest: str,
    entry: str,
    *,
    user_home: Path | None = None,
    harness_home: Path | None = None,
) -> str:
    command = [
        sys.executable,
        str(release / "scripts" / "bootstrap.py"),
        "--release",
        str(release),
        "--manifest-sha256",
        digest,
        "--entry",
        entry,
        "--state-dir",
        str(home / "state"),
    ]
    if user_home is not None and harness_home is not None:
        command.extend(
            [
                "--safe-yolo-home",
                str(home),
                "--user-home",
                str(user_home),
                "--harness-home",
                str(harness_home),
            ]
        )
    return shlex.join(command)


def inspect_cursor_wiring(
    path: Path,
    home: Path,
    release: Path,
    digest: str,
    *,
    user_home: Path | None = None,
    harness_home: Path | None = None,
) -> dict[str, Any]:
    problems: list[str] = []
    try:
        document = read_json_object(path)
    except RuntimeError as error:
        return {"healthy": False, "problems": [str(error)]}
    hooks = document.get("hooks", {})
    entries = hooks.get("preToolUse", []) if isinstance(hooks, dict) else []
    if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
        problems.append("exactly one Cursor preToolUse hook is required")
    else:
        hook = entries[0]
        if hook.get("matcher") != "*" or hook.get("failClosed") is not True:
            problems.append("Cursor preToolUse hook must match all tools and fail closed")
        if not is_safe_yolo_command(hook.get("command"), home, "cursor_v3"):
            problems.append("Cursor preToolUse hook is not a Safe YOLO command")
        elif hook.get("command") != pinned_command(
            home,
            release,
            digest,
            "cursor_v3",
            user_home=user_home,
            harness_home=harness_home,
        ):
            problems.append("Cursor preToolUse hook is not pinned to the expected release")
    return {"healthy": not problems, "problems": problems}
