"""Native harness configuration and immutable bootstrap command wiring."""

from __future__ import annotations

import json
import re
from pathlib import Path
import shlex
import sys
from typing import Any

from scripts.release_manifest import ENTRYPOINTS


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


SAFE_YOLO_VALUE_FLAGS = frozenset(
    {
        "--release",
        "--manifest-sha256",
        "--entry",
        "--state-dir",
        "--host-contract",
        "--safe-yolo-home",
        "--user-home",
        "--harness-home",
    }
)
CODEX_DESCRIPTION = "Safe YOLO v3 default-open policy with explicit hard denials and no approval path."


def is_safe_yolo_hook(hook: Any) -> bool:
    """Recognise a Safe YOLO bootstrap hook from any release, entry or installation.

    Install, doctor and uninstall all decide ownership here, so a pin this
    installer did not write is still seen and another tool's hook is never taken.
    """
    if not isinstance(hook, dict) or not isinstance(hook.get("command"), str):
        return False
    args = hook.get("args")
    if args is None:
        try:
            tokens = shlex.split(hook["command"])
        except ValueError:
            return False
    elif isinstance(args, list) and all(isinstance(arg, str) for arg in args):
        # Exec form: `command` is the program itself and may hold spaces.
        tokens = [hook["command"], *args]
    else:
        return False
    if len(tokens) < 2 or not re.fullmatch(r"python3(\.\d+)?", Path(tokens[0]).name):
        return False
    if Path(tokens[1]).name != "bootstrap.py":
        return False
    values: dict[str, str] = {}
    index = 2
    while index < len(tokens):
        flag = tokens[index]
        if flag == "--audit-only":
            index += 1
            continue
        if flag not in SAFE_YOLO_VALUE_FLAGS or flag in values or index + 1 >= len(tokens):
            return False
        values[flag] = tokens[index + 1]
        index += 2
    return values.get("--entry") in ENTRYPOINTS and {"--release", "--manifest-sha256"} <= set(values)


def safe_yolo_hook_slots(groups: Any) -> list[tuple[int, int]]:
    """Positions, as (group, hook), of every Safe YOLO hook in an event's group list."""
    if not isinstance(groups, list):
        return []
    return [
        (group_index, hook_index)
        for group_index, group in enumerate(groups)
        if isinstance(group, dict) and isinstance(group.get("hooks"), list)
        for hook_index, hook in enumerate(group["hooks"])
        if is_safe_yolo_hook(hook)
    ]


def remove_safe_yolo_hooks(groups: list[Any], *, keep_positions: bool) -> list[Any]:
    """Drop Safe YOLO hooks and leave every other hook as it was.

    Codex records hook trust by group and hook position. With `keep_positions`,
    a group this removal empties ahead of another group stays as an empty group,
    and a removal that would move a hook within its group is refused.
    """
    slots = set(safe_yolo_hook_slots(groups))
    kept: list[Any] = []
    for group_index, group in enumerate(groups):
        removed = [hook_index for index, hook_index in slots if index == group_index]
        if not removed:
            kept.append(group)
            continue
        hooks = [hook for hook_index, hook in enumerate(group["hooks"]) if hook_index not in removed]
        if keep_positions and any(hook_index > min(removed) for hook_index in range(len(group["hooks"]))
                                  if hook_index not in removed):
            raise RuntimeError(
                "Another hook follows Safe YOLO's in the same group; removing Safe YOLO's would move it "
                "and Codex would stop trusting it. Move that hook to its own group, then uninstall."
            )
        if hooks or (keep_positions and group_index < len(groups) - 1):
            kept.append({**group, "hooks": hooks})
    return kept


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
    refusal = RuntimeError(
        f"{label} already has an existing PreToolUse entry Safe YOLO cannot keep or replace. "
        "It must be a list of well-formed hook groups holding at most one Safe YOLO hook, and "
        "that hook must be this installation's own command hook in a group matched to *."
    )
    # A declaration the harness cannot load can make it discard the whole file.
    if not isinstance(existing_pretool, list) or not all(
        isinstance(group, dict)
        and isinstance(group.get("hooks"), list)
        and all(
            isinstance(hook, dict)
            and isinstance(hook.get("type"), str)
            and (hook["type"] != "command" or isinstance(hook.get("command"), str))
            for hook in group["hooks"]
        )
        for group in existing_pretool
    ):
        raise refusal
    if hooks.get("PostToolUse", []):
        raise RuntimeError(f"{label} has a non-empty PostToolUse lifecycle; Safe YOLO will not replace it.")
    own_hook = {
        "type": "command",
        "command": command,
        "timeout": 10,
        "statusMessage": "Checking explicit Safe YOLO restrictions",
    }
    slots = safe_yolo_hook_slots(existing_pretool)
    if not slots:
        hooks["PreToolUse"] = [*existing_pretool, {"matcher": "*", "hooks": [own_hook]}]
    else:
        group_index, hook_index = slots[0]
        group = existing_pretool[group_index]
        current = group["hooks"][hook_index]
        if (
            len(slots) != 1
            or group.get("matcher") != "*"
            or current.get("type") != "command"
            or "args" in current
            or not is_safe_yolo_command(current.get("command"), home, entry)
        ):
            raise refusal
        group["hooks"][hook_index] = own_hook
    if entry == "codex_v3":
        document.setdefault("description", CODEX_DESCRIPTION)
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
