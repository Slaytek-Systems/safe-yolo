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


def looks_like_safe_yolo_command(command: Any) -> bool:
    """Recognise a Safe YOLO bootstrap hook from any installation, release or entry."""
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    return (
        len(tokens) >= 2
        and re.fullmatch(r"python3(\.\d+)?", Path(tokens[0]).name) is not None
        and Path(tokens[1]).name == "bootstrap.py"
        and "--entry" in tokens
        and "--manifest-sha256" in tokens
    )


def _hook_is_safe_yolo(hook: Any) -> bool:
    return isinstance(hook, dict) and looks_like_safe_yolo_command(hook.get("command"))


def without_safe_yolo_groups(groups: Any) -> list[Any]:
    """Hook groups that hold no Safe YOLO hook, in their original order."""
    if not isinstance(groups, list):
        return []
    return [
        group
        for group in groups
        if not (
            isinstance(group, dict)
            and isinstance(group.get("hooks"), list)
            and any(_hook_is_safe_yolo(hook) for hook in group["hooks"])
        )
    ]


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
        "It must be a list of hook groups, and any Safe YOLO hook in it must be this "
        "installation's own, alone in a group matched to *."
    )
    if not isinstance(existing_pretool, list):
        raise refusal
    others: list[Any] = []
    for group in existing_pretool:
        entries = group.get("hooks") if isinstance(group, dict) else None
        if not isinstance(entries, list):
            raise refusal
        if not any(_hook_is_safe_yolo(hook) for hook in entries):
            others.append(group)
        elif group.get("matcher") != "*" or not all(
            isinstance(hook, dict)
            and hook.get("type") == "command"
            and is_safe_yolo_command(hook.get("command"), home, entry)
            for hook in entries
        ):
            raise refusal
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
        },
        *others,
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


OPENCODE_PLUGIN_TEMPLATE = Path("adapters") / "opencode_v2_plugin.js"
_OPENCODE_COMMAND_SLOT = "/* SAFE_YOLO_COMMAND */ []"


def render_opencode_plugin(release: Path, command: str) -> bytes:
    """The OpenCode plugin of this release, calling exactly this pinned command."""
    template = (release / OPENCODE_PLUGIN_TEMPLATE).read_text(encoding="utf-8")
    if template.count(_OPENCODE_COMMAND_SLOT) != 1:
        raise RuntimeError("OpenCode plugin template has no single command slot.")
    return template.replace(_OPENCODE_COMMAND_SLOT, json.dumps(shlex.split(command))).encode()


def looks_like_safe_yolo_plugin(payload: bytes) -> bool:
    """Recognise a Safe YOLO OpenCode plugin from any release, V1 hand-placed copies included."""
    text = payload.decode("utf-8", errors="replace")
    return all(marker in text for marker in ("bootstrap.py", "--manifest-sha256", "opencode_v3"))


def prepare_opencode_plugin(path: Path) -> tuple[bytes | None, int]:
    """Previous bytes and mode of the plugin file Safe YOLO is about to own."""
    if not path.exists() and not path.is_symlink():
        return None, 0o600
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("OpenCode plugin path is unavailable or unsafe.")
    original = path.read_bytes()
    if not looks_like_safe_yolo_plugin(original):
        raise RuntimeError(
            f"{path} is not a Safe YOLO plugin. Safe YOLO will not overwrite another plugin; "
            "move it aside through operator review first."
        )
    return original, path.stat().st_mode & 0o777


def inspect_opencode_wiring(
    path: Path,
    home: Path,
    release: Path,
    digest: str,
    *,
    user_home: Path | None = None,
    harness_home: Path | None = None,
) -> dict[str, Any]:
    command = pinned_command(
        home, release, digest, "opencode_v3", user_home=user_home, harness_home=harness_home
    )
    try:
        actual = path.read_bytes()
        expected = render_opencode_plugin(release, command)
    except (OSError, RuntimeError) as error:
        return {"healthy": False, "problems": [f"OpenCode plugin unreadable: {type(error).__name__}"]}
    if actual != expected:
        return {
            "healthy": False,
            "problems": ["OpenCode plugin is not the Safe YOLO plugin pinned to the expected release"],
        }
    return {"healthy": True, "problems": []}
