"""Native harness configuration and the stable Safe YOLO hook command."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
import shlex
import sys
from typing import Any, Callable


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"JSON file is unreadable: {path} ({type(error).__name__})") from error
    if not isinstance(document, dict):
        raise RuntimeError(f"JSON document must be an object: {path}")
    return document


def launcher_path(home: Path, harness: str) -> Path:
    """The fixed path of a harness's launcher: a copy of the active release's bootstrap.

    One file per harness, so each harness's install, update and rollback refresh only its own.
    """
    return home / "hooks" / f"{harness}.py"


def stable_arguments(home: Path, harness: str, entry: str) -> list[str]:
    """Everything after the interpreter in the stable command; none of it changes between releases."""
    return [str(launcher_path(home, harness)), "--harness", harness, "--entry", entry, "--safe-yolo-home", str(home)]


def stable_command(home: Path, harness: str, entry: str) -> str:
    """The hook command a harness runs. The release and its digest come from the install receipt."""
    return shlex.join([sys.executable, *stable_arguments(home, harness, entry)])


def _python_tokens(command: Any) -> list[str] | None:
    if not isinstance(command, str):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    if len(tokens) < 2 or not re.fullmatch(r"python3(\.\d+)?", Path(tokens[0]).name):
        return None
    return tokens


def is_stable_command(command: Any, home: Path, harness: str, entry: str) -> bool:
    """The stable command for this harness, as `shlex.join` spells it, with any python3 interpreter."""
    tokens = _python_tokens(command)
    return (
        tokens is not None
        and shlex.join(tokens) == command
        and tokens[1:] == stable_arguments(home, harness, entry)
    )


def is_safe_yolo_command(command: Any, home: Path, entry: str = "codex_v3") -> bool:
    """Any Safe YOLO hook command under this home: the stable form, or a release pin from 3.0.0-beta.17 or earlier."""
    tokens = _python_tokens(command)
    if tokens is None:
        return False
    bootstrap = Path(tokens[1])
    if bootstrap.parent == home / "hooks":
        return is_stable_command(command, home, bootstrap.stem, entry)
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


def command_hook(command: str) -> dict[str, Any]:
    """The whole hook entry Safe YOLO writes for Codex and Claude Code."""
    return {
        "type": "command",
        "command": command,
        "timeout": 10,
        "statusMessage": "Checking explicit Safe YOLO restrictions",
    }


def prepare_command_hooks(
    path: Path,
    home: Path,
    command: str,
    *,
    entry: str = "codex_v3",
    label: str = "Codex",
    own_slots: Callable[[Any], list[tuple[int, int]]] | None = None,
) -> tuple[dict[str, Any], bytes | None, int]:
    """Write Safe YOLO's PreToolUse hook into a harness hooks document.

    Without `own_slots` Safe YOLO must be the only PreToolUse hook. With it, an
    update replaces the one hook `own_slots` finds and leaves every other hook alone.
    """
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
    if own_slots is None and existing_pretool and not recognized_pretool:
        raise RuntimeError(
            f"{label} already has an existing PreToolUse command hook. "
            "Safe YOLO will not replace a foreign enforcement surface."
        )
    if hooks.get("PostToolUse", []):
        raise RuntimeError(f"{label} has a non-empty PostToolUse lifecycle; Safe YOLO will not replace it.")
    own_hook = command_hook(command)
    if own_slots is None:
        hooks["PreToolUse"] = [{"matcher": "*", "hooks": [own_hook]}]
    else:
        slots = own_slots(existing_pretool)
        if len(slots) != 1:
            raise RuntimeError(f"{label} does not hold exactly one hook from the installed Safe YOLO release.")
        group_index, hook_index = slots[0]
        existing_pretool[group_index]["hooks"][hook_index] = own_hook
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
    """A command that runs one release directly.

    Install runs its canaries through it before the cut-over. Before 3.0.0-beta.18 every
    hook was wired this way, which is why an update changed the command a harness saw.
    """
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


def inspect_cursor_wiring(path: Path, owns: Callable[[str], bool]) -> dict[str, Any]:
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
        if not isinstance(hook.get("command"), str) or not owns(hook["command"]):
            problems.append("Cursor preToolUse hook is not the command Safe YOLO installed")
    return {"healthy": not problems, "problems": problems}


OPENCODE_PLUGIN_TEMPLATE = Path("adapters") / "opencode_v2_plugin.js"
_OPENCODE_COMMAND_SLOT = "/* SAFE_YOLO_COMMAND */ []"


def render_opencode_plugin(release: Path, command: str) -> bytes:
    """The OpenCode plugin of this release, calling exactly this command."""
    template = (release / OPENCODE_PLUGIN_TEMPLATE).read_text(encoding="utf-8")
    if template.count(_OPENCODE_COMMAND_SLOT) != 1:
        raise RuntimeError("OpenCode plugin template has no single command slot.")
    return template.replace(_OPENCODE_COMMAND_SLOT, json.dumps(shlex.split(command))).encode()


OPENCODE_V1_TEMPLATE = Path("adapters") / "opencode_v1_retired_plugin.js"
_OPENCODE_V1_PINS = re.compile(
    rb'^(const (?:PYTHON|BOOTSTRAP|RELEASE|MANIFEST_SHA256|STATE_DIR) = )"[^"\\\n]*";$', re.MULTILINE
)


def _without_v1_pins(payload: bytes) -> bytes:
    return _OPENCODE_V1_PINS.sub(rb'\1"";', payload)


def opencode_plugin_path_problem(path: Path) -> str | None:
    """Safe YOLO manages only a regular plugin file whose folder is inside the selected config root."""
    if path.is_symlink():
        return f"{path} is a symlink; Safe YOLO manages only a regular plugin file."
    if Path(os.path.realpath(path.parent)) != path.parent:
        return f"{path.parent} is a symlink; Safe YOLO writes only inside the selected OpenCode config folder."
    return None


def prepare_opencode_plugin(path: Path, release: Path, owned: list[bytes]) -> tuple[bytes | None, int]:
    """Previous bytes and mode of the plugin file Safe YOLO is about to own.

    The file is Safe YOLO's only when it is byte-identical to a plugin rendered from an
    installed release (`owned`) or is the retired V1 template with only its pins changed.
    """
    problem = opencode_plugin_path_problem(path)
    if problem:
        raise RuntimeError(problem)
    if not path.exists():
        return None, 0o600
    if not path.is_file():
        raise RuntimeError("OpenCode plugin path is unavailable or unsafe.")
    original = path.read_bytes()
    retired_v1 = _without_v1_pins((release / OPENCODE_V1_TEMPLATE).read_bytes())
    if original not in owned and _without_v1_pins(original) != retired_v1:
        raise RuntimeError(
            f"{path} is not a Safe YOLO plugin. Safe YOLO will not overwrite another plugin; "
            "move it aside through operator review first."
        )
    return original, path.stat().st_mode & 0o777


def inspect_opencode_wiring(path: Path, release: Path, commands: list[str]) -> dict[str, Any]:
    """Whether the plugin file is this release's plugin calling one of `commands`."""
    problem = opencode_plugin_path_problem(path)
    if problem:
        return {"healthy": False, "problems": [problem]}
    try:
        actual = path.read_bytes()
        expected = [render_opencode_plugin(release, command) for command in commands]
    except (OSError, RuntimeError) as error:
        return {"healthy": False, "problems": [f"OpenCode plugin unreadable: {type(error).__name__}"]}
    if actual not in expected:
        return {
            "healthy": False,
            "problems": ["OpenCode plugin is not the Safe YOLO plugin this installation wrote"],
        }
    return {"healthy": True, "problems": []}


ANTIGRAVITY_GROUP = "safe-yolo"


def antigravity_hooks_path_problem(path: Path) -> str | None:
    """Safe YOLO manages only a regular hooks file whose folder is inside the selected Antigravity root."""
    root = path.parents[1]
    if path.parent.is_symlink():
        return f"{path.parent} is a symlink; Safe YOLO writes only inside the selected Antigravity root."
    if path.is_symlink() or (path.exists() and not path.is_file()):
        return f"{path} is not a regular file; Safe YOLO manages only a regular hooks file."
    if not Path(os.path.realpath(path)).is_relative_to(root):
        return f"{path} resolves outside {root}; Safe YOLO writes only inside the selected Antigravity root."
    return None


def config_path_problem(harness: str, path: Path) -> str | None:
    """Why Safe YOLO must not touch this harness file in place, or None."""
    check = {"opencode": opencode_plugin_path_problem, "antigravity": antigravity_hooks_path_problem,
             "antigravity-t3": antigravity_hooks_path_problem}.get(harness)
    return check(path) if check else None


def antigravity_group(command: str) -> dict[str, Any]:
    """The whole named group Safe YOLO writes into Antigravity's hooks.json."""
    return {
        "enabled": True,
        "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 10}]}],
    }


def antigravity_group_command(group: Any) -> str | None:
    """The command of a group shaped field for field like `antigravity_group`, else None."""
    try:
        hook = group["PreToolUse"][0]["hooks"][0]
        command = hook["command"]
    except (KeyError, IndexError, TypeError):
        return None
    if (
        not isinstance(command, str)
        or group != antigravity_group(command)
        or group["enabled"] is not True
        or type(hook["timeout"]) is not int
    ):
        return None
    return command


def read_antigravity_hooks(path: Path) -> dict[str, Any]:
    """Antigravity's hooks document, refused when writing it back could change a value or break the file."""
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: set[str] = set()
        for key, _ in pairs:
            if key in seen:
                raise ValueError(f"duplicate key {key!r}")
            seen.add(key)
        return dict(pairs)

    def exact(parse: Callable[[str], Any]) -> Callable[[str], Any]:
        def number(literal: str) -> Any:
            value = parse(literal)
            if json.dumps(value) != literal:
                raise ValueError(f"number {literal} would not be written back as {literal}")
            return value
        return number

    def not_json(literal: str) -> Any:
        raise ValueError(f"{literal} is not a JSON number")

    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_keys,
            parse_float=exact(float),
            parse_int=exact(int),
            parse_constant=not_json,
        )
    except (OSError, ValueError) as error:
        raise RuntimeError(
            f"Antigravity hooks file is unreadable or cannot be rewritten unchanged: {path} ({error})"
        ) from error
    if not isinstance(document, dict):
        raise RuntimeError(f"Antigravity hooks file must be a JSON object: {path}")
    return document


def is_hand_wired_antigravity_group(group: Any, home: Path) -> bool:
    """A group shaped like the installer's that runs a verified release already under this Safe YOLO home.

    This is how Antigravity was wired by hand before it had an install lifecycle.
    """
    from scripts.doctor import _release_exposes_entry
    from scripts.release_manifest import verify_manifest

    command = antigravity_group_command(group)
    if command is None or not is_safe_yolo_command(command, home, "antigravity_v3"):
        return False
    tokens = shlex.split(command)
    flags = dict(zip(tokens[2::2], tokens[3::2]))
    if "--release" not in flags:
        return False
    release = Path(flags["--release"])
    bootstrap = Path(tokens[1])
    return (
        release.parent == home / "releases"
        and bootstrap in (release / "scripts" / "bootstrap.py", home / "bootstrap.py")
        and bootstrap.is_file()
        and bool(flags["--manifest-sha256"])
        and not verify_manifest(release, flags["--manifest-sha256"])
        and _release_exposes_entry(release, "antigravity_v3")
    )


def prepare_antigravity_hooks(
    path: Path, command: str, owns: Callable[[Any], bool]
) -> tuple[dict[str, Any], bytes | None, int]:
    """Antigravity's hooks document with Safe YOLO's named group set; every other group is left as found."""
    original_bytes: bytes | None = None
    mode = 0o600
    document: dict[str, Any] = {}
    problem = antigravity_hooks_path_problem(path)
    if problem:
        raise RuntimeError(problem)
    if path.exists():
        original_bytes = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        document = read_antigravity_hooks(path)
    if ANTIGRAVITY_GROUP in document and not owns(document[ANTIGRAVITY_GROUP]):
        raise RuntimeError(
            f"{path} already has a {ANTIGRAVITY_GROUP!r} hook group that this Safe YOLO installation did not "
            "write. Safe YOLO will not replace it; move it aside through operator review first."
        )
    document[ANTIGRAVITY_GROUP] = antigravity_group(command)
    return document, original_bytes, mode
