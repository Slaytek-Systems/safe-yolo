from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
import shlex
import tomllib
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.harness_wiring import (
    ANTIGRAVITY_GROUP,
    antigravity_group_command,
    antigravity_hooks_path_problem,
    command_hook,
    read_antigravity_hooks,
)
from scripts.release_manifest import ENTRYPOINTS, verify_manifest


def inspect_release(release_dir: str | Path, expected_manifest_hash: str | None = None) -> dict[str, Any]:
    release = Path(release_dir).resolve()
    problems = verify_manifest(release, expected_manifest_hash)
    version_path = release / "VERSION"
    version = version_path.read_text(encoding="utf-8").strip() if version_path.is_file() else "unknown"
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
    safe_yolo_home: str | Path | None = None,
    user_home: str | Path | None = None,
    harness_home: str | Path | None = None,
) -> dict[str, Any]:
    """Read-only check for the pinned Codex hook lifecycle of one release entry."""
    problems: list[str] = []
    try:
        config = tomllib.loads(Path(config_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        return {"healthy": False, "problems": [f"config unreadable: {type(error).__name__}"]}
    if config.get("approval_policy") != "never":
        problems.append("approval_policy must be never")
    if config.get("sandbox_mode") != "danger-full-access":
        problems.append("sandbox_mode must be danger-full-access")
    features = config.get("features", {})
    if isinstance(features, dict) and features.get("hooks") is False:
        problems.append("hooks feature must be enabled")
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
        safe_yolo_home=safe_yolo_home,
        user_home=user_home,
        harness_home=harness_home,
    ):
        problems.append("PreToolUse hook is not pinned to the expected Safe YOLO bootstrap release")
    if not _release_exposes_entry(release_path, entry):
        problems.append(f"release does not expose the expected entrypoint: {entry}")
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
    if entry in {"codex_v3", "claude_code_v3", "grok_v3", "cursor_v3", "opencode_v3", "antigravity_v3"} and _command_hooks(hooks, "PostToolUse"):
        problems.append(f"PostToolUse command hooks must be absent for {entry}")
    return {"healthy": not problems, "problems": problems}


CODEX_SKIPS_SAFE_YOLO = "Codex will skip Safe YOLO until you approve it in /hooks"


# The fields and value types Codex 0.172.0 accepts. Anything else means "unknown", never "approved".
_STRING, _COUNT, _NONE = (str,), (int,), (type(None),)
_GROUP_FIELDS = {"matcher": _STRING + _NONE, "hooks": (list,)}
_HOOK_FIELDS = {"type": _STRING, "command": _STRING, "timeout": _COUNT + _NONE, "async": (bool,),
                "statusMessage": _STRING + _NONE, "additionalContextLimit": _COUNT + _NONE}
_STATE_FIELDS = {"enabled": (bool,), "trusted_hash": _STRING, "trusted_content_hash": _STRING}


def _has_shape(table: Any, fields: dict[str, tuple[type, ...]]) -> bool:
    return isinstance(table, dict) and all(
        type(value) in fields.get(key, ()) and not (type(value) is int and value < 0) for key, value in table.items())


def codex_hook_hash(group: dict[str, Any], hook: dict[str, Any]) -> str | None:
    """The hash Codex 0.172.0 compares with a PreToolUse command hook's saved `trusted_hash`.

    codex-rs/hooks/src/engine/discovery.rs `hook_hash` and codex-rs/config/src/fingerprint.rs
    `version_for_toml`: the normalized hook as sorted, compact, unescaped JSON. None when the hook
    has a field or value this does not model.
    """
    if not (_has_shape(group, _GROUP_FIELDS) and _has_shape(hook, _HOOK_FIELDS)
            and hook.get("type") == "command" and hook.get("command", "").strip()):
        return None
    timeout = hook.get("timeout")
    handler = {"type": "command", "command": hook["command"], "timeout": max(1, 600 if timeout is None else timeout),
               "async": hook.get("async", False)}
    if hook.get("statusMessage") is not None:
        handler["statusMessage"] = hook["statusMessage"]
    if hook.get("additionalContextLimit") not in (None, 2500):
        handler["additionalContextLimit"] = hook["additionalContextLimit"]
    identity: dict[str, Any] = {"event_name": "pre_tool_use", "hooks": [handler]}
    if group.get("matcher") is not None:
        identity["matcher"] = group["matcher"]
    serialized = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(serialized.encode()).hexdigest()


def codex_hook_approval(hooks_path: str | Path, config_path: str | Path) -> tuple[str, str | None]:
    """Read-only: whether Codex will run the one PreToolUse command hook in hooks.json.

    Returns ("approved", None), ("not approved", reason) or ("unknown", reason). Codex skips a
    user hook unless config.toml saves a `trusted_hash` equal to the hook's current hash.
    """
    hooks_path, config_path = Path(hooks_path).absolute(), Path(config_path)
    try:
        groups = json.loads(hooks_path.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
        slots = [(group_index, hook_index, group, hook)
                 for group_index, group in enumerate(groups)
                 for hook_index, hook in enumerate(group["hooks"]) if hook.get("type") == "command"]
    except (OSError, ValueError, LookupError, TypeError, AttributeError) as error:
        return "unknown", f"cannot read hooks.json: {type(error).__name__}"
    if len(slots) != 1:
        return "unknown", "hooks.json does not hold exactly one PreToolUse command hook"
    group_index, hook_index, group, hook = slots[0]
    current = codex_hook_hash(group, hook)
    if current is None:
        return "unknown", "hooks.json has a hook field Safe YOLO does not check"
    try:
        hooks = tomllib.loads(config_path.read_text(encoding="utf-8")).get("hooks", {})
    except (OSError, ValueError) as error:
        return "unknown", f"cannot read config.toml: {type(error).__name__}"
    states = hooks.get("state", {}) if isinstance(hooks, dict) else None
    if not isinstance(states, dict) or not all(_has_shape(state, _STATE_FIELDS) for state in states.values()):
        return "unknown", "config.toml has a saved hook state Codex would reject"
    state = states.get(f"{hooks_path}:pre_tool_use:{group_index}:{hook_index}", {})
    if state.get("enabled") is False:
        return "not approved", "the hook is turned off"
    if "trusted_hash" not in state:
        return "not approved", "no approval is saved"
    if state["trusted_hash"] != current:
        return "not approved", "the saved approval is for a different hook"
    return "approved", None


def inspect_claude_code_wiring(
    settings_path: str | Path,
    bootstrap_path: str | Path,
    manifest_sha256: str,
    *,
    release_path: str | Path,
    entry: str = "claude_code_v3",
    safe_yolo_home: str | Path | None = None,
    user_home: str | Path | None = None,
    harness_home: str | Path | None = None,
    state_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Read-only check that Claude Code user settings pin one Safe YOLO PreToolUse hook."""
    problems: list[str] = []
    try:
        document = json.loads(Path(settings_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"healthy": False, "problems": [f"settings unreadable: {type(error).__name__}"]}
    if not isinstance(document, dict):
        return {"healthy": False, "problems": ["settings document must be an object"]}
    if document.get("disableAllHooks"):
        problems.append("disableAllHooks must not be set")
    hooks = document.get("hooks", {})
    groups = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    slots = pinned_hook_slots(
        groups,
        bootstrap_path=bootstrap_path,
        release_path=release_path,
        manifest_sha256=manifest_sha256,
        entry=entry,
        safe_yolo_home=safe_yolo_home,
        user_home=user_home,
        harness_home=harness_home,
        state_dir=state_dir,
    )
    if len(slots) > 1:
        problems.append("exactly one Safe YOLO PreToolUse command hook is required")
    elif not slots or groups[slots[0][0]].get("matcher", "") not in ("*", ""):
        problems.append("PreToolUse hook is not pinned to the expected Safe YOLO bootstrap release")
    if not _release_exposes_entry(release_path, entry):
        problems.append(f"release does not expose the expected entrypoint: {entry}")
    return {"healthy": not problems, "problems": problems}


def _release_exposes_entry(release_path: str | Path, entry: str) -> bool:
    expected = ENTRYPOINTS.get(entry)
    if expected is None:
        return False
    release = Path(release_path)
    try:
        manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(manifest.get("entrypoints"), dict)
        and manifest["entrypoints"].get(entry) == expected
        and (release / expected).is_file()
    )


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


def pinned_hook_slots(groups: Any, **pin: Any) -> list[tuple[int, int]]:
    """Positions, as (group, hook), of each hook that is, field for field, the entry Safe YOLO writes for this pin.

    Claude Code install, doctor and uninstall all find Safe YOLO's hook here.
    Every other hook belongs to someone else and is neither read nor judged.
    """
    if not isinstance(groups, list):
        return []
    return [
        (group_index, hook_index)
        for group_index, group in enumerate(groups)
        if isinstance(group, dict) and isinstance(group.get("hooks"), list)
        for hook_index, hook in enumerate(group["hooks"])
        if isinstance(hook, dict)
        and isinstance(hook.get("command"), str)
        and hook == command_hook(hook["command"])
        and type(hook["timeout"]) is int
        and _is_installer_spelling(hook["command"])
        and _command_is_pinned(hook["command"], **pin)
    ]


def owns_antigravity_group(group: Any, **pin: Any) -> bool:
    """Whether this named group is, field for field, the one Safe YOLO writes for this pin."""
    command = antigravity_group_command(group)
    return command is not None and _is_installer_spelling(command) and _command_is_pinned(command, **pin)


def inspect_antigravity_wiring(path: str | Path, **pin: Any) -> dict[str, Any]:
    """Read-only check of Safe YOLO's named group in Antigravity's hooks.json; other groups are not judged."""
    problem = antigravity_hooks_path_problem(Path(path))
    if problem:
        return {"healthy": False, "problems": [problem]}
    try:
        document = read_antigravity_hooks(Path(path))
    except RuntimeError as error:
        return {"healthy": False, "problems": [str(error)]}
    problems: list[str] = []
    if not owns_antigravity_group(document.get(ANTIGRAVITY_GROUP), **pin):
        problems.append("Antigravity safe-yolo hook group is not the one Safe YOLO installed")
    if not _release_exposes_entry(pin["release_path"], pin["entry"]):
        problems.append(f"release does not expose the expected entrypoint: {pin['entry']}")
    return {"healthy": not problems, "problems": problems}


INSTALLER_FLAG_ORDER = (
    "--release", "--manifest-sha256", "--entry", "--state-dir", "--safe-yolo-home", "--user-home", "--harness-home",
)


def _is_installer_spelling(command: str) -> bool:
    # The installer writes shlex.join output with its flags in one order. Any other
    # spelling may parse alike and run differently, so it is not the installed entry.
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    flags = tuple(tokens[2::2])
    return shlex.join(tokens) == command and flags == INSTALLER_FLAG_ORDER[: len(flags)]


def _command_is_pinned(
    command: str,
    *,
    bootstrap_path: str | Path,
    release_path: str | Path,
    manifest_sha256: str,
    entry: str,
    safe_yolo_home: str | Path | None = None,
    user_home: str | Path | None = None,
    harness_home: str | Path | None = None,
    state_dir: str | Path | None = None,
) -> bool:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return False

    if len(tokens) < 2 or not re.fullmatch(r"python3(\.\d+)?", Path(tokens[0]).name):
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
        "--safe-yolo-home",
        "--user-home",
        "--harness-home",
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
    if entry in {"codex_v2", "codex_v3", "claude_code_v3", "grok_v3", "cursor_v3", "opencode_v3", "antigravity_v3"} and (
        "--host-contract" in values or "--audit-only" in booleans
    ):
        return False
    context_expected = {
        "--safe-yolo-home": safe_yolo_home,
        "--user-home": user_home,
        "--harness-home": harness_home,
    }
    for flag, expected in context_expected.items():
        actual = values.get(flag)
        if expected is None:
            if actual is not None:
                return False
        elif actual != str(expected):
            return False
    return (
        values.get("--release") == str(release_path)
        and values.get("--manifest-sha256") == manifest_sha256
        and values.get("--entry") == entry
        and (state_dir is None or values.get("--state-dir") == str(state_dir))
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
    parser.add_argument(
        "--entry",
        choices=("codex", "codex_v2", "codex_v3", "claude_code_v3", "grok_v3", "cursor_v3", "opencode_v3", "antigravity_v3"),
        default="codex",
    )
    parser.add_argument("--claude-settings", type=Path)
    args = parser.parse_args()
    report = inspect_release(args.release, args.manifest_sha256)
    if args.claude_settings is not None:
        if args.bootstrap is None or not args.manifest_sha256:
            parser.error("--claude-settings requires --bootstrap and --manifest-sha256")
        wiring = inspect_claude_code_wiring(
            args.claude_settings,
            args.bootstrap,
            str(args.manifest_sha256),
            release_path=args.release,
            entry="claude_code_v3",
        )
        report["claude_code_wiring"] = wiring
        report["healthy"] = bool(report["healthy"] and wiring["healthy"])
        report["problems"].extend(
            f"claude code wiring: {problem}" for problem in wiring["problems"]
        )
        print(json.dumps(report, sort_keys=True))
        return 0
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
