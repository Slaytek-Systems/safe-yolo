from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adapters.codex_v3 import SAFE_METHODS, expand_scratch_paths
from adapters.hook_payload import normalize_hook_payload
from engine.consequences_v3 import DenyOnlyKernel


BASH_NAMES = {"run_terminal_command", "bash"}
READ_NAMES = {"read_file", "read"}
EDIT_NAMES = {
    "search_replace",
    "write_file",
    "create_file",
    "edit_file",
    "edit",
    "write",
    "multiedit",
    "multi_edit",
}
DELETE_NAMES = {"delete_file", "delete"}
PATH_KEYS = ("path", "file_path", "target_file", "filePath")
PROJECT_CLAUDE = ("settings.json", "settings.local.json")


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def build_kernel(
    *,
    safe_yolo_home: str | Path,
    grok_home: str | Path,
    user_home: str | Path,
    cwd: str | Path | None = None,
    scratch_paths: tuple[str, ...] | None = None,
    observation_dir: str | Path | None = None,
) -> DenyOnlyKernel:
    safe_yolo = Path(safe_yolo_home).expanduser()
    grok = Path(grok_home).expanduser()
    home = Path(user_home).expanduser()
    enforcement = [
        str(safe_yolo),
        str(grok / "config.toml"),
        str(grok / "hooks"),
        str(home / ".claude" / "settings.json"),
        str(home / ".claude" / "settings.local.json"),
        str(home / ".cursor" / "hooks.json"),
    ]
    if cwd:
        project = Path(cwd).expanduser()
        enforcement.append(str(project / ".grok" / "hooks"))
        enforcement.extend(str(project / ".claude" / name) for name in PROJECT_CLAUDE)
        enforcement.append(str(project / ".cursor" / "hooks.json"))
    return DenyOnlyKernel(
        customizations_path=safe_yolo / 'customizations.json',
        observation_dir=observation_dir,
        observation_harness="grok",
        enforcement_paths=tuple(enforcement),
        credential_paths=(
            str(grok / "auth.json"),
            str(home / ".claude" / ".credentials.json"),
            str(home / ".ssh"),
            str(home / ".gnupg"),
        ),
        scratch_paths=expand_scratch_paths(scratch_paths, home),
    )


def _first_path(tool_input: dict[str, Any]) -> str:
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_hook_payload(payload)
    tool_name = str(normalized.get("tool_name") or "").lower()
    tool_input = normalized.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    mapped_input = dict(tool_input)
    if tool_name in BASH_NAMES:
        normalized["tool_name"] = "bash"
    elif tool_name in READ_NAMES:
        path = _first_path(mapped_input)
        if path:
            mapped_input["file_path"] = path
        normalized["tool_name"] = "read"
        normalized["tool_input"] = mapped_input
    elif tool_name in EDIT_NAMES:
        path = _first_path(mapped_input)
        if path:
            mapped_input["file_path"] = path
        normalized["tool_name"] = "edit"
        normalized["tool_input"] = mapped_input
    elif tool_name in DELETE_NAMES:
        path = _first_path(mapped_input)
        if path:
            mapped_input["path"] = path
        normalized["tool_name"] = "delete_file"
        normalized["tool_input"] = mapped_input
    return normalized


def handle_pre_tool(
    payload: dict[str, Any],
    kernel: DenyOnlyKernel,
) -> dict[str, Any] | None:
    payload = normalize_hook_payload(payload)
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    decision = kernel.evaluate(normalize_payload(payload))
    if decision.outcome == "allow":
        return None
    consequence = str(decision.consequence)
    safe_method = SAFE_METHODS.get(consequence, "use a different safe method")
    return _deny(
        f"Safe YOLO denied [{consequence}]: {decision.display}. "
        f"Use a different safe method: {safe_method}."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO deny-only Grok consequence hook.")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--grok-home", type=Path, default=Path("~/.grok").expanduser())
    parser.add_argument("--user-home", type=Path, default=Path.home())
    parser.add_argument(
        "--scratch",
        action="append",
        default=None,
        metavar="PATH",
        help="Trusted scratch root. Repeatable; replaces the default /tmp and ~/tmp.",
    )
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, dict):
        response = None
    else:
        kernel = build_kernel(
            safe_yolo_home=args.safe_yolo_home,
            grok_home=args.grok_home,
            user_home=args.user_home,
            cwd=payload.get("cwd") if isinstance(payload.get("cwd"), str) else None,
            scratch_paths=tuple(args.scratch) if args.scratch is not None else None,
            observation_dir=args.state_dir,
        )
        response = handle_pre_tool(payload, kernel)
    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
