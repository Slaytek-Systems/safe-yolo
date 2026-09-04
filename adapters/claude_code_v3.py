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
from engine.consequences_v3 import DenyOnlyKernel


PROJECT_SETTINGS = ("settings.json", "settings.local.json")


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
    claude_home: str | Path,
    user_home: str | Path,
    cwd: str | Path | None = None,
    scratch_paths: tuple[str, ...] | None = None,
) -> DenyOnlyKernel:
    safe_yolo = Path(safe_yolo_home).expanduser()
    claude = Path(claude_home).expanduser()
    home = Path(user_home).expanduser()
    enforcement = [
        str(safe_yolo),
        str(claude / "settings.json"),
        str(claude / "settings.local.json"),
        str(claude / "hooks"),
    ]
    if cwd:
        project = Path(cwd).expanduser() / ".claude"
        enforcement.extend(str(project / name) for name in PROJECT_SETTINGS)
    return DenyOnlyKernel(
        enforcement_paths=tuple(enforcement),
        credential_paths=(
            str(claude / ".credentials.json"),
            str(home / ".ssh"),
            str(home / ".gnupg"),
        ),
        scratch_paths=expand_scratch_paths(scratch_paths, home),
    )


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Map Claude Code tool shapes onto the kernel's recognizers."""
    normalized = dict(payload)
    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    if tool_name == "NotebookEdit" and isinstance(tool_input, dict):
        notebook = tool_input.get("notebook_path")
        if isinstance(notebook, str) and notebook:
            normalized["tool_input"] = {**tool_input, "file_path": notebook}
        normalized["tool_name"] = "edit"
    return normalized


def handle_pre_tool(
    payload: dict[str, Any],
    kernel: DenyOnlyKernel,
) -> dict[str, Any] | None:
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
    parser = argparse.ArgumentParser(description="Safe YOLO deny-only Claude Code consequence hook.")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--claude-home", type=Path, default=Path("~/.claude").expanduser())
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
            claude_home=args.claude_home,
            user_home=args.user_home,
            cwd=payload.get("cwd") if isinstance(payload.get("cwd"), str) else None,
            scratch_paths=tuple(args.scratch) if args.scratch is not None else None,
        )
        response = handle_pre_tool(payload, kernel)
    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
