from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adapters.codex_v3 import SAFE_METHODS, expand_scratch_paths
from engine.consequences_v3 import DenyOnlyKernel


def build_kernel(
    *,
    safe_yolo_home: str | Path,
    devin_config: str | Path,
    user_home: str | Path,
    scratch_paths: tuple[str, ...] | None = None,
) -> DenyOnlyKernel:
    home = Path(user_home).expanduser()
    config = Path(devin_config).expanduser()
    return DenyOnlyKernel(
        enforcement_paths=(
            str(Path(safe_yolo_home).expanduser()),
            str(config.parent),
        ),
        credential_paths=(
            str(home / ".ssh"),
            str(home / ".gnupg"),
        ),
        scratch_paths=expand_scratch_paths(scratch_paths, home),
    )


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input")
    if tool_name.lower() == "exec":
        has_shell = isinstance(tool_input, dict) and bool(tool_input.get("shell_id"))
        has_workdir = isinstance(tool_input, dict) and bool(tool_input.get("workdir"))
        normalized["tool_name"] = "stateful_shell" if has_shell and not has_workdir else "exec_command"
    prompt_id = str(payload.get("prompt_id") or "")
    if prompt_id:
        normalized["turn_id"] = prompt_id
    if isinstance(tool_input, dict):
        workdir = tool_input.get("workdir")
        if isinstance(workdir, str) and workdir:
            normalized["cwd"] = workdir
    project_dir = os.environ.get("DEVIN_PROJECT_DIR")
    if "cwd" not in normalized and project_dir:
        normalized["cwd"] = project_dir
    return normalized


def handle_pre_tool(
    payload: dict[str, Any],
    kernel: DenyOnlyKernel,
) -> dict[str, str] | None:
    if payload.get("hook_event_name") != "PreToolUse":
        return None
    decision = kernel.evaluate(normalize_payload(payload))
    if decision.outcome == "allow":
        return None
    consequence = str(decision.consequence)
    safe_method = SAFE_METHODS.get(consequence, "use a different safe method")
    reason = (
        f"Safe YOLO denied [{consequence}]: {decision.display}. "
        f"Use a different safe method: {safe_method}."
    )
    return {"decision": "block", "reason": reason}


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO deny-only Devin consequence hook.")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument(
        "--devin-config",
        type=Path,
        default=Path("~/.config/devin/config.json").expanduser(),
    )
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
    if isinstance(payload, dict):
        response = handle_pre_tool(
            payload,
            build_kernel(
                safe_yolo_home=args.safe_yolo_home,
                devin_config=args.devin_config,
                user_home=args.user_home,
                scratch_paths=tuple(args.scratch) if args.scratch is not None else None,
            ),
        )
        if response is not None:
            json.dump(response, sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
