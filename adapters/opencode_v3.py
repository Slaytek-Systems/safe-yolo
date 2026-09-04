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


EDIT_NAMES = {"edit", "write"}
READ_NAMES = {"read"}
PATCH_NAMES = {"patch", "apply_patch"}
PATH_KEYS = ("filePath", "file_path", "path")
PATCH_KEYS = ("patchText", "patch_text", "patch", "input")


def _allow(reason: str = "no explicit restriction matched") -> dict[str, str]:
    return {"decision": "allow", "policy_id": "v3.allow", "reason": reason}


def _deny(policy_id: str, reason: str) -> dict[str, str]:
    return {"decision": "deny", "policy_id": policy_id, "reason": reason}


def build_kernel(
    *,
    safe_yolo_home: str | Path,
    opencode_config: str | Path,
    user_home: str | Path,
    cwd: str | Path | None = None,
    scratch_paths: tuple[str, ...] | None = None,
) -> DenyOnlyKernel:
    safe_yolo = Path(safe_yolo_home).expanduser()
    config = Path(opencode_config).expanduser()
    home = Path(user_home).expanduser()
    enforcement = [
        str(safe_yolo),
        str(config / "opencode.json"),
        str(config / "opencode.jsonc"),
        str(config / "plugins"),
    ]
    if cwd:
        project = Path(cwd).expanduser()
        enforcement.extend(
            (
                str(project / "opencode.json"),
                str(project / "opencode.jsonc"),
                str(project / ".opencode"),
            )
        )
    return DenyOnlyKernel(
        enforcement_paths=tuple(enforcement),
        credential_paths=(
            str(home / ".local" / "share" / "opencode" / "auth.json"),
            str(home / ".ssh"),
            str(home / ".gnupg"),
        ),
        scratch_paths=expand_scratch_paths(scratch_paths, home),
    )


def _first(values: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = values.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_hook_payload(payload)
    args = normalized.get("args") or normalized.get("tool_input") or {}
    if not isinstance(args, dict):
        args = {}
    tool = str(normalized.get("tool") or normalized.get("tool_name") or "")
    lower = tool.lower()
    tool_input = dict(args)
    if lower == "bash":
        command = args.get("command", args.get("cmd", ""))
        tool_input = {"command": command if isinstance(command, str) else ""}
        mapped = "bash"
    elif lower in EDIT_NAMES:
        path = _first(args, PATH_KEYS)
        if path:
            tool_input["file_path"] = path
        mapped = "edit"
    elif lower in READ_NAMES:
        path = _first(args, PATH_KEYS)
        tool_input = {"file_path": path}
        mapped = "read"
    elif lower in PATCH_NAMES:
        patch = _first(args, PATCH_KEYS)
        tool_input = {"patch": patch}
        mapped = "apply_patch"
    else:
        mapped = tool or "unknown"
    cwd = normalized.get("cwd")
    session_id = str(normalized.get("session_id") or "")
    call_id = str(normalized.get("call_id") or "")
    result = {
        "tool_name": mapped,
        "tool_input": tool_input,
    }
    if isinstance(cwd, str) and cwd:
        result["cwd"] = cwd
    if session_id:
        result["session_id"] = session_id
    if call_id:
        result["turn_id"] = call_id
    return result


def handle(payload: dict[str, Any], kernel: DenyOnlyKernel) -> dict[str, str]:
    decision = kernel.evaluate(normalize_payload(payload))
    if decision.outcome == "allow":
        return _allow()
    consequence = str(decision.consequence)
    safe_method = SAFE_METHODS.get(consequence, "use a different safe method")
    return _deny(
        consequence,
        f"Safe YOLO denied [{consequence}]: {decision.display}. "
        f"Use a different safe method: {safe_method}.",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO deny-only OpenCode consequence hook.")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument(
        "--opencode-config",
        type=Path,
        default=Path("~/.config/opencode").expanduser(),
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
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        json.dump(
            _deny("payload.invalid", f"Safe YOLO fail-closed: invalid OpenCode hook payload ({error})."),
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0
    if not isinstance(payload, dict):
        json.dump(
            _deny("payload.invalid", "Safe YOLO fail-closed: OpenCode hook payload must be a JSON object."),
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0
    cwd = payload.get("cwd")
    kernel = build_kernel(
        safe_yolo_home=args.safe_yolo_home,
        opencode_config=args.opencode_config,
        user_home=args.user_home,
        cwd=cwd if isinstance(cwd, str) else None,
        scratch_paths=tuple(args.scratch) if args.scratch is not None else None,
    )
    json.dump(handle(payload, kernel), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
