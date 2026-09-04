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
from adapters import grok_v3
from adapters.hook_payload import normalize_hook_payload
from engine.consequences_v3 import DenyOnlyKernel


WRITE_NAMES = {"write"}
EDIT_NAMES = {"strreplace", "editnotebook", "edit_notebook"}
DELETE_NAMES = {"delete"}
SHELL_EVENTS = {"beforeshellexecution"}
READ_EVENTS = {"beforereadfile"}
MCP_EVENTS = {"beforemcpexecution"}
PROMPT_EVENTS = {"beforesubmitprompt"}


def _allow() -> dict[str, str]:
    return {"permission": "allow"}


def _deny(reason: str) -> dict[str, str]:
    return {"permission": "deny", "user_message": reason, "agent_message": reason}


def _fail_closed(detail: str) -> dict[str, str]:
    reason = f"Safe YOLO fail-closed: {detail}"
    return _deny(reason)


def build_kernel(
    *,
    safe_yolo_home: str | Path,
    cursor_home: str | Path,
    user_home: str | Path,
    cwd: str | Path | None = None,
    scratch_paths: tuple[str, ...] | None = None,
) -> DenyOnlyKernel:
    safe_yolo = Path(safe_yolo_home).expanduser()
    cursor = Path(cursor_home).expanduser()
    home = Path(user_home).expanduser()
    enforcement = [
        str(safe_yolo),
        str(cursor / "hooks.json"),
        str(cursor / "hooks"),
    ]
    if cwd:
        enforcement.append(str(Path(cwd).expanduser() / ".cursor" / "hooks.json"))
    return DenyOnlyKernel(
        enforcement_paths=tuple(enforcement),
        credential_paths=(
            str(home / ".ssh"),
            str(home / ".gnupg"),
        ),
        scratch_paths=expand_scratch_paths(scratch_paths, home),
    )


def _cwd(payload: dict[str, Any]) -> str | None:
    for key in ("cwd", "working_directory"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        for key in ("working_directory", "workdir"):
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _compact_event(payload: dict[str, Any]) -> str:
    return str(payload.get("hook_event_name") or "").replace("_", "").lower()


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_hook_payload(payload)
    conversation_id = str(normalized.get("conversation_id") or normalized.get("session_id") or "")
    generation_id = str(normalized.get("generation_id") or normalized.get("turn_id") or "")
    if conversation_id:
        normalized["session_id"] = conversation_id
    if generation_id:
        normalized["turn_id"] = generation_id
    event = _compact_event(normalized)
    cwd = _cwd(normalized)
    if cwd:
        normalized["cwd"] = cwd

    if event in SHELL_EVENTS or (
        event not in MCP_EVENTS
        and "command" in normalized
        and "tool_name" not in payload
        and "toolName" not in payload
    ):
        command = normalized.get("command") or ""
        tool_input: dict[str, Any] = {"command": command}
        if cwd:
            tool_input["workdir"] = cwd
        normalized["tool_name"] = "bash"
        normalized["tool_input"] = tool_input
        return normalized

    if event in READ_EVENTS:
        path = normalized.get("file_path") or normalized.get("path") or ""
        normalized["tool_name"] = "read"
        normalized["tool_input"] = {"file_path": path}
        return normalized

    if event in MCP_EVENTS:
        tool_input = normalized.get("tool_input") or {}
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except json.JSONDecodeError:
                tool_input = {"raw": tool_input}
        normalized["tool_name"] = str(normalized.get("tool_name") or "mcp")
        normalized["tool_input"] = tool_input if isinstance(tool_input, dict) else {"value": tool_input}
        return normalized

    tool_name = str(normalized.get("tool_name") or "")
    tool_input = normalized.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}
    mapped_input = dict(tool_input)
    lower = tool_name.lower()
    if lower in {"editnotebook", "edit_notebook"} and "path" not in mapped_input:
        notebook = mapped_input.get("target_notebook") or mapped_input.get("notebook_path")
        if isinstance(notebook, str) and notebook:
            mapped_input["path"] = notebook
    path = ""
    for key in ("file_path", "path", "target_notebook", "notebook_path"):
        value = mapped_input.get(key)
        if isinstance(value, str) and value:
            path = value
            break
    if lower in grok_v3.BASH_NAMES | grok_v3.READ_NAMES | grok_v3.EDIT_NAMES | grok_v3.DELETE_NAMES:
        # Grok replays Cursor-compatible hooks with its own tool names.
        return grok_v3.normalize_payload(normalized)
    if lower in WRITE_NAMES:
        if path:
            mapped_input["file_path"] = path
        normalized["tool_name"] = "write"
    elif lower in EDIT_NAMES:
        if path:
            mapped_input["file_path"] = path
        normalized["tool_name"] = "edit"
    elif lower in DELETE_NAMES:
        if path:
            mapped_input["path"] = path
        normalized["tool_name"] = "delete_file"
    normalized["tool_input"] = mapped_input
    return normalized


def _reason(decision) -> str:
    consequence = str(decision.consequence)
    safe_method = SAFE_METHODS.get(consequence, "use a different safe method")
    return (
        f"Safe YOLO denied [{consequence}]: {decision.display}. "
        f"Use a different safe method: {safe_method}."
    )


def handle(payload: dict[str, Any], kernel: DenyOnlyKernel) -> dict[str, Any]:
    payload = normalize_hook_payload(payload)
    if _compact_event(payload) in PROMPT_EVENTS:
        return {"continue": True}
    decision = kernel.evaluate(normalize_payload(payload))
    if decision.outcome == "allow":
        return _allow()
    return _deny(_reason(decision))


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO deny-only Cursor consequence hook.")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--cursor-home", type=Path, default=Path("~/.cursor").expanduser())
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
        json.dump(_fail_closed(f"invalid Cursor hook payload ({error})."), sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    if not isinstance(payload, dict):
        json.dump(_fail_closed("Cursor hook payload must be a JSON object."), sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    kernel = build_kernel(
        safe_yolo_home=args.safe_yolo_home,
        cursor_home=args.cursor_home,
        user_home=args.user_home,
        cwd=_cwd(normalize_hook_payload(payload)),
        scratch_paths=tuple(args.scratch) if args.scratch is not None else None,
    )
    json.dump(handle(payload, kernel), sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
