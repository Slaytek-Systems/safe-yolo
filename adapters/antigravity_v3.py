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


EXEC_NAMES = {"run_command", "shell"}
EDIT_NAMES = {
    "create_file",
    "edit_file",
    "write_file",
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
    "client_create_file",
    "client_edit_file",
}
READ_NAMES = {"view_file", "read_file", "client_view_file"}
COMMAND_KEYS = ("CommandLine", "commandLine", "command_line", "Command", "command", "cmd")
WORKDIR_KEYS = ("Cwd", "cwd", "WorkingDirectory", "working_directory", "workdir")
PATH_KEYS = (
    "AbsolutePath",
    "TargetFile",
    "FilePath",
    "Path",
    "absolutePath",
    "targetFile",
    "filePath",
    "file_path",
    "path",
)
MCP_SERVER_KEYS = ("ServerName", "serverName", "server_name")
MCP_TOOL_KEYS = ("ToolName", "toolName", "tool_name")
PROJECT_HOOKS = (
    Path(".agents") / "hooks.json",
    Path(".agent") / "hooks.json",
    Path("_agents") / "hooks.json",
    Path("_agent") / "hooks.json",
)


def _deny(reason: str) -> dict[str, str]:
    return {"decision": "deny", "reason": reason}


def _first(values: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = values.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def _workspace_cwd(payload: dict[str, Any]) -> str:
    paths = payload.get("workspacePaths")
    if isinstance(paths, list) and paths:
        first = paths[0]
        if isinstance(first, str) and first:
            return first
    return str(Path.cwd())


def resolve_gemini_home(*, gemini_home: str | Path | None, user_home: str | Path) -> Path:
    if gemini_home is not None:
        return Path(gemini_home).expanduser()
    env = os.environ.get("GEMINI_HOME")
    if env:
        return Path(env).expanduser()
    return Path(user_home).expanduser() / ".gemini"


def build_kernel(
    *,
    safe_yolo_home: str | Path,
    gemini_home: str | Path,
    user_home: str | Path,
    cwd: str | Path | None = None,
    scratch_paths: tuple[str, ...] | None = None,
    observation_dir: str | Path | None = None,
) -> DenyOnlyKernel:
    safe_yolo = Path(safe_yolo_home).expanduser()
    gemini = Path(gemini_home).expanduser()
    home = Path(user_home).expanduser()
    default_gemini = home / ".gemini"
    enforcement = [
        str(safe_yolo),
        str(gemini / "config" / "hooks.json"),
        str(gemini / "config"),
        str(gemini / "antigravity-acp" / "settings.json"),
        str(gemini / "antigravity-acp" / "trusted_workspaces.json"),
        str(default_gemini / "config"),
    ]
    if cwd:
        project = Path(cwd).expanduser()
        enforcement.extend(str(project / relative) for relative in PROJECT_HOOKS)
    return DenyOnlyKernel(
        observation_dir=observation_dir,
        observation_harness="antigravity",
        enforcement_paths=tuple(enforcement),
        credential_paths=(
            str(gemini / "antigravity-acp" / "acp_token.json"),
            str(gemini / "antigravity-acp" / "acp_business_token.json"),
            str(home / ".ssh"),
            str(home / ".gnupg"),
        ),
        scratch_paths=expand_scratch_paths(scratch_paths, home),
    )


def normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    tool_call = payload.get("toolCall")
    if not isinstance(tool_call, dict):
        tool_call = {}
    tool_name = str(tool_call.get("name") or "")
    tool_input = tool_call.get("args")
    if not isinstance(tool_input, dict):
        tool_input = {}
    mapped_input = dict(tool_input)
    lower = tool_name.lower()
    cwd = _workspace_cwd(payload)
    if lower in EXEC_NAMES:
        command = _first(mapped_input, COMMAND_KEYS)
        workdir = _first(mapped_input, WORKDIR_KEYS)
        mapped_input["command"] = command
        if workdir:
            mapped_input["workdir"] = workdir
        mapped = "bash"
    elif lower in EDIT_NAMES:
        path = _first(mapped_input, PATH_KEYS)
        if path:
            mapped_input["file_path"] = path
        mapped = "edit"
    elif lower in READ_NAMES:
        path = _first(mapped_input, PATH_KEYS)
        if path:
            mapped_input["file_path"] = path
        mapped = "read"
    elif lower == "call_mcp_tool":
        server = _first(mapped_input, MCP_SERVER_KEYS)
        mcp_tool = _first(mapped_input, MCP_TOOL_KEYS)
        mapped = f"{server}_{mcp_tool}" if server and mcp_tool else tool_name
    else:
        mapped = tool_name
    return {
        "tool_name": mapped,
        "tool_input": mapped_input,
        "cwd": cwd,
    }


def handle_pre_tool(
    payload: dict[str, Any],
    kernel: DenyOnlyKernel,
) -> dict[str, str] | None:
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
    parser = argparse.ArgumentParser(description="Safe YOLO deny-only Antigravity ACP consequence hook.")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--gemini-home", type=Path, default=None)
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
            _deny(f"Safe YOLO fail-closed [payload.invalid]: invalid Antigravity hook payload ({error})."),
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0
    if not isinstance(payload, dict):
        json.dump(
            _deny("Safe YOLO fail-closed [payload.invalid]: Antigravity hook payload must be a JSON object."),
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0
    gemini_home = resolve_gemini_home(gemini_home=args.gemini_home, user_home=args.user_home)
    kernel = build_kernel(
        safe_yolo_home=args.safe_yolo_home,
        gemini_home=gemini_home,
        user_home=args.user_home,
        cwd=_workspace_cwd(payload),
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
