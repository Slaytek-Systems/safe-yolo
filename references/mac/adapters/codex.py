from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adapters.codex_context import turn_scope  # noqa: E402
from engine.capabilities import CapabilityStore  # noqa: E402
from engine.safe_yolo import SafeYoloEngine, result  # noqa: E402


PATCH_PATH_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$")
WRITE_TOOLS = {"apply_patch", "write", "edit", "multiedit", "multi_edit", "create_file", "write_file"}
SHELL_TOOLS = {"bash", "shell", "exec_command"}


def _strings(value: Any, key: str = ""):
    if isinstance(value, dict):
        for child_key, child in value.items():
            yield from _strings(child, str(child_key).lower())
    elif isinstance(value, list):
        for child in value:
            yield from _strings(child, key)
    elif isinstance(value, str):
        yield key, value


def candidate_write_paths(tool_input: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    path_keys = {"path", "file_path", "filepath", "filename", "target_file", "target_path"}
    for key, value in _strings(tool_input):
        if key in path_keys:
            paths.add(value)
    patch = tool_input.get("patch") or tool_input.get("input")
    if isinstance(patch, str):
        for line in patch.splitlines():
            match = PATCH_PATH_RE.match(line.strip())
            if match:
                paths.add(match.group(1).strip())
    return paths


def request_context(payload: dict[str, Any]) -> dict[str, Any]:
    supplied = payload.get("safe_yolo_context") or {}
    context = dict(supplied) if isinstance(supplied, dict) else {}
    capability_scope = turn_scope(payload)
    if capability_scope:
        context.setdefault("session_id", capability_scope)
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        context.setdefault("cwd", cwd)
    return context


def evaluate_payload(payload: dict[str, Any], engine: SafeYoloEngine) -> dict[str, Any]:
    tool_name = str(payload.get("tool_name") or "").lower()
    tool_input = payload.get("tool_input") or {}
    context = request_context(payload)

    if tool_name in SHELL_TOOLS:
        command = tool_input.get("command") or tool_input.get("cmd") or ""
        if not isinstance(command, str) or not command.strip():
            return result("allow", "codex.empty_shell", "No shell command supplied.")
        return engine.inspect_command(command, context)

    if tool_name in WRITE_TOOLS:
        for path in sorted(candidate_write_paths(tool_input)):
            decision = engine.inspect_path_write(path, context)
            if decision["decision"] != "allow":
                return decision
        return result("allow", "codex.workspace_write", "Structured write targets are permitted.")

    return result("allow", "codex.non_mutating_tool", "Tool is outside the staged mutation adapters.")


def hook_response(decision: dict[str, Any]) -> dict[str, str] | None:
    if decision["decision"] in {"block_hard", "block_method", "require_capability"}:
        return {
            "decision": "block",
            "reason": f"Safe YOLO [{decision['policy_id']}]: {decision['reason']}",
        }
    return None


def append_audit_record(
    audit_log: Path,
    payload: dict[str, Any],
    decision: dict[str, Any],
) -> None:
    record = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "session_id": str(payload.get("session_id") or ""),
        "turn_id": str(payload.get("turn_id") or ""),
        "tool_name": str(payload.get("tool_name") or ""),
        "decision": decision["decision"],
        "policy_id": decision["policy_id"],
        "reason": decision["reason"],
    }
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(audit_log.parent, 0o700)
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    os.chmod(audit_log, 0o600)


def process_payload(
    payload: dict[str, Any],
    engine: SafeYoloEngine,
    *,
    audit_only: bool = False,
    audit_log: Path | None = None,
) -> dict[str, str] | None:
    decision = evaluate_payload(payload, engine)
    if audit_only:
        if audit_log is not None:
            try:
                append_audit_record(audit_log, payload, decision)
            except OSError:
                pass
        return None
    return hook_response(decision)


def main() -> int:
    parser = argparse.ArgumentParser(description="Staged Codex adapter for Safe YOLO.")
    parser.add_argument("--explain", action="store_true", help="Print the canonical decision even when allowed.")
    parser.add_argument("--audit-only", action="store_true", help="Log the decision without returning a hook response.")
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=Path("~/.safe-yolo/state/audit.jsonl").expanduser(),
    )
    parser.add_argument("--policy", type=Path, default=ROOT / "policy.json")
    parser.add_argument(
        "--capabilities",
        type=Path,
        default=Path(os.environ.get("SAFE_YOLO_CAPABILITIES", "~/.safe-yolo/state/capabilities")).expanduser(),
    )
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
        engine = SafeYoloEngine.from_file(args.policy, capability_store=CapabilityStore(args.capabilities))
        decision = evaluate_payload(payload, engine)
        if args.audit_only:
            try:
                append_audit_record(args.audit_log, payload, decision)
            except OSError:
                pass
            return 0
        response = decision if args.explain else hook_response(decision)
    except Exception:
        if args.audit_only:
            return 0
        raise
    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
