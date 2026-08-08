from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from adapters.codex_context import turn_scope
from engine.capabilities import CapabilityStore, PendingMaintenanceStore
from engine.safe_yolo import SafeYoloEngine, result


PATCH_PATH_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$")
PATCH_DELETE_RE = re.compile(r"^\*\*\* Delete File:")
WRITE_TOOLS = {"apply_patch", "write", "edit", "multiedit", "multi_edit", "create_file", "write_file", "move_file", "rename_file", "copy_file"}
DELETE_TOOLS = {"delete_file", "remove_file"}
READ_TOOLS = {"read", "read_file", "readfile", "grep", "search", "rg", "glob", "list", "list_dir", "listdir", "web_search", "websearch", "webrun", "view_image", "update_plan", "request_user_input"}
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


def candidate_write_paths(tool_input: Any) -> set[str]:
    paths: set[str] = set()
    path_keys = {"path", "file_path", "filepath", "filename", "target_file", "target_path", "source", "source_path", "destination", "destination_path", "from", "to"}
    for key, value in _strings(tool_input):
        if key in path_keys:
            paths.add(value)
    if isinstance(tool_input, dict):
        for key, value in _strings(tool_input):
            if key in {"patch", "input", "command"}:
                for line in value.splitlines():
                    match = PATCH_PATH_RE.match(line.strip())
                    if match:
                        paths.add(match.group(1).strip())
    return paths


def contains_patch_delete(tool_input: Any) -> bool:
    return any(
        PATCH_DELETE_RE.match(line.strip())
        for key, value in _strings(tool_input)
        if key in {"patch", "input", "command"}
        for line in value.splitlines()
    )


def request_context(payload: dict[str, Any]) -> dict[str, Any]:
    supplied = payload.get("safe_yolo_context") or {}
    context = dict(supplied) if isinstance(supplied, dict) else {}
    scope = turn_scope(payload)
    if scope:
        context.setdefault("session_id", scope)
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        context.setdefault("cwd", cwd)
    return context


def evaluate_payload(payload: dict[str, Any], engine: SafeYoloEngine) -> dict[str, Any]:
    tool_name = str(payload.get("tool_name") or "").lower()
    tool_input = payload.get("tool_input") or {}
    context = request_context(payload)
    if tool_name in SHELL_TOOLS:
        command = tool_input.get("command") or tool_input.get("cmd") if isinstance(tool_input, dict) else ""
        if not isinstance(command, str) or not command.strip():
            return result("allow", "codex.empty_shell", "No shell command supplied.")
        return engine.inspect_command(command, context)
    if tool_name in DELETE_TOOLS:
        return engine.evaluate({"action": "filesystem.delete", **context})
    if tool_name in WRITE_TOOLS:
        if contains_patch_delete(tool_input):
            return engine.evaluate({"action": "filesystem.delete", **context})
        for path in sorted(candidate_write_paths(tool_input)):
            decision = engine.inspect_path_write(path, context)
            if decision["decision"] != "allow":
                return decision
        return result("allow", "codex.workspace_write", "Structured workspace write is permitted.")
    if tool_name in READ_TOOLS:
        return result("allow", "codex.read", "Read-only tool is permitted.")
    return result("block_hard", "tool.unclassified", "Unclassified tool with side-effect potential is blocked.")


def hook_response(decision: dict[str, Any], pending: dict[str, Any] | None = None) -> dict[str, str] | None:
    if decision["decision"] not in {"block_hard", "block_method", "require_capability"}:
        return None
    reason = f"Safe YOLO [{decision['policy_id']}]: {decision['reason']}"
    if pending is not None:
        reason += " A scoped maintenance request is pending; reply only 'approve' or 'yes' to authorize this exact maintenance scope."
    return {"decision": "block", "reason": reason}


def append_audit_record(audit_log: Path, payload: dict[str, Any], decision: dict[str, Any]) -> None:
    record = {"recorded_at": datetime.now(timezone.utc).isoformat(), "session_id": str(payload.get("session_id") or ""), "turn_id": str(payload.get("turn_id") or ""), "tool_name": str(payload.get("tool_name") or ""), "decision": decision["decision"], "policy_id": decision["policy_id"]}
    audit_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(audit_log.parent, 0o700)
    with audit_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
    os.chmod(audit_log, 0o600)


def audit_payload(payload: dict[str, Any], engine: SafeYoloEngine, audit_log: Path) -> dict[str, Any]:
    """Record the canonical decision without influencing the current hook authority."""
    decision = evaluate_payload(payload, engine)
    append_audit_record(audit_log, payload, decision)
    return decision


def process_payload(
    payload: dict[str, Any],
    engine: SafeYoloEngine,
    *,
    pending_store: PendingMaintenanceStore | None = None,
    audit_log: Path | None = None,
) -> dict[str, str] | None:
    decision = evaluate_payload(payload, engine)
    pending = None
    request = decision.get("maintenance_request")
    session_id = str(payload.get("session_id") or "")
    if isinstance(request, dict) and pending_store is not None and session_id:
        pending = pending_store.request(session_id=session_id, harness=str(request["harness"]), scopes=list(request["scopes"]))
    audit_warning = None
    if audit_log is not None:
        try:
            append_audit_record(audit_log, payload, decision)
        except OSError as error:
            audit_warning = f"Audit unavailable ({type(error).__name__}); enforcement decision still applied."
    response = hook_response(decision, pending)
    if audit_warning:
        if response is None:
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": audit_warning}}
        response["hookSpecificOutput"] = {"hookEventName": "PreToolUse", "additionalContext": audit_warning}
    return response


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Authoritative Safe YOLO Codex PreToolUse adapter.")
    parser.add_argument("--policy", type=Path, default=root / "policy" / "policy.json")
    parser.add_argument("--host-contract", type=Path, default=Path(os.environ["SAFE_YOLO_HOST_CONTRACT"]).expanduser() if os.environ.get("SAFE_YOLO_HOST_CONTRACT") else None)
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser())
    parser.add_argument("--explain", action="store_true")
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    payload = json.load(sys.stdin)
    store = CapabilityStore(args.state_dir / "capabilities")
    pending = PendingMaintenanceStore(args.state_dir / "pending-maintenance")
    host_contract = json.loads(args.host_contract.read_text(encoding="utf-8")) if args.host_contract else None
    engine = SafeYoloEngine.from_file(args.policy, capability_store=store, host_contract=host_contract)
    if args.explain:
        response = evaluate_payload(payload, engine)
    elif args.audit_only:
        audit_payload(payload, engine, args.state_dir / "audit.jsonl")
        response = None
    else:
        response = process_payload(payload, engine, pending_store=pending, audit_log=args.state_dir / "audit.jsonl")
    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
