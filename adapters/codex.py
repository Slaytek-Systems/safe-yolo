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
from engine.recovery import FileCheckpointStore, RecoveryUnavailable
from engine.safe_yolo import SafeYoloEngine, result


PATCH_PATH_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+)$")
PATCH_DELETE_RE = re.compile(r"^\*\*\* Delete File:")
WRITE_TOOLS = {"apply_patch", "write", "edit", "multiedit", "multi_edit", "create_file", "write_file", "move_file", "rename_file", "copy_file"}
DELETE_TOOLS = {"delete_file", "remove_file"}
READ_TOOLS = {"read", "read_file", "readfile", "grep", "search", "rg", "glob", "list", "list_dir", "listdir", "web_search", "websearch", "webrun", "view_image", "update_plan", "request_user_input"}
SHELL_TOOLS = {"bash", "shell", "exec_command"}
THREAD_INSPECTION_TOOLS = {"codex_applist_threads", "codex_appread_thread", "codex_applist_projects", "codex_appwait_threads"}
THREAD_CREATION_TOOLS = {"codex_appcreate_thread"}
THREAD_LIFECYCLE_TOOLS = {"codex_appset_thread_archived"}
THREAD_MESSAGE_TOOLS = {"codex_appsend_message_to_thread"}
AUTOMATION_TOOLS = {"codex_appautomation_update"}
AUTOMATION_MANAGEMENT_MODES = {"create", "update", "pause", "resume"}
COLLABORATION_TOOLS = {"collaborationspawn_agent", "collaborationwait_agent", "collaborationlist_agents"}
NODE_REPL_JS_TOOLS = {"mcp__node_repl__js"}
NODE_REPL_RESET_TOOLS = {"mcp__node_repl__js_reset"}
COMPUTER_USE_OBSERVATION_METHODS = {"get_app_state", "list_apps", "scroll"}
COMPUTER_USE_ACTION_METHODS = {
    "click",
    "drag",
    "perform_secondary_action",
    "press_key",
    "select_text",
    "set_value",
    "type_text",
}
JS_CALL_RE = re.compile(r"(?<![\w$])([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")
JS_IMPORT_RE = re.compile(r"\bimport\s*\(\s*(['\"])([^'\"]+)\1\s*\)")
ALLOWED_COMPUTER_USE_IMPORTS = {"@oai/sky", "node:fs/promises", "node:url"}
ALLOWED_COMPUTER_USE_HELPER_CALLS = {
    "import",
    "JSON.stringify",
    "nodeRepl.write",
    "nodeRepl.emitImage",
    "fs.readFile",
    "fileURLToPath",
}
JS_CONTROL_KEYWORDS = {"if"}


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


def _mask_js_literals(code: str) -> str:
    """Mask strings and comments so call discovery cannot be confused by their text."""
    output = list(code)
    index = 0
    while index < len(code):
        if code.startswith("//", index):
            end = code.find("\n", index + 2)
            end = len(code) if end < 0 else end
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        if code.startswith("/*", index):
            end = code.find("*/", index + 2)
            end = len(code) if end < 0 else end + 2
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        if code[index] in {"'", '"', "`"}:
            quote = code[index]
            output[index] = " "
            index += 1
            while index < len(code):
                output[index] = " "
                if code[index] == "\\":
                    index += 2
                    continue
                if code[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        index += 1
    return "".join(output)


def classify_node_repl(tool_input: Any) -> dict[str, Any]:
    code = tool_input.get("code") if isinstance(tool_input, dict) else None
    if not isinstance(code, str) or not code.strip() or "`" in code:
        return result(
            "block_method",
            "codex.node_repl_code_unclassified",
            "Node REPL code requires a narrow recognized Computer Use mapping.",
        )

    masked = _mask_js_literals(code)
    if re.search(r"\b(?:sky|nodeRepl|fs)\s*\[", masked):
        return result(
            "block_method",
            "codex.node_repl_code_unclassified",
            "Computed runtime method access is not classified.",
        )

    imports = [match.group(2) for match in JS_IMPORT_RE.finditer(code)]
    import_call_count = len(re.findall(r"\bimport\s*\(", masked))
    if import_call_count != len(imports) or any(
        module not in ALLOWED_COMPUTER_USE_IMPORTS for module in imports
    ):
        return result(
            "block_method",
            "codex.node_repl_code_unclassified",
            "Only the documented Computer Use imports are classified.",
        )

    calls = set(JS_CALL_RE.findall(masked))
    sky_calls = {call for call in calls if call.startswith("sky.")}
    sky_methods = {call.split(".", 1)[1] for call in sky_calls}
    known_sky_methods = COMPUTER_USE_OBSERVATION_METHODS | COMPUTER_USE_ACTION_METHODS
    allowed_calls = {
        *(f"sky.{method}" for method in known_sky_methods),
        *ALLOWED_COMPUTER_USE_HELPER_CALLS,
        *JS_CONTROL_KEYWORDS,
    }
    if calls - allowed_calls:
        return result(
            "block_method",
            "codex.node_repl_code_unclassified",
            "Node REPL call is outside the documented Computer Use surface.",
        )

    if not sky_methods:
        if imports == ["@oai/sky"] and calls <= {"import"}:
            return result(
                "allow",
                "codex.computer_use_bootstrap",
                "The documented Computer Use runtime bootstrap is permitted.",
            )
        return result(
            "block_method",
            "codex.node_repl_code_unclassified",
            "Generic Node REPL execution is not a Computer Use action.",
        )

    if "fs.readFile" in calls and not (
        "fileURLToPath" in calls
        and re.search(r"fs\.readFile\s*\(\s*fileURLToPath\s*\([^)]*\.screenshot\.url", code)
    ):
        return result(
            "block_method",
            "codex.node_repl_code_unclassified",
            "File reads are classified only for emitting a Computer Use screenshot.",
        )

    if sky_methods & COMPUTER_USE_ACTION_METHODS:
        return result(
            "allow_report",
            "codex.computer_use_action",
            "Recognized Computer Use actions are permitted and reported; action-time confirmation policy still applies.",
        )
    return result(
        "allow",
        "codex.computer_use_observation",
        "Read-only Computer Use observation and navigation are permitted.",
    )


def request_context(payload: dict[str, Any], shell_input: dict[str, Any] | None = None) -> dict[str, Any]:
    supplied = payload.get("safe_yolo_context") or {}
    context = dict(supplied) if isinstance(supplied, dict) else {}
    scope = turn_scope(payload)
    if scope:
        context.setdefault("session_id", scope)
    cwd = payload.get("cwd")
    if isinstance(cwd, str) and cwd:
        context.setdefault("cwd", cwd)
    workdir = shell_input.get("workdir") if isinstance(shell_input, dict) else None
    if isinstance(workdir, str) and workdir:
        effective = Path(workdir).expanduser()
        if not effective.is_absolute() and isinstance(cwd, str) and cwd:
            effective = Path(cwd).expanduser() / effective
        context["cwd"] = str(effective.resolve(strict=False))
    return context


def evaluate_payload(payload: dict[str, Any], engine: SafeYoloEngine) -> dict[str, Any]:
    tool_name = str(payload.get("tool_name") or "").lower()
    tool_input = payload.get("tool_input") or {}
    context = request_context(payload, tool_input if tool_name in SHELL_TOOLS else None)
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
    if tool_name in THREAD_INSPECTION_TOOLS:
        return result("allow", "codex.thread_inspection", "Existing thread inspection is permitted.")
    if tool_name in THREAD_CREATION_TOOLS:
        return result("allow_report", "codex.thread_creation", "Creating a user-owned task/thread is permitted and reported.")
    if tool_name in THREAD_LIFECYCLE_TOOLS:
        return result("allow_report", "codex.thread_lifecycle", "Reversible thread archival is permitted and reported.")
    if tool_name in THREAD_MESSAGE_TOOLS:
        return result("allow", "codex.thread_message", "Messaging an existing thread is permitted.")
    if tool_name in AUTOMATION_TOOLS:
        mode = str(tool_input.get("mode") or "").lower() if isinstance(tool_input, dict) else ""
        if mode == "view":
            return result("allow", "codex.automation_inspection", "Existing automation inspection is permitted.")
        if mode in AUTOMATION_MANAGEMENT_MODES:
            return result("allow_report", "codex.automation_management", "Reversible automation management is permitted and reported.")
        if mode == "delete":
            return engine.evaluate({"action": "records.delete", **context})
        return result("block_method", "codex.automation_operation_unclassified", "Unclassified automation operation requires an adapter update before use.")
    if tool_name in NODE_REPL_JS_TOOLS:
        return classify_node_repl(tool_input)
    if tool_name in NODE_REPL_RESET_TOOLS:
        return result("allow_report", "codex.node_repl_reset", "Resetting ephemeral Node REPL state is permitted and reported.")
    if tool_name in COLLABORATION_TOOLS:
        return result("allow", "codex.collaboration", "Collaboration management is permitted.")
    return result("block_method", "tool.unclassified", "Unclassified tool requires a consequence mapping before use.")


def hook_response(decision: dict[str, Any], pending: dict[str, Any] | None = None) -> dict[str, str] | None:
    if decision["decision"] not in {"block_hard", "block_method", "require_capability"}:
        return None
    reason = f"Safe YOLO [{decision['policy_id']}]: {decision['reason']}"
    if pending is not None:
        reason += " A scoped maintenance request is pending; reply only 'approve' or 'yes' to authorize this exact maintenance scope."
    return {"decision": "block", "reason": reason}


def append_audit_record(audit_log: Path, payload: dict[str, Any], decision: dict[str, Any]) -> None:
    record = {"recorded_at": datetime.now(timezone.utc).isoformat(), "session_id": str(payload.get("session_id") or ""), "turn_id": str(payload.get("turn_id") or ""), "tool_name": str(payload.get("tool_name") or ""), "decision": decision["decision"], "policy_id": decision["policy_id"]}
    if decision.get("recovery_id"):
        record["recovery_id"] = str(decision["recovery_id"])
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
    recovery_store: FileCheckpointStore | None = None,
) -> dict[str, str] | None:
    decision = evaluate_payload(payload, engine)
    if recovery_store is not None and decision["decision"] in {"allow", "allow_report"} and decision.get("effect") != "read":
        tool_name = str(payload.get("tool_name") or "").lower()
        if tool_name in WRITE_TOOLS or tool_name in SHELL_TOOLS:
            context = request_context(payload)
            cwd = context.get("cwd")
            try:
                if not isinstance(cwd, str) or not cwd:
                    raise RecoveryUnavailable("Mutating tools require a known working directory.")
                if tool_name in SHELL_TOOLS:
                    checkpoint = recovery_store.checkpoint_workspace(
                        cwd=cwd,
                        session_id=str(payload.get("session_id") or ""),
                        turn_id=str(payload.get("turn_id") or ""),
                    )
                else:
                    checkpoint = recovery_store.checkpoint(
                        candidate_write_paths(payload.get("tool_input") or {}),
                        cwd=cwd,
                        session_id=str(payload.get("session_id") or ""),
                        turn_id=str(payload.get("turn_id") or ""),
                    )
                decision = {**decision, "recovery_id": checkpoint["id"]}
            except (OSError, ValueError, RecoveryUnavailable) as error:
                decision = result(
                    "block_method",
                    "recovery.unavailable",
                    f"Tool was not run because its recovery checkpoint failed ({type(error).__name__}).",
                )
    pending = None
    request = decision.get("maintenance_request")
    session_id = str(payload.get("session_id") or "")
    if isinstance(request, dict) and pending_store is not None and session_id:
        pending = pending_store.request(
            session_id=session_id,
            kind=str(request.get("kind") or "maintenance"),
            harness=str(request["harness"]),
            scopes=list(request["scopes"]),
        )
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
    recovery = FileCheckpointStore(args.state_dir / "recovery")
    host_contract = json.loads(args.host_contract.read_text(encoding="utf-8")) if args.host_contract else None
    engine = SafeYoloEngine.from_file(args.policy, capability_store=store, host_contract=host_contract)
    if args.explain:
        response = evaluate_payload(payload, engine)
    elif args.audit_only:
        audit_payload(payload, engine, args.state_dir / "audit.jsonl")
        response = None
    else:
        response = process_payload(payload, engine, pending_store=pending, audit_log=args.state_dir / "audit.jsonl", recovery_store=recovery)
    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
