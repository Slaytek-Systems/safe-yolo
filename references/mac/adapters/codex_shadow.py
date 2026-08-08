from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
CODEX_HOOKS = Path.home() / ".codex" / "hooks"
DEFAULT_STATE_DIR = Path.home() / ".safe-yolo" / "state" / "codex-shadow-v1"
DEFAULT_PATH_GUARD = CODEX_HOOKS / "pre_tool_use_path_guard.py"
DEFAULT_BASH_GUARD = CODEX_HOOKS / "pre_tool_use_bash_guard.py"
DEFAULT_LIMIT = 20
AUDIT_NAME = "observations.jsonl"
REPORT_NAME = "report.txt"
LOCK_NAME = ".lock"
COMPLETED_NAME = ".completed"
WRITE_TOOLS = {"apply_patch", "write", "edit", "multiedit", "multi_edit", "create_file", "write_file"}
REPORT_END = "NO CUTOVER: legacy Codex guards remain authoritative.\n"
Evaluator = Callable[[dict[str, Any], Path], dict[str, Any]]


@dataclass(frozen=True)
class WrapperResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def normalize_decision(decision: str) -> str:
    if decision in {"allow", "allow_report"}:
        return "allow"
    if decision in {"require_capability", "block_method", "block_hard"}:
        return "block"
    raise ValueError(f"Unknown Safe YOLO decision: {decision}")


def _legacy_decision(stdout: bytes) -> str | None:
    if not stdout.strip():
        return "allow"
    try:
        response = json.loads(stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        isinstance(response, dict)
        and response.get("decision") == "block"
        and isinstance(response.get("reason"), str)
        and response["reason"]
    ):
        return "block"
    return None


def _run_guard(path: Path, payload_bytes: bytes) -> WrapperResult:
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{CODEX_HOOKS}{os.pathsep}{existing_pythonpath}" if existing_pythonpath else str(CODEX_HOOKS)
    )
    process = subprocess.run(
        [sys.executable, str(path)],
        input=payload_bytes,
        capture_output=True,
        check=False,
        env=environment,
    )
    return WrapperResult(process.returncode, process.stdout, process.stderr)


def _is_observation(payload: dict[str, Any]) -> bool:
    tool_name = str(payload.get("tool_name") or "")
    if tool_name.lower() in WRITE_TOOLS:
        return True
    if tool_name != "Bash":
        return False
    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if not isinstance(command, str) or not command.strip():
        return False
    if str(CODEX_HOOKS) not in sys.path:
        sys.path.insert(0, str(CODEX_HOOKS))
    from hook_state import classify_command

    return not bool(classify_command(command)["informational"])


def _evaluate_shadow(payload: dict[str, Any], policy: Path) -> dict[str, Any]:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from adapters.codex import evaluate_payload
    from engine.safe_yolo import SafeYoloEngine

    return evaluate_payload(payload, SafeYoloEngine.from_file(policy))


def _private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)


def _atomic_write(path: Path, content: str) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _load_records_recover(audit_path: Path) -> list[dict[str, Any]]:
    if not audit_path.exists():
        return []
    data = audit_path.read_bytes()
    records: list[dict[str, Any]] = []
    valid_bytes = 0
    chunks = data.splitlines(keepends=True)
    for index, chunk in enumerate(chunks):
        try:
            record = json.loads(chunk)
            if not isinstance(record, dict):
                raise ValueError("audit record must be an object")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            is_truncated_tail = index == len(chunks) - 1 and not chunk.endswith((b"\n", b"\r"))
            if not is_truncated_tail:
                raise
            with audit_path.open("r+b") as audit:
                audit.truncate(valid_bytes)
                audit.flush()
                os.fsync(audit.fileno())
            return records
        records.append(record)
        valid_bytes += len(chunk)
    return records


def _report_text(records: list[dict[str, Any]]) -> str:
    matrix = {("allow", "allow"): 0, ("allow", "block"): 0, ("block", "allow"): 0, ("block", "block"): 0}
    disagreements: dict[str, int] = {}
    for record in records:
        key = (record["legacy_decision"], record["safe_yolo_decision"])
        matrix[key] += 1
        if not record["agreement"]:
            policy_id = record["safe_yolo_policy_id"]
            disagreements[policy_id] = disagreements.get(policy_id, 0) + 1
    agreement_count = sum(1 for record in records if record["agreement"])
    policies = ",".join(f"{key}:{value}" for key, value in sorted(disagreements.items())) or "none"
    return (
        f"Codex Safe YOLO shadow: total={len(records)} agreement={agreement_count} "
        f"disagreement={len(records) - agreement_count}\n"
        "matrix "
        f"legacy_allow/safe_allow={matrix[('allow', 'allow')]} "
        f"legacy_allow/safe_block={matrix[('allow', 'block')]} "
        f"legacy_block/safe_allow={matrix[('block', 'allow')]} "
        f"legacy_block/safe_block={matrix[('block', 'block')]}\n"
        f"policy_disagreement={policies}\n"
        f"{REPORT_END}"
    )


def _report_is_complete(path: Path, limit: int) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return text.startswith(f"Codex Safe YOLO shadow: total={limit} ") and text.endswith(REPORT_END)


def _marker_is_complete(path: Path, limit: int) -> bool:
    try:
        return path.read_text(encoding="utf-8") == f"limit={limit}\n"
    except OSError:
        return False


def _fast_complete(state_dir: Path, limit: int) -> bool:
    return _marker_is_complete(state_dir / COMPLETED_NAME, limit) and _report_is_complete(
        state_dir / REPORT_NAME, limit
    )


def _complete_locked(state_dir: Path, records: list[dict[str, Any]], limit: int) -> None:
    report_path = state_dir / REPORT_NAME
    if not _report_is_complete(report_path, limit):
        _atomic_write(report_path, _report_text(records[:limit]))
    marker_path = state_dir / COMPLETED_NAME
    if not _marker_is_complete(marker_path, limit):
        _atomic_write(marker_path, f"limit={limit}\n")


def _record(
    ordinal: int,
    payload: dict[str, Any],
    legacy_decision: str,
    safe_yolo_decision: str,
    policy_id: str,
) -> dict[str, Any]:
    return {
        "ordinal": ordinal,
        "timestamp": datetime.now(UTC).isoformat(),
        "tool_name": str(payload.get("tool_name") or ""),
        "legacy_decision": legacy_decision,
        "safe_yolo_decision": safe_yolo_decision,
        "safe_yolo_policy_id": policy_id,
        "agreement": legacy_decision == safe_yolo_decision,
    }


def _append_locked(state_dir: Path, record: dict[str, Any]) -> None:
    audit_path = state_dir / AUDIT_NAME
    descriptor = os.open(audit_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    os.chmod(audit_path, 0o600)
    with os.fdopen(descriptor, "a", encoding="utf-8") as audit:
        audit.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        audit.flush()
        os.fsync(audit.fileno())


def _locked_state(state_dir: Path):
    _private_directory(state_dir)
    lock_path = state_dir / LOCK_NAME
    descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    os.chmod(lock_path, 0o600)
    lock = os.fdopen(descriptor, "r+", encoding="utf-8")
    fcntl.flock(lock, fcntl.LOCK_EX)
    return lock


def append_observation(
    state_dir: Path,
    *,
    limit: int,
    payload: dict[str, Any],
    legacy_decision: str,
    safe_yolo_decision: str,
    policy_id: str,
) -> bool:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    with _locked_state(state_dir):
        records = _load_records_recover(state_dir / AUDIT_NAME)
        if len(records) >= limit:
            _complete_locked(state_dir, records, limit)
            return False
        record = _record(
            len(records) + 1,
            payload,
            legacy_decision,
            safe_yolo_decision,
            policy_id,
        )
        _append_locked(state_dir, record)
        records.append(record)
        if len(records) == limit:
            _complete_locked(state_dir, records, limit)
        return True


def _evaluate_and_append(
    state_dir: Path,
    *,
    limit: int,
    payload: dict[str, Any],
    legacy_decision: str,
    policy: Path,
    evaluator: Evaluator,
) -> None:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    with _locked_state(state_dir):
        records = _load_records_recover(state_dir / AUDIT_NAME)
        if len(records) >= limit:
            _complete_locked(state_dir, records, limit)
            return
        safe_result = evaluator(payload, policy)
        safe_decision = normalize_decision(str(safe_result["decision"]))
        record = _record(
            len(records) + 1,
            payload,
            legacy_decision,
            safe_decision,
            str(safe_result["policy_id"]),
        )
        _append_locked(state_dir, record)
        records.append(record)
        if len(records) == limit:
            _complete_locked(state_dir, records, limit)


def run_wrapper(
    payload: dict[str, Any],
    *,
    state_dir: Path = DEFAULT_STATE_DIR,
    limit: int = DEFAULT_LIMIT,
    path_guard: Path = DEFAULT_PATH_GUARD,
    bash_guard: Path = DEFAULT_BASH_GUARD,
    policy: Path = ROOT / "policy.json",
    evaluator: Evaluator = _evaluate_shadow,
) -> WrapperResult:
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode()
    results = [_run_guard(path_guard, payload_bytes)]
    if str(payload.get("tool_name") or "") == "Bash":
        results.append(_run_guard(bash_guard, payload_bytes))

    stdout = b"".join(result.stdout for result in results)
    stderr = b"".join(result.stderr for result in results)
    returncode = next((result.returncode for result in results if result.returncode != 0), 0)
    decisions = [_legacy_decision(result.stdout) for result in results]
    if returncode != 0 or any(decision is None for decision in decisions):
        return WrapperResult(returncode, stdout, stderr)

    legacy_decision = "block" if "block" in decisions else "allow"
    try:
        if _is_observation(payload) and not _fast_complete(state_dir, limit):
            _evaluate_and_append(
                state_dir,
                limit=limit,
                payload=payload,
                legacy_decision=legacy_decision,
                policy=policy,
                evaluator=evaluator,
            )
    except Exception:
        pass
    return WrapperResult(returncode, stdout, stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Legacy-authoritative Codex Safe YOLO shadow wrapper.")
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--path-guard", type=Path, default=DEFAULT_PATH_GUARD)
    parser.add_argument("--bash-guard", type=Path, default=DEFAULT_BASH_GUARD)
    parser.add_argument("--policy", type=Path, default=ROOT / "policy.json")
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    result = run_wrapper(
        payload,
        state_dir=args.state_dir,
        limit=args.limit,
        path_guard=args.path_guard,
        bash_guard=args.bash_guard,
        policy=args.policy,
    )
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
