from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.approvals_v2 import ApprovalLedger
from engine.consequences_v2 import ConsequenceKernel


APPROVAL_MARKER = "SAFE_YOLO_REQUEST_USER_INPUT="


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
    codex_home: str | Path,
    user_home: str | Path,
) -> ConsequenceKernel:
    safe_yolo = Path(safe_yolo_home).expanduser()
    codex = Path(codex_home).expanduser()
    home = Path(user_home).expanduser()
    return ConsequenceKernel(
        enforcement_paths=(
            str(safe_yolo),
            str(codex / "config.toml"),
            str(codex / "hooks.json"),
            str(codex / "hooks"),
        ),
        credential_paths=(
            str(codex / "auth.json"),
            str(home / ".ssh"),
            str(home / ".gnupg"),
        ),
    )


def approval_request_from_denial(response: dict[str, Any]) -> dict[str, Any]:
    reason = response["hookSpecificOutput"]["permissionDecisionReason"]
    marker, encoded = reason.rsplit(APPROVAL_MARKER, 1)
    if not marker:
        raise ValueError("Approval denial is missing its explanation.")
    value = json.loads(encoded)
    if not isinstance(value, dict):
        raise ValueError("Approval request must be a JSON object.")
    return value


def handle_pre_tool(
    payload: dict[str, Any],
    kernel: ConsequenceKernel,
    ledger: ApprovalLedger,
) -> dict[str, Any] | None:
    decision = kernel.evaluate(payload)
    if decision.outcome == "allow":
        return None
    if decision.outcome == "operator_only":
        return _deny(
            f"Safe YOLO operator-only boundary [{decision.consequence}]: {decision.display}."
        )
    try:
        if ledger.consume_approval(payload):
            return None
        tool_input = ledger.create_request(
            payload,
            consequence=str(decision.consequence),
            display=str(decision.display),
        )
    except (OSError, ValueError) as error:
        return _deny(
            f"Safe YOLO approval unavailable [{decision.consequence}]: "
            f"{type(error).__name__}; action remains blocked."
        )
    encoded = json.dumps(tool_input, sort_keys=True, separators=(",", ":"))
    return _deny(
        f"Safe YOLO approval required [{decision.consequence}]: {decision.display}. "
        "Call request_user_input exactly once with the following JSON, then retry the identical action.\n"
        f"{APPROVAL_MARKER}{encoded}"
    )


def handle_post_tool(payload: dict[str, Any], ledger: ApprovalLedger) -> bool:
    return ledger.approve_from_tool(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO v2 Codex consequence hook.")
    parser.add_argument("--state-dir", type=Path, default=Path("~/.safe-yolo/state").expanduser())
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--codex-home", type=Path, default=Path("~/.codex").expanduser())
    parser.add_argument("--user-home", type=Path, default=Path.home())
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, dict):
        json.dump(
            _deny("Safe YOLO received an unreadable hook payload."),
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0
    kernel = build_kernel(
        safe_yolo_home=args.safe_yolo_home,
        codex_home=args.codex_home,
        user_home=args.user_home,
    )
    ledger = ApprovalLedger(args.state_dir)
    event = str(payload.get("hook_event_name") or "")
    if event == "PostToolUse":
        if handle_post_tool(payload, ledger):
            json.dump(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": "Safe YOLO recorded one exact retry approval.",
                    }
                },
                sys.stdout,
                sort_keys=True,
            )
            sys.stdout.write("\n")
        return 0
    response = handle_pre_tool(payload, kernel, ledger)
    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
