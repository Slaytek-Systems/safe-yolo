from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from adapters.codex_context import turn_scope
from engine.capabilities import CapabilityStore, PendingActionStore, PendingMaintenanceStore


APPROVAL_WORDS = {"approve", "yes"}
TTL_SECONDS = 15 * 60


def authorize_prompt(
    payload: dict[str, Any],
    store: CapabilityStore,
    pending_store: PendingMaintenanceStore,
    pending_action_store: PendingActionStore | None = None,
) -> dict[str, Any] | None:
    """Consume one pending capability request only after an exact approval reply."""
    session_id = str(payload.get("session_id") or "")
    prompt = str(payload.get("prompt") or "").strip().lower()
    if not session_id:
        return None
    if prompt not in APPROVAL_WORDS:
        pending_store.cancel(session_id)
        if pending_action_store is not None:
            pending_action_store.cancel(session_id)
        return None
    pending = pending_store.consume(session_id)
    scoped_session = turn_scope(payload)
    if pending is None and pending_action_store is not None:
        pending = pending_action_store.consume(session_id)
    if pending is None:
        return None
    kind = str(pending.get("kind") or "maintenance")
    if kind == "action":
        action = str(pending["action"])
        constraints = dict(pending["constraints"])
        store.issue(
            kind="action",
            action=action,
            session_id=scoped_session,
            constraints=constraints,
            ttl_seconds=TTL_SECONDS,
            user_authorized=True,
        )
        return {"kind": "action", "action": action, "constraints": constraints}
    store.issue(
        kind=kind,
        session_id=scoped_session,
        constraints={"harness": pending["harness"], "scopes": pending["scopes"]},
        ttl_seconds=TTL_SECONDS,
        user_authorized=True,
    )
    return {"kind": kind, "harness": pending["harness"], "scopes": pending["scopes"]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO exact maintenance approval adapter.")
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser())
    args = parser.parse_args()
    payload = json.load(sys.stdin)
    authorization = authorize_prompt(
        payload,
        CapabilityStore(args.state_dir / "capabilities"),
        PendingMaintenanceStore(args.state_dir / "pending-maintenance"),
        PendingActionStore(args.state_dir / "pending-actions"),
    )
    if authorization is not None:
        json.dump({"hookSpecificOutput": {"additionalContext": f"Safe YOLO capability active: {authorization}"}}, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
