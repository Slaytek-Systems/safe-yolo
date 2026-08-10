from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from adapters.codex_context import turn_scope
from engine.capabilities import CapabilityStore, PendingMaintenanceStore


APPROVAL_WORDS = {"approve", "yes"}
TTL_SECONDS = 15 * 60


def authorize_prompt(
    payload: dict[str, Any],
    store: CapabilityStore,
    pending_store: PendingMaintenanceStore,
) -> dict[str, Any] | None:
    """Consume one pending maintenance request only after an exact approval reply."""
    session_id = str(payload.get("session_id") or "")
    prompt = str(payload.get("prompt") or "").strip().lower()
    if not session_id:
        return None
    if prompt not in APPROVAL_WORDS:
        pending_store.cancel(session_id)
        return None
    pending = pending_store.consume(session_id)
    if pending is None:
        return None
    scoped_session = turn_scope(payload)
    kind = str(pending.get("kind") or "maintenance")
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
    )
    if authorization is not None:
        json.dump({"hookSpecificOutput": {"additionalContext": f"Safe YOLO maintenance capability active: {authorization}"}}, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
