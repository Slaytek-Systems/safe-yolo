from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from adapters.codex_prompt import APPROVAL_WORDS, authorize_prompt
from engine.capabilities import CapabilityStore, PendingMaintenanceStore


def _load_stdin() -> dict[str, Any]:
    raw = sys.stdin.buffer.read()
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    text = raw.decode("utf-8").lstrip("\ufeff")
    payload = json.loads(text) if text.strip() else {}
    if not isinstance(payload, dict):
        raise ValueError("Cursor prompt payload must be a JSON object.")
    return payload


def normalize_prompt_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    conversation_id = str(payload.get("conversation_id") or payload.get("session_id") or "")
    generation_id = str(payload.get("generation_id") or payload.get("turn_id") or "")
    if conversation_id:
        normalized["session_id"] = conversation_id
    if generation_id:
        normalized["turn_id"] = generation_id
    return normalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO Cursor maintenance approval adapter.")
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser(),
    )
    args = parser.parse_args()
    try:
        payload = normalize_prompt_payload(_load_stdin())
    except (json.JSONDecodeError, ValueError) as error:
        json.dump(
            {
                "continue": False,
                "user_message": f"Safe YOLO authorization error: {error}",
            },
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0

    authorization = authorize_prompt(
        payload,
        CapabilityStore(args.state_dir / "capabilities"),
        PendingMaintenanceStore(args.state_dir / "pending-maintenance"),
    )
    if authorization is not None:
        json.dump(
            {
                "continue": True,
                "user_message": f"Safe YOLO maintenance capability active: {authorization}",
            },
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
        return 0

    prompt = str(payload.get("prompt") or "").strip().lower()
    # Non-approval prompts always continue; cancel already happened inside authorize_prompt.
    if prompt in APPROVAL_WORDS:
        # Exact approval with no pending request: continue quietly.
        json.dump({"continue": True}, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0

    json.dump({"continue": True}, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
