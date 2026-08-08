from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from adapters.codex_context import turn_scope  # noqa: E402
from engine.capabilities import CapabilityStore  # noqa: E402


TTL_SECONDS = 15 * 60
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
REPOSITORY_PR_RE = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#([1-9][0-9]*)$")
TAG_RE = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$")
POLICY_ID_RE = re.compile(r"^[a-z][a-z0-9_.-]+$")
MAINTENANCE_SCOPES = {
    "codex": {"config", "instructions", "hooks", "scripts", "rules", "tests"},
    "claude": {"config", "instructions", "hooks", "rules", "tests"},
    "pi": {"config", "instructions", "hooks", "tests"},
    "grok": {"config", "instructions", "hooks", "rules", "tests"},
}


def authorize_prompt(prompt: str, session_id: str, store: CapabilityStore) -> dict[str, Any] | None:
    if not session_id:
        raise ValueError("A session id is required for turn-scoped authorization.")
    store.revoke_session(session_id)

    stripped = prompt.strip()
    if not stripped.startswith("/"):
        return None
    try:
        parts = shlex.split(stripped)
    except ValueError as error:
        raise ValueError(f"Authorization command could not be parsed: {error}") from error
    if not parts:
        return None

    command, args = parts[0], parts[1:]
    if command == "/maintenance":
        if len(args) < 2:
            raise ValueError("Usage: /maintenance <harness> <scope> [scope ...]")
        harness, scopes = args[0], args[1:]
        allowed = MAINTENANCE_SCOPES.get(harness)
        if allowed is None:
            raise ValueError(f"Unknown maintenance harness: {harness}")
        unknown = sorted(set(scopes) - allowed)
        if unknown:
            raise ValueError(f"Unknown {harness} maintenance scopes: {', '.join(unknown)}")
        store.issue(
            kind="maintenance",
            session_id=session_id,
            constraints={"harness": harness, "scopes": scopes},
            ttl_seconds=TTL_SECONDS,
            user_authorized=True,
        )
        return {"kind": "maintenance", "harness": harness, "scopes": scopes}

    if command == "/maintenance-policy":
        if not args or any(not POLICY_ID_RE.fullmatch(item) for item in args):
            raise ValueError("Usage: /maintenance-policy <policy-id> [policy-id ...]")
        store.issue(
            kind="policy_maintenance",
            session_id=session_id,
            constraints={"policy_ids": args},
            ttl_seconds=TTL_SECONDS,
            user_authorized=True,
        )
        return {"kind": "policy_maintenance", "policy_ids": args}

    if command == "/merge-pr":
        if len(args) != 2 or args[1] not in {"--squash", "--merge", "--rebase"}:
            raise ValueError("Usage: /merge-pr <owner/repo>#<number> <--squash|--merge|--rebase>")
        match = REPOSITORY_PR_RE.fullmatch(args[0])
        if not match:
            raise ValueError("Merge target must be owner/repo#number.")
        repository, target = match.groups()
        method = args[1].removeprefix("--")
        store.issue(
            kind="action",
            action="github.pr_merge",
            session_id=session_id,
            constraints={"repository": repository, "target": target, "method": method},
            ttl_seconds=TTL_SECONDS,
            user_authorized=True,
        )
        return {"kind": "action", "action": "github.pr_merge", "repository": repository, "target": target, "method": method}

    if command == "/push-tag":
        if len(args) != 2 or not REPOSITORY_RE.fullmatch(args[0]) or not TAG_RE.fullmatch(args[1]):
            raise ValueError("Usage: /push-tag <owner/repo> <vX.Y.Z>")
        repository, target = args
        store.issue(
            kind="action",
            action="git.push_tag",
            session_id=session_id,
            constraints={"repository": repository, "target": target},
            ttl_seconds=TTL_SECONDS,
            user_authorized=True,
        )
        return {"kind": "action", "action": "git.push_tag", "repository": repository, "target": target}

    if command == "/deploy-production":
        if len(args) != 2:
            raise ValueError("Usage: /deploy-production <repository> <target>")
        repository, target = args
        store.issue(
            kind="action",
            action="deploy.production",
            session_id=session_id,
            constraints={"repository": repository, "target": target},
            ttl_seconds=TTL_SECONDS,
            user_authorized=True,
        )
        return {"kind": "action", "action": "deploy.production", "repository": repository, "target": target}

    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Staged Codex UserPromptSubmit adapter for Safe YOLO.")
    parser.add_argument(
        "--capabilities",
        type=Path,
        default=Path(os.environ.get("SAFE_YOLO_CAPABILITIES", "~/.safe-yolo/state/capabilities")).expanduser(),
    )
    args = parser.parse_args()
    payload = json.load(sys.stdin)
    prompt = str(payload.get("prompt") or "")
    session_id = turn_scope(payload)
    try:
        authorization = authorize_prompt(prompt, session_id, CapabilityStore(args.capabilities))
    except ValueError as error:
        json.dump({"decision": "block", "reason": f"Safe YOLO authorization error: {error}"}, sys.stdout)
        sys.stdout.write("\n")
        return 0
    if authorization is not None:
        json.dump(
            {
                "hookSpecificOutput": {
                    "additionalContext": f"Safe YOLO capability active for this turn: {authorization}"
                }
            },
            sys.stdout,
            sort_keys=True,
        )
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
