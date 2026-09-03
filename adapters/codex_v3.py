from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.consequences_v3 import DenyOnlyKernel


SAFE_METHODS = {
    "filesystem.delete": "move the target to managed quarantine or leave it for managed cleanup",
    "git.history_mutation": "use an additive commit or the repository's guarded history workflow",
    "production.mutate": "use the repository's protected merge and deployment workflow without bypass flags",
    "remote.execute": "use the owning workspace or reviewed remote-operation interface",
    "privilege.modify": "use the documented administrator-owned maintenance path",
    "network.public_exposure": "bind to loopback and use the approved preview or forwarding path",
    "credentials.access": "use the approved credential broker or value-blind readiness check",
    "enforcement.modify": "publish an immutable reviewed Safe YOLO release through operator maintenance",
    "interactive.process_write": "use a fresh one-shot command with an explicit working directory",
}


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
) -> DenyOnlyKernel:
    safe_yolo = Path(safe_yolo_home).expanduser()
    codex = Path(codex_home).expanduser()
    home = Path(user_home).expanduser()
    return DenyOnlyKernel(
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


def handle_pre_tool(
    payload: dict[str, Any],
    kernel: DenyOnlyKernel,
) -> dict[str, Any] | None:
    decision = kernel.evaluate(payload)
    if decision.outcome == "allow":
        return None
    consequence = str(decision.consequence)
    safe_method = SAFE_METHODS.get(consequence, "use a different safe method")
    return _deny(
        f"Safe YOLO denied [{consequence}]: {decision.display}. "
        f"Use a different safe method: {safe_method}."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe YOLO deny-only Codex consequence hook.")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--safe-yolo-home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--codex-home", type=Path, default=Path("~/.codex").expanduser())
    parser.add_argument("--user-home", type=Path, default=Path.home())
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if not isinstance(payload, dict):
        response = None
    else:
        kernel = build_kernel(
            safe_yolo_home=args.safe_yolo_home,
            codex_home=args.codex_home,
            user_home=args.user_home,
        )
        response = handle_pre_tool(payload, kernel)
    if response is not None:
        json.dump(response, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
