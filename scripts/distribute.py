"""User-facing, reversible Safe YOLO private-beta distribution workflow."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.activate_v3 import _ensure_release, verify_source
from scripts.doctor import inspect_codex_wiring, inspect_release


RECEIPT_NAME = "codex-install.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"JSON file is unreadable: {path} ({type(error).__name__})") from error
    if not isinstance(document, dict):
        raise RuntimeError(f"JSON document must be an object: {path}")
    return document


def _is_safe_yolo_command(command: Any, home: Path) -> bool:
    if not isinstance(command, str):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    return (
        len(tokens) >= 2
        and tokens[1] == str(home / "bootstrap.py")
        and "--entry" in tokens
        and tokens[tokens.index("--entry") + 1 : tokens.index("--entry") + 2] == ["codex_v3"]
    )


def _prepare_hooks(path: Path, home: Path, command: str) -> tuple[dict[str, Any], bytes | None, int]:
    original_bytes: bytes | None = None
    mode = 0o600
    if path.exists():
        if path.is_symlink() or not path.is_file():
            raise RuntimeError("Codex hooks path is unavailable or unsafe.")
        original_bytes = path.read_bytes()
        mode = path.stat().st_mode & 0o777
        document = _read_json_object(path)
    else:
        document = {}
    hooks = document.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise RuntimeError("Codex hooks field must be an object.")
    existing_pretool = hooks.get("PreToolUse", [])
    commands = [
        entry.get("command")
        for group in existing_pretool
        if isinstance(group, dict)
        for entry in group.get("hooks", [])
        if isinstance(entry, dict) and entry.get("type") == "command"
    ] if isinstance(existing_pretool, list) else []
    if commands and not all(_is_safe_yolo_command(item, home) for item in commands):
        raise RuntimeError(
            "Codex already has an existing PreToolUse command hook. "
            "Safe YOLO will not replace a foreign enforcement surface."
        )
    posttool = hooks.get("PostToolUse", [])
    if posttool:
        raise RuntimeError("Codex has a non-empty PostToolUse lifecycle; Safe YOLO will not replace it.")
    hooks["PreToolUse"] = [
        {
            "matcher": "*",
            "hooks": [
                {
                    "type": "command",
                    "command": command,
                    "timeout": 10,
                    "statusMessage": "Checking explicit Safe YOLO restrictions",
                }
            ],
        }
    ]
    document["description"] = (
        "Safe YOLO v3 default-open policy with explicit hard denials and no approval path."
    )
    return document, original_bytes, mode


def _run_canaries(home: Path, release: Path, manifest_sha256: str) -> dict[str, bool]:
    command = [
        sys.executable,
        str(home / "bootstrap.py"),
        "--release",
        str(release),
        "--manifest-sha256",
        manifest_sha256,
        "--entry",
        "codex_v3",
        "--state-dir",
        str(home / "state"),
    ]
    base = {
        "hook_event_name": "PreToolUse",
        "cwd": str(Path.cwd()),
        "tool_name": "exec_command",
    }
    allowed = subprocess.run(
        command,
        input=json.dumps({**base, "tool_input": {"cmd": "git status --short"}}),
        text=True,
        capture_output=True,
        check=False,
    )
    denied = subprocess.run(
        command,
        input=json.dumps({**base, "tool_input": {"cmd": "git push --force-with-lease"}}),
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        denial = json.loads(denied.stdout)
        deny_ok = (
            denied.returncode == 0
            and denial["hookSpecificOutput"]["permissionDecision"] == "deny"
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        deny_ok = False
    return {
        "allow": allowed.returncode == 0 and not allowed.stdout.strip(),
        "deny": deny_ok,
    }


def _receipt_path(home: Path) -> Path:
    return home / "state" / RECEIPT_NAME


def _write_receipt(home: Path, receipt: dict[str, Any]) -> None:
    _atomic_write(
        _receipt_path(home),
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )


def install_codex(
    *,
    source: str | Path,
    safe_yolo_home: str | Path,
    codex_home: str | Path,
    expected_commit: str,
) -> dict[str, Any]:
    source_path = Path(source).resolve()
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    codex = Path(codex_home).expanduser().resolve(strict=False)
    hooks_path = codex / "hooks.json"
    config_path = codex / "config.toml"
    source_commit = verify_source(source_path, expected_commit)
    release, digest, version = _ensure_release(source_path, home)
    command = shlex.join(
        [
            sys.executable,
            str(home / "bootstrap.py"),
            "--release",
            str(release),
            "--manifest-sha256",
            digest,
            "--entry",
            "codex_v3",
            "--state-dir",
            str(home / "state"),
        ]
    )
    candidate, original_bytes, original_mode = _prepare_hooks(hooks_path, home, command)
    backup_root = home / "backups" / (
        f"pre-{version}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    )
    backup_root.mkdir(parents=True, mode=0o700)
    backup_path: Path | None = None
    if original_bytes is not None:
        backup_path = backup_root / "hooks.json"
        _atomic_write(backup_path, original_bytes, original_mode)
    payload = (json.dumps(candidate, indent=2) + "\n").encode()
    _atomic_write(hooks_path, payload, original_mode)
    try:
        wiring = inspect_codex_wiring(
            config_path,
            hooks_path,
            home / "bootstrap.py",
            digest,
            release_path=release,
            entry="codex_v3",
        )
        canaries = _run_canaries(home, release, digest)
        if not wiring["healthy"] or not all(canaries.values()):
            raise RuntimeError(
                f"doctor problems={wiring['problems']}; canaries={canaries}"
            )
    except Exception as error:
        if original_bytes is None:
            failed = backup_root / "failed-hooks.json"
            os.replace(hooks_path, failed)
        else:
            _atomic_write(hooks_path, original_bytes, original_mode)
        raise RuntimeError(f"Safe YOLO activation failed; previous hooks restored: {error}") from error
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "active",
        "version": version,
        "source_commit": source_commit,
        "release": str(release),
        "manifest_sha256": digest,
        "hooks_path": str(hooks_path),
        "installed_hooks_sha256": _sha256(hooks_path),
        "previous_hooks_existed": original_bytes is not None,
        "previous_hooks_backup": str(backup_path) if backup_path else None,
        "previous_hooks_mode": original_mode,
        "healthy": True,
        "canaries": canaries,
        "next_action": "Restart Codex, open /hooks, review this command, and trust its hash.",
    }
    _write_receipt(home, receipt)
    return receipt


def doctor_codex(*, safe_yolo_home: str | Path, codex_home: str | Path) -> dict[str, Any]:
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    codex = Path(codex_home).expanduser().resolve(strict=False)
    receipt_path = _receipt_path(home)
    receipt = _read_json_object(receipt_path)
    problems: list[str] = []
    if receipt.get("status") != "active":
        problems.append("installation receipt is not active")
    hooks_path = Path(str(receipt.get("hooks_path", codex / "hooks.json")))
    if not hooks_path.is_file():
        problems.append("installed hooks file is missing")
    elif _sha256(hooks_path) != receipt.get("installed_hooks_sha256"):
        problems.append("installed hooks changed after activation")
    release = Path(str(receipt.get("release", "")))
    digest = str(receipt.get("manifest_sha256", ""))
    release_report = inspect_release(release, digest)
    problems.extend(release_report["problems"])
    wiring = inspect_codex_wiring(
        codex / "config.toml",
        hooks_path,
        home / "bootstrap.py",
        digest,
        release_path=release,
        entry="codex_v3",
    )
    problems.extend(wiring["problems"])
    canaries = _run_canaries(home, release, digest) if release_report["healthy"] else {"allow": False, "deny": False}
    if not all(canaries.values()):
        problems.append("allow/deny runtime canaries failed")
    return {
        "healthy": not problems,
        "status": receipt.get("status"),
        "version": receipt.get("version"),
        "release": str(release),
        "canaries": canaries,
        "problems": problems,
        "session_trust": "Restart Codex and verify the hook is trusted in /hooks.",
    }


def deactivate_codex(*, safe_yolo_home: str | Path, codex_home: str | Path) -> dict[str, Any]:
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    codex = Path(codex_home).expanduser().resolve(strict=False)
    receipt = _read_json_object(_receipt_path(home))
    if receipt.get("status") != "active":
        raise RuntimeError("Safe YOLO Codex installation is not active.")
    hooks_path = codex / "hooks.json"
    if not hooks_path.is_file() or _sha256(hooks_path) != receipt.get("installed_hooks_sha256"):
        raise RuntimeError("Codex hooks changed since installation; refusing to overwrite newer work.")
    if receipt.get("previous_hooks_existed"):
        backup = Path(str(receipt.get("previous_hooks_backup")))
        if not backup.is_file():
            raise RuntimeError("Previous hooks backup is missing; refusing an incomplete rollback.")
        _atomic_write(hooks_path, backup.read_bytes(), int(receipt.get("previous_hooks_mode", 0o600)))
    else:
        retained = home / "backups" / (
            f"deactivated-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-hooks.json"
        )
        retained.parent.mkdir(parents=True, exist_ok=True)
        os.replace(hooks_path, retained)
        receipt["deactivated_hooks_backup"] = str(retained)
    receipt["status"] = "inactive"
    receipt["deactivated_at"] = datetime.now(UTC).isoformat()
    _write_receipt(home, receipt)
    return {
        "status": "inactive",
        "restored_previous_hooks": bool(receipt.get("previous_hooks_existed")),
        "retained_release": str(receipt.get("release")),
        "next_action": "Restart Codex. Immutable release and rollback evidence were retained.",
    }


def _current_commit(source: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Safe YOLO must be installed from a Git checkout.")
    return completed.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="safe-yolo",
        description="Install, verify, or deactivate the Safe YOLO Codex private beta.",
    )
    parser.add_argument("--home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument(
        "--codex-home",
        type=Path,
        default=Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser(),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    install = subparsers.add_parser("install", help="Install and activate the Codex integration.")
    install.add_argument("--source", type=Path, default=ROOT)
    subparsers.add_parser("doctor", help="Verify release, wiring, and allow/deny canaries.")
    subparsers.add_parser("deactivate", help="Restore the exact pre-install hook state.")
    args = parser.parse_args(argv)
    try:
        if args.command == "install":
            source = args.source.resolve()
            result = install_codex(
                source=source,
                safe_yolo_home=args.home,
                codex_home=args.codex_home,
                expected_commit=_current_commit(source),
            )
        elif args.command == "doctor":
            result = doctor_codex(safe_yolo_home=args.home, codex_home=args.codex_home)
        else:
            result = deactivate_codex(safe_yolo_home=args.home, codex_home=args.codex_home)
    except RuntimeError as error:
        print(f"safe-yolo: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("healthy", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
