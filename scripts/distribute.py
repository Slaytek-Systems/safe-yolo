"""User-facing, reversible Safe YOLO private-beta distribution workflow."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.activate_v3 import _ensure_release, verify_source
from scripts.doctor import inspect_claude_code_wiring, inspect_codex_wiring, inspect_release
from scripts.harness_specs import HARNESS_BY_ID, HARNESS_HOME_ENV, HARNESSES, HarnessSpec
from scripts.package import MANIFEST as DISTRIBUTION_MANIFEST, verify_bundle
from scripts.harness_wiring import (
    inspect_cursor_wiring as _inspect_cursor_wiring,
    pinned_command as _pinned_command,
    prepare_command_hooks as _prepare_hooks,
    prepare_cursor_hooks as _prepare_cursor_hooks,
    read_json_object as _read_json_object,
)


RECEIPT_NAME = "codex-install.json"


def harness_catalog(user_home: str | Path | None = None) -> list[dict[str, Any]]:
    home = Path.home() if user_home is None else Path(user_home).expanduser()
    return [
        {
            "id": spec.id,
            "name": spec.name,
            "status": spec.status,
            "entry": spec.entry,
            "lifecycle_supported": spec.lifecycle_supported,
            "detected": shutil.which(spec.binary) is not None or (home / spec.config_dir).exists(),
        }
        for spec in HARNESSES
    ]


def _spec(harness: str) -> HarnessSpec:
    try:
        spec = HARNESS_BY_ID[harness]
    except KeyError as error:
        raise RuntimeError(
            f"Unknown harness {harness!r}. Choose one of: {', '.join(HARNESS_BY_ID)}."
        ) from error
    if not spec.lifecycle_supported:
        raise RuntimeError(
            f"{spec.name} is adapter-only in this release; install, doctor, and deactivate are not yet supported."
        )
    return spec


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


def _run_canaries(
    home: Path,
    release: Path,
    manifest_sha256: str,
    *,
    harness: str = "codex",
    entry: str = "codex_v3",
    user_home: Path | None = None,
    harness_home: Path | None = None,
) -> dict[str, bool]:
    command = shlex.split(
        _pinned_command(
            home,
            release,
            manifest_sha256,
            entry,
            user_home=user_home,
            harness_home=harness_home,
        )
    )
    base = {"hook_event_name": "PreToolUse", "cwd": str(Path.cwd())}
    if harness == "codex":
        allowed_payload = {**base, "tool_name": "exec_command", "tool_input": {"cmd": "git status --short"}}
        denied_payload = {**base, "tool_name": "exec_command", "tool_input": {"cmd": "git push --force-with-lease"}}
    elif harness == "claude-code":
        allowed_payload = {**base, "tool_name": "Bash", "tool_input": {"command": "git status --short"}}
        denied_payload = {**base, "tool_name": "Bash", "tool_input": {"command": "git push --force-with-lease"}}
    else:
        cursor_base = {"hook_event_name": "preToolUse", "cwd": str(Path.cwd()), "tool_name": "Shell"}
        allowed_payload = {**cursor_base, "tool_input": {"command": "git status --short"}}
        denied_payload = {**cursor_base, "tool_input": {"command": "git push --force-with-lease"}}
    allowed = subprocess.run(
        command,
        input=json.dumps(allowed_payload),
        text=True,
        capture_output=True,
        check=False,
    )
    denied = subprocess.run(
        command,
        input=json.dumps(denied_payload),
        text=True,
        capture_output=True,
        check=False,
    )
    allow_ok = allowed.returncode == 0 and not allowed.stdout.strip()
    try:
        denial = json.loads(denied.stdout)
        deny_ok = denied.returncode == 0 and (
            denial.get("permission") == "deny"
            if harness == "cursor"
            else denial["hookSpecificOutput"]["permissionDecision"] == "deny"
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        deny_ok = False
    if harness == "cursor":
        try:
            allow_ok = (
                allowed.returncode == 0
                and json.loads(allowed.stdout).get("permission") == "allow"
            )
        except (json.JSONDecodeError, AttributeError):
            allow_ok = False
    return {"allow": allow_ok, "deny": deny_ok}


def _receipt_path(home: Path) -> Path:
    return home / "state" / RECEIPT_NAME


def _write_receipt(home: Path, receipt: dict[str, Any]) -> None:
    _atomic_write(
        _receipt_path(home),
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )


def _harness_receipt_path(home: Path, harness: str) -> Path:
    return home / "state" / "installations" / f"{harness}.json"


def _read_harness_receipt(home: Path, spec: HarnessSpec) -> tuple[dict[str, Any], Path]:
    receipt_path = _harness_receipt_path(home, spec.id)
    if receipt_path.is_file() or spec.id != "codex":
        return _read_json_object(receipt_path), receipt_path

    legacy_path = _receipt_path(home)
    legacy = _read_json_object(legacy_path)
    normalized = {
        **legacy,
        "harness": "codex",
        "config_path": legacy.get("hooks_path"),
        "installed_config_sha256": legacy.get("installed_hooks_sha256"),
        "previous_config_existed": legacy.get("previous_hooks_existed"),
        "previous_config_backup": legacy.get("previous_hooks_backup"),
        "previous_config_mode": legacy.get("previous_hooks_mode"),
    }
    return normalized, legacy_path


def _has_harness_receipt(home: Path, spec: HarnessSpec) -> bool:
    return _harness_receipt_path(home, spec.id).is_file() or (
        spec.id == "codex" and _receipt_path(home).is_file()
    )


def _config_path(spec: HarnessSpec, user_home: Path, config_home: str | Path | None) -> Path:
    environment_name = HARNESS_HOME_ENV.get(spec.id)
    environment_home = os.environ.get(environment_name) if environment_name else None
    root = (
        Path(config_home).expanduser().resolve(strict=False)
        if config_home is not None
        else (
            Path(environment_home).expanduser().resolve(strict=False)
            if environment_home
            else (user_home / spec.config_dir).resolve(strict=False)
        )
    )
    return root / spec.config_file


def _inspect_wiring(
    spec: HarnessSpec,
    config_path: Path,
    home: Path,
    release: Path,
    digest: str,
    *,
    user_home: Path | None = None,
    harness_home: Path | None = None,
    bootstrap: Path | None = None,
) -> dict[str, Any]:
    bootstrap_path = bootstrap or home / "bootstrap.py"
    if spec.id == "codex":
        return inspect_codex_wiring(
            config_path.parent / "config.toml",
            config_path,
            bootstrap_path,
            digest,
            release_path=release,
            entry=spec.entry,
            safe_yolo_home=home if user_home is not None else None,
            user_home=user_home,
            harness_home=harness_home,
        )
    if spec.id == "claude-code":
        return inspect_claude_code_wiring(
            config_path,
            bootstrap_path,
            digest,
            release_path=release,
            entry=spec.entry,
            safe_yolo_home=home if user_home is not None else None,
            user_home=user_home,
            harness_home=harness_home,
        )
    return _inspect_cursor_wiring(
        config_path,
        home,
        release,
        digest,
        user_home=user_home,
        harness_home=harness_home,
    )


def install_harness(
    *,
    harness: str,
    source: str | Path,
    safe_yolo_home: str | Path,
    user_home: str | Path,
    expected_commit: str,
    config_home: str | Path | None = None,
) -> dict[str, Any]:
    spec = _spec(harness)
    source_path = Path(source).resolve()
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    user = Path(user_home).expanduser().resolve(strict=False)
    target = _config_path(spec, user, config_home)
    source_commit = (
        verify_bundle(source_path)
        if (source_path / DISTRIBUTION_MANIFEST).is_file()
        else verify_source(source_path, expected_commit)
    )
    if source_commit != expected_commit:
        raise RuntimeError('Download source revision does not match the requested revision.')
    release, digest, version = _ensure_release(source_path, home)
    command = _pinned_command(
        home,
        release,
        digest,
        spec.entry,
        user_home=user,
        harness_home=target.parent,
    )
    if spec.id == "cursor":
        candidate, original_bytes, original_mode = _prepare_cursor_hooks(target, home, command)
    else:
        candidate, original_bytes, original_mode = _prepare_hooks(
            target, home, command, entry=spec.entry, label=spec.name
        )
    backup_root = home / "backups" / (
        f"pre-{spec.id}-{version}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    )
    backup_root.mkdir(parents=True, mode=0o700)
    backup_path: Path | None = None
    if original_bytes is not None:
        backup_path = backup_root / target.name
        _atomic_write(backup_path, original_bytes, original_mode)
    payload = (json.dumps(candidate, indent=2) + "\n").encode()
    _atomic_write(target, payload, original_mode)
    try:
        wiring = _inspect_wiring(
            spec,
            target,
            home,
            release,
            digest,
            user_home=user,
            harness_home=target.parent,
            bootstrap=release / "scripts" / "bootstrap.py",
        )
        canaries = _run_canaries(
            home,
            release,
            digest,
            harness=spec.id,
            entry=spec.entry,
            user_home=user,
            harness_home=target.parent,
        )
        if not wiring["healthy"] or not all(canaries.values()):
            raise RuntimeError(
                f"doctor problems={wiring['problems']}; canaries={canaries}"
            )
    except Exception as error:
        if original_bytes is None:
            failed = backup_root / f"failed-{target.name}"
            os.replace(target, failed)
        else:
            _atomic_write(target, original_bytes, original_mode)
        raise RuntimeError(f"Safe YOLO activation failed; previous hooks restored: {error}") from error
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "active",
        "harness": spec.id,
        "version": version,
        "source_commit": source_commit,
        "release": str(release),
        "bootstrap": str(release / "scripts" / "bootstrap.py"),
        "manifest_sha256": digest,
        "config_path": str(target),
        "user_home": str(user),
        "harness_home": str(target.parent),
        "installed_config_sha256": _sha256(target),
        "previous_config_existed": original_bytes is not None,
        "previous_config_backup": str(backup_path) if backup_path else None,
        "previous_config_mode": original_mode,
        "healthy": True,
        "canaries": canaries,
        "next_action": {
            "codex": "Restart Codex, open /hooks, review this command, and trust its hash.",
            "claude-code": "Restart Claude Code, then run /hooks and verify the Safe YOLO PreToolUse hook.",
            "cursor": "Cursor watches the user hooks file and reloads it automatically; verify Safe YOLO in Hooks.",
        }[spec.id],
    }
    _atomic_write(
        _harness_receipt_path(home, spec.id),
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )
    return receipt


def doctor_harness(
    *, harness: str, safe_yolo_home: str | Path, user_home: str | Path
) -> dict[str, Any]:
    spec = _spec(harness)
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    receipt, _ = _read_harness_receipt(home, spec)
    problems: list[str] = []
    if receipt.get("status") != "active":
        problems.append("installation receipt is not active")
    config_path = Path(str(receipt.get("config_path", "")))
    if not config_path.is_file():
        problems.append("installed harness configuration is missing")
    elif _sha256(config_path) != receipt.get("installed_config_sha256"):
        problems.append("installed harness configuration changed after activation")
    release = Path(str(receipt.get("release", "")))
    digest = str(receipt.get("manifest_sha256", ""))
    receipt_user_home = receipt.get("user_home")
    receipt_harness_home = receipt.get("harness_home")
    user = Path(str(receipt_user_home)) if receipt_user_home else None
    harness_home = Path(str(receipt_harness_home)) if receipt_harness_home else None
    receipt_bootstrap = receipt.get("bootstrap")
    bootstrap = Path(str(receipt_bootstrap)) if receipt_bootstrap else home / "bootstrap.py"
    release_report = inspect_release(release, digest)
    problems.extend(release_report["problems"])
    wiring = _inspect_wiring(
        spec,
        config_path,
        home,
        release,
        digest,
        user_home=user,
        harness_home=harness_home,
        bootstrap=bootstrap,
    )
    problems.extend(wiring["problems"])
    canaries = (
        _run_canaries(
            home,
            release,
            digest,
            harness=spec.id,
            entry=spec.entry,
            user_home=user,
            harness_home=harness_home,
        )
        if release_report["healthy"]
        else {"allow": False, "deny": False}
    )
    if not all(canaries.values()):
        problems.append("allow/deny runtime canaries failed")
    return {
        "healthy": not problems,
        "harness": spec.id,
        "status": receipt.get("status"),
        "version": receipt.get("version"),
        "release": str(release),
        "canaries": canaries,
        "problems": problems,
        "activation_check": receipt.get("next_action"),
    }


def deactivate_harness(
    *, harness: str, safe_yolo_home: str | Path, user_home: str | Path
) -> dict[str, Any]:
    spec = _spec(harness)
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    receipt, receipt_path = _read_harness_receipt(home, spec)
    if receipt.get("status") != "active":
        raise RuntimeError(f"Safe YOLO {spec.name} installation is not active.")
    config_path = Path(str(receipt.get("config_path", "")))
    if not config_path.is_file() or _sha256(config_path) != receipt.get("installed_config_sha256"):
        raise RuntimeError(f"{spec.name} configuration changed since installation; refusing to overwrite newer work.")
    if receipt.get("previous_config_existed"):
        backup = Path(str(receipt.get("previous_config_backup")))
        if not backup.is_file():
            raise RuntimeError("Previous configuration backup is missing; refusing an incomplete rollback.")
        _atomic_write(config_path, backup.read_bytes(), int(receipt.get("previous_config_mode", 0o600)))
    else:
        retained = home / "backups" / (
            f"deactivated-{spec.id}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}-{config_path.name}"
        )
        retained.parent.mkdir(parents=True, exist_ok=True)
        os.replace(config_path, retained)
        receipt["deactivated_config_backup"] = str(retained)
    receipt["status"] = "inactive"
    receipt["deactivated_at"] = datetime.now(UTC).isoformat()
    _atomic_write(receipt_path, (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
    return {
        "status": "inactive",
        "harness": spec.id,
        "restored_previous_config": bool(receipt.get("previous_config_existed")),
        "retained_release": str(receipt.get("release")),
        "next_action": f"Restart {spec.name} if it is running. Immutable release and rollback evidence were retained.",
    }


def install_codex(
    *, source: str | Path, safe_yolo_home: str | Path, codex_home: str | Path, expected_commit: str
) -> dict[str, Any]:
    receipt = install_harness(
        harness="codex",
        source=source,
        safe_yolo_home=safe_yolo_home,
        user_home=Path(codex_home).expanduser().parent,
        config_home=codex_home,
        expected_commit=expected_commit,
    )
    legacy = {
        **receipt,
        "hooks_path": receipt["config_path"],
        "installed_hooks_sha256": receipt["installed_config_sha256"],
        "previous_hooks_existed": receipt["previous_config_existed"],
        "previous_hooks_backup": receipt["previous_config_backup"],
        "previous_hooks_mode": receipt["previous_config_mode"],
    }
    _write_receipt(Path(safe_yolo_home).expanduser().resolve(strict=False), legacy)
    return legacy


def doctor_codex(*, safe_yolo_home: str | Path, codex_home: str | Path) -> dict[str, Any]:
    return doctor_harness(
        harness="codex",
        safe_yolo_home=safe_yolo_home,
        user_home=Path(codex_home).expanduser().parent,
    )


def deactivate_codex(*, safe_yolo_home: str | Path, codex_home: str | Path) -> dict[str, Any]:
    result = deactivate_harness(
        harness="codex",
        safe_yolo_home=safe_yolo_home,
        user_home=Path(codex_home).expanduser().parent,
    )
    return {**result, "restored_previous_hooks": result["restored_previous_config"]}


def _current_commit(source: Path) -> str:
    if (source / DISTRIBUTION_MANIFEST).is_file():
        return verify_bundle(source)
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
        description="Manage the harness-agnostic Safe YOLO private beta.",
    )
    parser.add_argument("--home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--user-home", type=Path, default=Path.home())
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("harnesses", help="List adapters and honest lifecycle support levels.")
    install = subparsers.add_parser("install", help="Install and activate one supported harness integration.")
    install.add_argument("--harness", choices=tuple(HARNESS_BY_ID), required=True)
    install.add_argument("--source", type=Path, default=ROOT)
    install.add_argument("--config-home", type=Path)
    doctor = subparsers.add_parser("doctor", help="Verify release, wiring, and allow/deny canaries.")
    doctor_group = doctor.add_mutually_exclusive_group(required=True)
    doctor_group.add_argument("--harness", choices=tuple(HARNESS_BY_ID))
    doctor_group.add_argument("--all", action="store_true", help="Check every installed supported harness.")
    deactivate = subparsers.add_parser("deactivate", help="Restore one harness's exact pre-install state.")
    deactivate.add_argument("--harness", choices=tuple(HARNESS_BY_ID), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "harnesses":
            result: Any = {"harnesses": harness_catalog(args.user_home)}
        elif args.command == "install":
            source = args.source.resolve()
            result = install_harness(
                harness=args.harness,
                source=source,
                safe_yolo_home=args.home,
                user_home=args.user_home,
                config_home=args.config_home,
                expected_commit=_current_commit(source),
            )
        elif args.command == "doctor":
            if args.all:
                installed = [
                    spec.id
                    for spec in HARNESSES
                    if spec.lifecycle_supported
                    and _has_harness_receipt(args.home.expanduser(), spec)
                ]
                reports = [
                    doctor_harness(
                        harness=harness,
                        safe_yolo_home=args.home,
                        user_home=args.user_home,
                    )
                    for harness in installed
                ]
                result = {"healthy": bool(reports) and all(item["healthy"] for item in reports), "reports": reports}
            else:
                result = doctor_harness(
                    harness=args.harness,
                    safe_yolo_home=args.home,
                    user_home=args.user_home,
                )
        else:
            result = deactivate_harness(
                harness=args.harness,
                safe_yolo_home=args.home,
                user_home=args.user_home,
            )
    except RuntimeError as error:
        print(f"safe-yolo: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("healthy", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
