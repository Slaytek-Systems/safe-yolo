"""Externally operated, atomic Safe YOLO v3 installation and Codex hook cutover."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.doctor import inspect_codex_wiring, inspect_release
from scripts.install import install_release
from scripts.release_manifest import manifest_digest, source_files


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_source(source: Path, expected_commit: str) -> str:
    if len(expected_commit) != 40 or any(character not in "0123456789abcdef" for character in expected_commit.lower()):
        raise RuntimeError("Expected source commit must be one full hexadecimal Git SHA.")
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        text=True,
        capture_output=True,
        check=False,
    )
    if revision.returncode != 0 or revision.stdout.strip() != expected_commit:
        raise RuntimeError("Source checkout is not at the expected reviewed commit.")
    status = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=source,
        text=True,
        capture_output=True,
        check=False,
    )
    if status.returncode != 0 or status.stdout:
        raise RuntimeError("Source checkout must be clean before activation.")
    return expected_commit


def _read_hooks(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("Codex hooks file is unavailable or unsafe.")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Codex hooks file is unreadable: {type(error).__name__}") from error
    hooks = document.get("hooks") if isinstance(document, dict) else None
    pretool = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
    commands: list[dict[str, Any]] = []
    if isinstance(pretool, list):
        for group in pretool:
            if not isinstance(group, dict) or group.get("matcher") != "*":
                continue
            entries = group.get("hooks")
            if not isinstance(entries, list):
                continue
            commands.extend(
                entry
                for entry in entries
                if isinstance(entry, dict) and entry.get("type") == "command"
            )
    if len(commands) != 1:
        raise RuntimeError("Activation requires exactly one PreToolUse command hook matched to *.")
    posttool = hooks.get("PostToolUse") if isinstance(hooks, dict) else None
    if posttool:
        raise RuntimeError("Activation refuses a non-empty PostToolUse hook lifecycle.")
    return document, commands[0]


def _candidate_hooks(
    original: dict[str, Any],
    command_hook: dict[str, Any],
    *,
    home: Path,
    release: Path,
    manifest_sha256: str,
) -> dict[str, Any]:
    candidate = json.loads(json.dumps(original))
    hooks = candidate["hooks"]["PreToolUse"]
    selected = next(
        entry
        for group in hooks
        if isinstance(group, dict) and group.get("matcher") == "*"
        for entry in group.get("hooks", [])
        if isinstance(entry, dict) and entry.get("type") == "command"
    )
    selected.clear()
    selected.update(command_hook)
    selected["command"] = (
        f"/usr/bin/python3 {home / 'bootstrap.py'} "
        f"--release {release} --manifest-sha256 {manifest_sha256} "
        f"--entry codex_v3 --state-dir {home / 'state'}"
    )
    selected["statusMessage"] = "Checking explicit Safe YOLO restrictions"
    candidate["description"] = (
        "Safe YOLO v3 default-open policy with explicit hard denials and no approval path."
    )
    return candidate


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
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


def _existing_release_matches_source(source: Path, release: Path) -> bool:
    report = inspect_release(release)
    if not report["healthy"]:
        return False
    try:
        manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    expected = {
        str(path.relative_to(source)): _sha256(path)
        for path in source_files(source)
    }
    return manifest.get("files") == expected


def _ensure_release(source: Path, home: Path) -> tuple[Path, str, str]:
    version = (source / "VERSION").read_text(encoding="utf-8").strip()
    if not version.startswith("3."):
        raise RuntimeError("The v3 operator activates only a Safe YOLO 3.x candidate.")
    release = home / "releases" / version
    if release.exists():
        if not _existing_release_matches_source(source, release):
            raise RuntimeError("Existing release does not match the reviewed source candidate.")
        return release, manifest_digest(release), version
    receipt = install_release(source, home)
    return Path(receipt["release"]), str(receipt["manifest_sha256"]), version


def activate_release(
    *,
    source: str | Path,
    home: str | Path,
    hooks_path: str | Path,
    config_path: str | Path,
    expected_commit: str,
) -> dict[str, Any]:
    source_path = Path(source).resolve()
    home_path = Path(home).expanduser().resolve(strict=False)
    hooks = Path(hooks_path).expanduser()
    if not hooks.is_absolute():
        hooks = Path.cwd() / hooks
    config = Path(config_path).expanduser().resolve(strict=False)
    source_commit = verify_source(source_path, expected_commit)
    original_document, command_hook = _read_hooks(hooks)
    original_bytes = hooks.read_bytes()
    original_mode = hooks.stat().st_mode & 0o777
    release, digest, version = _ensure_release(source_path, home_path)
    release_report = inspect_release(release, digest)
    if not release_report["healthy"]:
        raise RuntimeError(f"Candidate release failed doctor: {release_report['problems']}")
    candidate = _candidate_hooks(
        original_document,
        command_hook,
        home=home_path,
        release=release,
        manifest_sha256=digest,
    )
    backup_root = home_path / "backups" / (
        f"pre-{version}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    )
    backup_root.mkdir(parents=True, mode=0o700)
    backup = backup_root / "hooks.json"
    shutil.copy2(hooks, backup)
    (home_path / "state").mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(candidate, indent=2) + "\n").encode()
    _atomic_write(hooks, payload, original_mode)
    try:
        wiring = inspect_codex_wiring(
            config,
            hooks,
            home_path / "bootstrap.py",
            digest,
            release_path=release,
            entry="codex_v3",
        )
    except Exception as error:
        _atomic_write(hooks, original_bytes, original_mode)
        raise RuntimeError("Activated release doctor crashed; hooks restored.") from error
    if not wiring["healthy"]:
        _atomic_write(hooks, original_bytes, original_mode)
        raise RuntimeError(f"Activated release failed doctor; hooks restored: {wiring['problems']}")
    return {
        "version": version,
        "release": str(release),
        "manifest_sha256": digest,
        "source_commit": source_commit,
        "backup": str(backup),
        "healthy": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Atomically activate a reviewed Safe YOLO v3 release for Codex.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--home", type=Path, default=Path("/home/dev/.safe-yolo"))
    parser.add_argument("--hooks", type=Path, default=Path("/home/dev/.codex/hooks.json"))
    parser.add_argument("--config", type=Path, default=Path("/home/dev/.codex/config.toml"))
    args = parser.parse_args()
    receipt = activate_release(
        source=args.source,
        home=args.home,
        hooks_path=args.hooks,
        config_path=args.config,
        expected_commit=args.expected_source_commit,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
