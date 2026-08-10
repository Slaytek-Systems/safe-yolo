"""Atomically cut macOS Codex over to one verified Safe YOLO release."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any

from scripts.doctor import inspect_codex_wiring, inspect_release
from scripts.install import install_release


RELEASE_PIN_RE = re.compile(r"(--release\s+)\S+")
MANIFEST_PIN_RE = re.compile(r"(--manifest-sha256\s+)[0-9a-f]{64}")


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary = Path(raw_temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _repin_hooks(document: dict[str, Any], release: Path, manifest_sha256: str) -> tuple[dict[str, Any], int]:
    replaced = 0
    for groups in (document.get("hooks") or {}).values():
        for group in groups:
            for hook in group.get("hooks", []):
                command = hook.get("command")
                if not isinstance(command, str) or "--manifest-sha256" not in command:
                    continue
                updated, release_count = RELEASE_PIN_RE.subn(rf"\g<1>{release}", command, count=1)
                updated, digest_count = MANIFEST_PIN_RE.subn(rf"\g<1>{manifest_sha256}", updated, count=1)
                if release_count == 1 and digest_count == 1:
                    hook["command"] = updated
                    replaced += 1
    return document, replaced


def cutover(source: str | Path, safe_yolo_home: str | Path, codex_home: str | Path) -> dict[str, Any]:
    source_path = Path(source).resolve()
    home = Path(safe_yolo_home).expanduser().resolve(strict=True)
    codex = Path(codex_home).expanduser().resolve(strict=True)
    hooks = codex / "hooks.json"
    config = codex / "config.toml"
    host_contract = home / "host-contract.json"
    source_contract = source_path / "hosts" / "macos" / "macos.contract.json"
    if not hooks.is_file() or not config.is_file() or not source_contract.is_file():
        raise FileNotFoundError("Cutover requires existing Codex hooks/config and the source macOS host contract.")

    original_hooks = hooks.read_bytes()
    original_bootstrap = (home / "bootstrap.py").read_bytes()
    original_contract = host_contract.read_bytes()
    version = (source_path / "VERSION").read_text(encoding="utf-8").strip()
    backup_root = home / "backups" / f"macos-cutover-{version}"
    if backup_root.exists():
        raise FileExistsError(f"Cutover backup already exists: {backup_root}")
    backup_root.mkdir(parents=True, mode=0o700)
    os.chmod(backup_root, 0o700)
    (backup_root / "hooks.json").write_bytes(original_hooks)
    (backup_root / "bootstrap.py").write_bytes(original_bootstrap)
    (backup_root / "host-contract.json").write_bytes(original_contract)
    for backup in backup_root.iterdir():
        os.chmod(backup, 0o600)

    receipt = install_release(source_path, home, allow_bootstrap_mismatch=True)
    release = Path(receipt["release"])
    digest = str(receipt["manifest_sha256"])
    release_report = inspect_release(release, digest)
    if not release_report["healthy"]:
        raise RuntimeError(f"Release failed pre-cutover doctor: {release_report['problems']}")

    document = json.loads(original_hooks)
    document, replaced = _repin_hooks(document, release, digest)
    if replaced != 2:
        raise RuntimeError(f"Expected exactly two Safe YOLO hook pins; found {replaced}.")

    try:
        _atomic_write(home / "bootstrap.py", (source_path / "scripts" / "bootstrap.py").read_bytes(), 0o700)
        _atomic_write(host_contract, source_contract.read_bytes(), 0o600)
        _atomic_write(hooks, (json.dumps(document, indent=2) + "\n").encode("utf-8"), 0o600)
        wiring = inspect_codex_wiring(config, hooks, home / "bootstrap.py", digest)
        if not wiring["healthy"]:
            raise RuntimeError(f"Cutover wiring failed doctor: {wiring['problems']}")
    except Exception:
        _atomic_write(home / "bootstrap.py", original_bootstrap, 0o700)
        _atomic_write(host_contract, original_contract, 0o600)
        _atomic_write(hooks, original_hooks, 0o600)
        raise

    return {
        "healthy": True,
        "version": version,
        "release": str(release),
        "manifest_sha256": digest,
        "hook_pins": replaced,
        "rollback": str(backup_root),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verified, atomic macOS Safe YOLO cutover with rollback.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--codex-home", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(cutover(args.source, args.home, args.codex_home), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
