"""Update the devbox Safe YOLO runtime from its locally verified canonical source."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.doctor import inspect_codex_wiring, inspect_release
from scripts.install import install_release
from scripts.release_manifest import manifest_digest

SOURCE = Path("/home/dev/safe-yolo-source")
HOME = Path("/home/dev/.safe-yolo")
HOOKS = Path("/home/dev/.codex/hooks.json")
HOST_CONTRACT_SOURCE = Path("/home/dev/devbox-ops/config/safe-yolo-host-contract.json")
HOST_CONTRACT = HOME / "host-contract.json"
CURSOR_HOOKS = (
    Path("/home/dev/.cursor/hooks/safe-yolo-cursor.sh"),
    Path("/home/dev/.cursor/hooks/safe-yolo-cursor-prompt.sh"),
)
RELEASE_PIN_RE = re.compile(r"(--release\s+)\S+")
MANIFEST_PIN_RE = re.compile(r"(--manifest-sha256\s+)[0-9a-f]{64}")


def install_host_contract(
    source: Path,
    target: Path,
    backup_dir: Path,
    version: str,
) -> bool:
    raw = source.read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError("Reviewed host contract must be valid JSON.") from error
    if not isinstance(document, dict) or not isinstance(document.get("version"), str) or not document["version"]:
        raise ValueError("Reviewed host contract must be a versioned JSON object.")
    if target.is_file() and target.read_bytes() == raw:
        os.chmod(target, 0o600)
        return False

    target.parent.mkdir(parents=True, exist_ok=True)
    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    if target.exists():
        backup = backup_dir / f"host-contract.json.pre-{version}"
        if not backup.exists():
            shutil.copy2(target, backup)
            os.chmod(backup, 0o600)

    with tempfile.TemporaryDirectory(dir=target.parent, prefix=".host-contract.") as temporary:
        staging = Path(temporary) / target.name
        staging.write_bytes(raw)
        os.chmod(staging, 0o600)
        os.replace(staging, target)
    return True


def repin_command_text(text: str, release: Path, manifest_sha256: str) -> tuple[str, int]:
    """Update release/manifest pins in single-line or shell-continued commands."""
    updated, release_count = RELEASE_PIN_RE.subn(rf"\g<1>{release}", text, count=1)
    updated, digest_count = MANIFEST_PIN_RE.subn(rf"\g<1>{manifest_sha256}", updated, count=1)
    if release_count != 1 or digest_count != 1:
        return text, 0
    return updated, 1


def repin_hooks(release: Path, manifest_sha256: str) -> int:
    document = json.loads(HOOKS.read_text())
    replaced = 0
    for groups in document.get("hooks", {}).values():
        for group in groups:
            for hook in group.get("hooks", []):
                command = hook.get("command")
                if not isinstance(command, str):
                    continue
                updated, count = repin_command_text(command, release, manifest_sha256)
                if count:
                    hook["command"] = updated
                    replaced += count
    if replaced < 2:
        raise RuntimeError("Expected to repin both canonical Safe YOLO hooks.")
    backup = HOME / "backups" / "hooks.json.pre-remote-update"
    if not backup.exists():
        shutil.copy2(HOOKS, backup)
    HOOKS.write_text(json.dumps(document, indent=2) + "\n")
    return replaced


def repin_cursor_hooks(release: Path, manifest_sha256: str) -> int:
    replaced = 0
    for path in CURSOR_HOOKS:
        if not path.is_file():
            continue
        original = path.read_text()
        updated, count = repin_command_text(original, release, manifest_sha256)
        if count:
            path.write_text(updated)
            replaced += count
    if replaced < 1:
        raise RuntimeError("Expected to repin at least one Cursor Safe YOLO hook.")
    return replaced


def ensure_release(version: str) -> dict[str, str]:
    target = HOME / "releases" / version
    if target.exists():
        digest = manifest_digest(target)
        return {"version": version, "release": str(target), "manifest_sha256": digest}
    receipt = install_release(SOURCE, HOME)
    return {
        "version": str(receipt["version"]),
        "release": str(receipt["release"]),
        "manifest_sha256": str(receipt["manifest_sha256"]),
    }


def main() -> int:
    if not SOURCE.is_dir() or not HOME.is_dir() or not HOST_CONTRACT_SOURCE.is_file():
        raise RuntimeError("Expected devbox canonical source, host contract, and Safe YOLO home paths.")
    version = (SOURCE / "VERSION").read_text().strip()
    receipt = ensure_release(version)
    release = Path(receipt["release"])
    manifest_sha256 = receipt["manifest_sha256"]
    report = inspect_release(release, manifest_sha256)
    if not report["healthy"]:
        raise RuntimeError(f"Release failed doctor before wiring: {report['problems']}")

    bootstrap = HOME / "bootstrap.py"
    source_bootstrap = SOURCE / "scripts" / "bootstrap.py"
    if bootstrap.read_bytes() != source_bootstrap.read_bytes():
        backup = HOME / "backups" / f"bootstrap.py.pre-{version}"
        if not backup.exists():
            shutil.copy2(bootstrap, backup)
        shutil.copy2(source_bootstrap, bootstrap)

    host_contract_updated = install_host_contract(
        HOST_CONTRACT_SOURCE,
        HOST_CONTRACT,
        HOME / "backups",
        version,
    )
    repin_hooks(release, manifest_sha256)
    cursor_pins = repin_cursor_hooks(release, manifest_sha256)
    wiring = inspect_codex_wiring(
        HOME.parent / ".codex" / "config.toml",
        HOOKS,
        HOME / "bootstrap.py",
        manifest_sha256,
    )
    if not wiring["healthy"]:
        raise RuntimeError(f"Installed release failed doctor: {wiring['problems']}")
    print(json.dumps({
        "version": version,
        "release": str(release),
        "manifest_sha256": manifest_sha256,
        "cursor_pins": cursor_pins,
        "host_contract_updated": host_contract_updated,
        "healthy": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
