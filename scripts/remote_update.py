"""Update the devbox Safe YOLO runtime from its locally verified canonical source."""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.doctor import inspect_codex_wiring, inspect_release
from scripts.install import install_release

SOURCE = Path("/home/dev/safe-yolo-source")
HOME = Path("/home/dev/.safe-yolo")
HOOKS = Path("/home/dev/.codex/hooks.json")
CURSOR_HOOKS = (
    Path("/home/dev/.cursor/hooks/safe-yolo-cursor.sh"),
    Path("/home/dev/.cursor/hooks/safe-yolo-cursor-prompt.sh"),
)
PIN_RE = re.compile(r"--release\s+\S+\s+--manifest-sha256\s+[0-9a-f]{64}")


def repin_hooks(release: Path, manifest_sha256: str) -> int:
    document = json.loads(HOOKS.read_text())
    replaced = 0
    replacement = f"--release {release} --manifest-sha256 {manifest_sha256}"
    for groups in document.get("hooks", {}).values():
        for group in groups:
            for hook in group.get("hooks", []):
                command = hook.get("command")
                if not isinstance(command, str):
                    continue
                updated, count = PIN_RE.subn(replacement, command)
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
    replacement = f"--release {release} --manifest-sha256 {manifest_sha256}"
    for path in CURSOR_HOOKS:
        if not path.is_file():
            continue
        original = path.read_text()
        updated, count = PIN_RE.subn(replacement, original)
        if count:
            path.write_text(updated)
            replaced += count
    if replaced < 1:
        raise RuntimeError("Expected to repin at least one Cursor Safe YOLO hook.")
    return replaced


def main() -> int:
    if not SOURCE.is_dir() or not HOME.is_dir():
        raise RuntimeError("Expected devbox canonical source and Safe YOLO home directories.")
    version = (SOURCE / "VERSION").read_text().strip()
    bootstrap = HOME / "bootstrap.py"
    source_bootstrap = SOURCE / "scripts" / "bootstrap.py"
    if bootstrap.read_bytes() != source_bootstrap.read_bytes():
        backup = HOME / "backups" / f"bootstrap.py.pre-{version}"
        if not backup.exists():
            shutil.copy2(bootstrap, backup)
        shutil.copy2(source_bootstrap, bootstrap)
    receipt = install_release(SOURCE, HOME)
    release = Path(receipt["release"])
    manifest_sha256 = receipt["manifest_sha256"]
    repin_hooks(release, manifest_sha256)
    cursor_pins = repin_cursor_hooks(release, manifest_sha256)
    report = inspect_release(release, manifest_sha256)
    wiring = inspect_codex_wiring(HOME.parent / ".codex" / "config.toml", HOOKS, HOME / "bootstrap.py", manifest_sha256)
    if not report["healthy"] or not wiring["healthy"]:
        raise RuntimeError(f"Installed release failed doctor: {[ *report['problems'], *wiring['problems'] ]}")
    print(json.dumps({
        "version": version,
        "release": str(release),
        "manifest_sha256": manifest_sha256,
        "cursor_pins": cursor_pins,
        "healthy": True,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
