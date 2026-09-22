from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.release_manifest import build_manifest, manifest_digest


RELEASE_CONTENT = ("policy", "engine", "adapters")
RELEASE_FILES = ("scripts/bootstrap.py",)


def _copy_release(source: Path, staging: Path) -> None:
    for name in RELEASE_CONTENT:
        shutil.copytree(source / name, staging / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(source / "VERSION", staging / "VERSION")
    for relative in RELEASE_FILES:
        target = staging / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / relative, target)


def install_release(source_dir: str | Path, safe_yolo_home: str | Path) -> dict[str, Any]:
    """Create one immutable versioned release; never changes Codex config or hooks."""
    source = Path(source_dir).resolve()
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    version = (source / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise ValueError("Source VERSION is required.")
    releases = home / "releases"
    target = releases / version
    if target.exists():
        raise FileExistsError(f"Safe YOLO release already exists: {target}")
    bootstrap_source = source / "scripts" / "bootstrap.py"
    legacy_bootstrap = home / "bootstrap.py"
    releases.mkdir(parents=True, exist_ok=True)
    os.chmod(home, 0o700)
    os.chmod(releases, 0o700)
    with tempfile.TemporaryDirectory(dir=releases, prefix=f".{version}.") as temporary:
        staging = Path(temporary) / version
        staging.mkdir()
        _copy_release(source, staging)
        build_manifest(staging)
        digest = manifest_digest(staging)
        os.replace(staging, target)
    bootstrap_target = target / "scripts" / "bootstrap.py"
    os.chmod(bootstrap_target, 0o700)
    if not legacy_bootstrap.exists():
        shutil.copy2(bootstrap_source, legacy_bootstrap)
        os.chmod(legacy_bootstrap, 0o700)
    receipt = {
        "version": version,
        "release": target,
        "manifest_sha256": digest,
        "bootstrap": bootstrap_target,
    }
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description="Install a versioned Safe YOLO release without wiring host configuration.")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--home", type=Path, required=True)
    args = parser.parse_args()
    receipt = install_release(args.source, args.home)
    print(json.dumps({key: str(value) for key, value in receipt.items()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
