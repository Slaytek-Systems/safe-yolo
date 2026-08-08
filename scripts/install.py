from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any

from scripts.release_manifest import build_manifest, manifest_digest


RELEASE_CONTENT = ("policy", "engine", "adapters")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_release(source: Path, staging: Path) -> None:
    for name in RELEASE_CONTENT:
        shutil.copytree(source / name, staging / name, ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(source / "VERSION", staging / "VERSION")


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
    bootstrap_target = home / "bootstrap.py"
    if bootstrap_target.exists() and _sha256(bootstrap_target) != _sha256(bootstrap_source):
        raise FileExistsError("Existing bootstrap differs; replace it only through explicit maintenance.")
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
    if not bootstrap_target.exists():
        shutil.copy2(bootstrap_source, bootstrap_target)
        os.chmod(bootstrap_target, 0o700)
    receipt = {"version": version, "release": target, "manifest_sha256": digest, "bootstrap": bootstrap_target}
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
