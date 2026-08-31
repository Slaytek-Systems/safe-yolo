from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

MANIFEST_NAME = "manifest.json"
ENTRYPOINTS = {
    "codex": "adapters/codex.py",
    "codex_v2": "adapters/codex_v2.py",
    "codex_v3": "adapters/codex_v3.py",
    "prompt": "adapters/codex_prompt.py",
    "cursor": "adapters/cursor.py",
    "cursor_prompt": "adapters/cursor_prompt.py",
}
SOURCE_ROOTS = ("policy", "engine", "adapters")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_files(release_dir: Path) -> list[Path]:
    files: list[Path] = []
    for root_name in SOURCE_ROOTS:
        root = release_dir / root_name
        if not root.is_dir():
            continue
        files.extend(path for path in root.rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    version = release_dir / "VERSION"
    if version.is_file():
        files.append(version)
    return sorted(files)


def build_manifest(release_dir: str | Path) -> dict[str, Any]:
    release = Path(release_dir).resolve()
    version = (release / "VERSION").read_text(encoding="utf-8").strip()
    if not version:
        raise ValueError("Release VERSION is required.")
    missing = [path for path in ENTRYPOINTS.values() if not (release / path).is_file()]
    if missing:
        raise ValueError(f"Release entrypoints missing: {', '.join(missing)}")
    manifest = {
        "version": version,
        "entrypoints": ENTRYPOINTS,
        "files": {str(path.relative_to(release)): _sha256(path) for path in source_files(release)},
    }
    target = release / MANIFEST_NAME
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def manifest_digest(release_dir: str | Path) -> str:
    manifest = Path(release_dir).resolve() / MANIFEST_NAME
    if not manifest.is_file():
        raise ValueError("Release manifest is missing.")
    return _sha256(manifest)


def verify_manifest(release_dir: str | Path, expected_manifest_hash: str | None = None) -> list[str]:
    release = Path(release_dir).resolve()
    manifest_path = release / MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return [f"manifest unreadable: {type(error).__name__}"]
    problems: list[str] = []
    if expected_manifest_hash and manifest_digest(release) != expected_manifest_hash:
        problems.append("manifest hash mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict):
        return [*problems, "manifest files entry is invalid"]
    for relative_path, expected_hash in files.items():
        path = release / relative_path
        if not path.is_file():
            problems.append(f"missing: {relative_path}")
        elif _sha256(path) != expected_hash:
            problems.append(f"hash mismatch: {relative_path}")
    for name, relative_path in ENTRYPOINTS.items():
        if manifest.get("entrypoints", {}).get(name) != relative_path:
            problems.append(f"entrypoint mismatch: {name}")
    return problems
