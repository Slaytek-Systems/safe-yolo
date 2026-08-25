from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ENTRYPOINTS = {
    "codex": "adapters/codex.py",
    "prompt": "adapters/codex_prompt.py",
    "cursor": "adapters/cursor.py",
    "cursor_prompt": "adapters/cursor_prompt.py",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified_entry(release_dir: str | Path, entry: str, *, expected_manifest_hash: str) -> Path:
    if entry not in ENTRYPOINTS:
        raise ValueError(f"Unknown Safe YOLO entrypoint: {entry}")
    if not expected_manifest_hash:
        raise ValueError("A trusted manifest hash is required.")
    release = Path(release_dir).resolve()
    manifest_path = release / "manifest.json"
    if not manifest_path.is_file() or _sha256(manifest_path) != expected_manifest_hash:
        raise ValueError("manifest hash mismatch")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"manifest unreadable: {type(error).__name__}") from error
    if manifest.get("entrypoints", {}).get(entry) != ENTRYPOINTS[entry]:
        raise ValueError(f"entrypoint mismatch: {entry}")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("manifest files entry is invalid")
    for relative_path, expected_hash in files.items():
        path = release / relative_path
        if not path.is_file() or _sha256(path) != expected_hash:
            raise ValueError(f"release verification failed: {relative_path}")
    return release / ENTRYPOINTS[entry]


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Safe YOLO release before dispatching a Codex hook.")
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--entry", choices=sorted(ENTRYPOINTS), required=True)
    parser.add_argument("--host-contract", type=Path)
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser())
    args = parser.parse_args()
    try:
        entry = verified_entry(args.release, args.entry, expected_manifest_hash=args.manifest_sha256)
    except ValueError as error:
        print(f"Safe YOLO fail-closed: {error}", file=sys.stderr)
        return 2
    command = [sys.executable, str(entry), "--state-dir", str(args.state_dir)]
    if args.host_contract is not None:
        command.extend(["--host-contract", str(args.host_contract)])
    if args.audit_only:
        command.append("--audit-only")
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(args.release) if not existing_pythonpath else f"{args.release}{os.pathsep}{existing_pythonpath}"
    return subprocess.run(command, check=False, env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(main())
