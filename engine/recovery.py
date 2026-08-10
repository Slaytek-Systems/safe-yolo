from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import uuid
import sys
from typing import Iterable


class RecoveryUnavailable(RuntimeError):
    pass


class FileCheckpointStore:
    """Append-only, bounded snapshots for exact structured-write targets."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_file_bytes: int = 32 * 1024 * 1024,
        max_total_bytes: int = 1024 * 1024 * 1024,
    ):
        self.root = Path(root).expanduser().resolve(strict=False)
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes

    def checkpoint(
        self,
        paths: Iterable[str],
        *,
        cwd: str | Path,
        session_id: str = "",
        turn_id: str = "",
    ) -> dict[str, object]:
        working = Path(cwd).expanduser().resolve(strict=True)
        resolved = sorted({self._resolve(path, working) for path in paths}, key=str)
        if not resolved:
            raise RecoveryUnavailable("Structured write has no exact recovery targets.")
        incoming_bytes = 0
        for target in resolved:
            if target.is_file() and not target.is_symlink():
                size = target.stat().st_size
                if size > self.max_file_bytes:
                    raise RecoveryUnavailable(f"Recovery target exceeds {self.max_file_bytes} bytes: {target}")
                incoming_bytes += size
            elif target.exists() and not target.is_symlink():
                raise RecoveryUnavailable(f"Directory or special-file writes require a workspace checkpoint: {target}")
        if self._stored_bytes() + incoming_bytes > self.max_total_bytes:
            raise RecoveryUnavailable("Recovery store capacity reached; archive checkpoints before further writes.")

        identifier = uuid.uuid4().hex
        checkpoint = self.root / "checkpoints" / identifier
        objects = checkpoint / "objects"
        objects.mkdir(parents=True, mode=0o700)
        os.chmod(self.root, 0o700)
        os.chmod(self.root / "checkpoints", 0o700)
        os.chmod(checkpoint, 0o700)

        records: list[dict[str, object]] = []
        try:
            for index, target in enumerate(resolved):
                record: dict[str, object] = {"path": str(target), "existed": target.exists() or target.is_symlink()}
                if not record["existed"]:
                    records.append(record)
                    continue
                if target.is_symlink():
                    record.update({"kind": "symlink", "link_target": os.readlink(target)})
                elif target.is_file():
                    size = target.stat().st_size
                    stored = objects / str(index)
                    shutil.copy2(target, stored)
                    record.update({
                        "kind": "file",
                        "size": size,
                        "sha256": self._sha256(stored),
                        "stored": str(stored.relative_to(checkpoint)),
                    })
                records.append(record)
        except Exception:
            shutil.rmtree(checkpoint, ignore_errors=True)
            raise

        manifest = {
            "id": identifier,
            "created_at": time.time(),
            "cwd": str(working),
            "session_id": session_id,
            "turn_id": turn_id,
            "targets": records,
        }
        manifest_path = checkpoint / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.chmod(manifest_path, 0o600)
        return manifest

    def materialize(self, identifier: str, destination: str | Path) -> Path:
        checkpoint = self.root / "checkpoints" / identifier
        manifest = json.loads((checkpoint / "manifest.json").read_text(encoding="utf-8"))
        output = Path(destination).expanduser().resolve(strict=False)
        if output.exists():
            raise FileExistsError(f"Recovery materialization destination exists: {output}")
        output.mkdir(parents=True, mode=0o700)
        for index, record in enumerate(manifest["targets"]):
            target = output / str(index)
            target.mkdir(mode=0o700)
            (target / "metadata.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if record.get("kind") == "file":
                stored = checkpoint / str(record["stored"])
                if self._sha256(stored) != record["sha256"]:
                    raise RecoveryUnavailable(f"Checkpoint object failed verification: {identifier}/{index}")
                shutil.copy2(stored, target / "content")
            elif record.get("kind") == "symlink":
                (target / "link_target").write_text(str(record["link_target"]), encoding="utf-8")
        return output

    def list_checkpoints(self) -> list[dict[str, object]]:
        manifests = self.root / "checkpoints"
        if not manifests.exists():
            return []
        records: list[dict[str, object]] = []
        for manifest in sorted(manifests.glob("*/manifest.json")):
            try:
                record = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            records.append({
                "id": record.get("id"),
                "created_at": record.get("created_at"),
                "session_id": record.get("session_id"),
                "turn_id": record.get("turn_id"),
                "target_count": len(record.get("targets") or []),
            })
        return records

    def _stored_bytes(self) -> int:
        if not self.root.exists():
            return 0
        return sum(path.stat().st_size for path in self.root.rglob("*") if path.is_file())

    @staticmethod
    def _resolve(raw_path: str, cwd: Path) -> Path:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        return candidate.resolve(strict=False)

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect or materialize Safe YOLO recovery checkpoints.")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("list")
    materialize = subparsers.add_parser("materialize")
    materialize.add_argument("identifier")
    materialize.add_argument("destination")
    args = parser.parse_args(argv)
    state = Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser()
    store = FileCheckpointStore(state / "recovery")
    if args.operation == "list":
        response: object = store.list_checkpoints()
    else:
        response = {"materialized_path": str(store.materialize(args.identifier, args.destination))}
    json.dump(response, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
