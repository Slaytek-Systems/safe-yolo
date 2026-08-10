from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import shutil
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path


class Quarantine:
    def __init__(self, storage: str | Path, workspace: str | Path):
        self.storage = Path(storage).resolve(strict=False)
        self.workspace = Path(workspace).resolve(strict=True)
        self.objects = self.storage / "objects"
        self.manifest = self.storage / "manifest.jsonl"

    def put(self, target: str | Path) -> dict[str, str]:
        requested = Path(target).expanduser().absolute()
        source = requested.resolve(strict=True)
        if source == self.workspace or self.workspace not in source.parents:
            raise ValueError("Quarantine targets must be descendants of the active workspace.")

        identifier = uuid.uuid4().hex
        self.objects.mkdir(parents=True, exist_ok=True)
        destination = self.objects / identifier
        shutil.move(str(source), str(destination))
        if not destination.exists():
            raise RuntimeError("Quarantine move could not be verified.")

        record = {
            "id": identifier,
            "original_path": str(requested),
            "stored_path": str(destination),
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "status": "quarantined",
        }
        self._append(record)
        return record

    def restore(self, identifier: str) -> Path:
        record = self._latest(identifier)
        if record is None or record.get("status") != "quarantined":
            raise ValueError(f"No restorable quarantine object: {identifier}")

        stored = Path(record["stored_path"]).resolve(strict=True)
        original = Path(record["original_path"]).expanduser().absolute()
        resolved_original = original.resolve(strict=False)
        if original.exists():
            raise FileExistsError(f"Restore destination already exists: {original}")
        if resolved_original == self.workspace or self.workspace not in resolved_original.parents:
            raise ValueError("Restore destination is outside the active workspace.")

        original.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stored), str(original))
        if not original.exists():
            raise RuntimeError("Quarantine restore could not be verified.")
        self._append(
            {
                **record,
                "restored_at": datetime.now(timezone.utc).isoformat(),
                "status": "restored",
            }
        )
        return original

    def _append(self, record: dict[str, str]) -> None:
        self.storage.mkdir(parents=True, exist_ok=True)
        with self.manifest.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")

    def _latest(self, identifier: str) -> dict[str, str] | None:
        if not self.manifest.exists():
            return None
        latest = None
        for line in self.manifest.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record.get("id") == identifier:
                latest = record
        return latest

    def records(self) -> list[dict[str, str]]:
        if not self.manifest.exists():
            return []
        return [json.loads(line) for line in self.manifest.read_text(encoding="utf-8").splitlines() if line]


def workspace_root(cwd: str | Path | None = None) -> Path:
    working = Path(cwd or Path.cwd()).resolve(strict=True)
    completed = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=working,
        text=True,
        capture_output=True,
        check=False,
        timeout=2,
    )
    if completed.returncode == 0 and completed.stdout.strip():
        return Path(completed.stdout.strip()).resolve(strict=True)
    return working


def quarantine_storage(workspace: Path) -> Path:
    state = Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser()
    identity = hashlib.sha256(str(workspace).encode("utf-8")).hexdigest()[:16]
    return state / "quarantine" / identity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Recoverable Safe YOLO workspace quarantine.")
    subparsers = parser.add_subparsers(dest="operation", required=True)
    put = subparsers.add_parser("put")
    put.add_argument("target")
    restore = subparsers.add_parser("restore")
    restore.add_argument("identifier")
    subparsers.add_parser("list")
    args = parser.parse_args(argv)

    workspace = workspace_root()
    quarantine = Quarantine(quarantine_storage(workspace), workspace)
    if args.operation == "put":
        response: object = quarantine.put(args.target)
    elif args.operation == "restore":
        response = {"restored_path": str(quarantine.restore(args.identifier))}
    else:
        response = quarantine.records()
    json.dump(response, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
