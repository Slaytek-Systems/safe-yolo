from __future__ import annotations

import json
import shutil
import uuid
from datetime import UTC, datetime
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
            "quarantined_at": datetime.now(UTC).isoformat(),
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
                "restored_at": datetime.now(UTC).isoformat(),
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
