from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
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
            if target.is_symlink():
                raise RecoveryUnavailable(f"Structured writes through symlinks require an explicit contract: {target}")
            if target.is_file():
                size = target.stat().st_size
                if size > self.max_file_bytes:
                    raise RecoveryUnavailable(f"Recovery target exceeds {self.max_file_bytes} bytes: {target}")
                incoming_bytes += size
            elif target.exists() and not target.is_symlink():
                raise RecoveryUnavailable(f"Directory or special-file writes require a workspace checkpoint: {target}")
        if self._stored_bytes() + incoming_bytes > self.max_total_bytes:
            raise RecoveryUnavailable("Recovery store capacity reached; archive checkpoints before further writes.")

        self._secure_store_root()
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

    def checkpoint_workspace(
        self,
        *,
        cwd: str | Path,
        session_id: str = "",
        turn_id: str = "",
    ) -> dict[str, object]:
        working = Path(cwd).expanduser().resolve(strict=True)
        root_result = self._git(["rev-parse", "--show-toplevel"], working)
        if root_result.returncode != 0 or not root_result.stdout.strip():
            raise RecoveryUnavailable("Shell mutation requires a Git workspace recovery boundary.")
        workspace = Path(root_result.stdout.decode("utf-8").strip()).resolve(strict=True)
        scope = f"{session_id}\0{turn_id}\0{workspace}" if session_id or turn_id else f"{uuid.uuid4().hex}\0{workspace}"
        identifier = hashlib.sha256(scope.encode("utf-8")).hexdigest()
        checkpoint = self.root / "workspace-checkpoints" / identifier
        manifest_path = checkpoint / "manifest.json"
        if manifest_path.is_file():
            return json.loads(manifest_path.read_text(encoding="utf-8"))

        head = self._git(["rev-parse", "HEAD"], workspace)
        if head.returncode != 0 or not head.stdout.strip():
            raise RecoveryUnavailable("Workspace must have a committed HEAD before shell execution.")
        diff = self._git(["diff", "--binary", "HEAD", "--"], workspace)
        if diff.returncode != 0:
            raise RecoveryUnavailable("Tracked workspace state could not be checkpointed.")
        untracked_result = self._git(["ls-files", "--others", "--exclude-standard", "-z"], workspace)
        if untracked_result.returncode != 0:
            raise RecoveryUnavailable("Untracked workspace state could not be enumerated.")

        sources: list[tuple[Path, str]] = []
        incoming_bytes = len(diff.stdout)
        for raw in (item for item in untracked_result.stdout.split(b"\0") if item):
            relative = raw.decode("utf-8", errors="strict")
            relative_path = Path(relative)
            if relative_path.is_absolute() or ".." in relative_path.parts:
                raise RecoveryUnavailable("Untracked recovery target escaped the workspace.")
            source = workspace / relative_path
            if source.is_symlink():
                resolved_target = source.resolve(strict=False)
                if resolved_target != workspace and workspace not in resolved_target.parents:
                    raise RecoveryUnavailable("Untracked symlink target escaped the workspace.")
                incoming_bytes += len(os.readlink(source).encode("utf-8"))
            elif source.is_file():
                size = source.stat().st_size
                if size > self.max_file_bytes:
                    raise RecoveryUnavailable(f"Untracked recovery target exceeds {self.max_file_bytes} bytes: {source}")
                incoming_bytes += size
            else:
                raise RecoveryUnavailable(f"Untracked directory or special file requires an explicit contract: {source}")
            sources.append((source, relative))
        if self._stored_bytes() + incoming_bytes > self.max_total_bytes:
            raise RecoveryUnavailable("Recovery store capacity reached; archive checkpoints before further shell use.")

        temporary = checkpoint.with_name(f".{identifier}.{uuid.uuid4().hex}")
        self._secure_store_root()
        objects = temporary / "untracked"
        objects.mkdir(parents=True, mode=0o700)
        tracked_patch = temporary / "tracked.patch"
        tracked_patch.write_bytes(diff.stdout)
        os.chmod(tracked_patch, 0o600)
        records: list[dict[str, object]] = []
        try:
            for index, (source, relative) in enumerate(sources):
                record: dict[str, object] = {"path": relative}
                if source.is_symlink():
                    record.update({"kind": "symlink", "link_target": os.readlink(source)})
                else:
                    stored = objects / str(index)
                    shutil.copy2(source, stored)
                    record.update({"kind": "file", "size": stored.stat().st_size, "sha256": self._sha256(stored), "stored": str(stored.relative_to(temporary))})
                records.append(record)
            manifest = {
                "id": identifier,
                "kind": "workspace",
                "created_at": time.time(),
                "cwd": str(working),
                "workspace": str(workspace),
                "head": head.stdout.decode("utf-8").strip(),
                "session_id": session_id,
                "turn_id": turn_id,
                "tracked_patch_sha256": self._sha256(temporary / "tracked.patch"),
                "untracked": records,
            }
            temporary_manifest = temporary / "manifest.json"
            temporary_manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(temporary_manifest, 0o600)
            (self.root / "workspace-checkpoints").mkdir(parents=True, mode=0o700, exist_ok=True)
            os.chmod(self.root / "workspace-checkpoints", 0o700)
            os.chmod(temporary, 0o700)
            try:
                os.replace(temporary, checkpoint)
            except OSError:
                if not manifest_path.is_file():
                    raise
                shutil.rmtree(temporary, ignore_errors=True)
                return json.loads(manifest_path.read_text(encoding="utf-8"))
            return manifest
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise

    def materialize(self, identifier: str, destination: str | Path) -> Path:
        checkpoint = self.root / "checkpoints" / identifier
        if not checkpoint.is_dir():
            checkpoint = self.root / "workspace-checkpoints" / identifier
        manifest = json.loads((checkpoint / "manifest.json").read_text(encoding="utf-8"))
        output = Path(destination).expanduser().resolve(strict=False)
        if output.exists():
            raise FileExistsError(f"Recovery materialization destination exists: {output}")
        output.mkdir(parents=True, mode=0o700)
        if manifest.get("kind") == "workspace":
            patch = checkpoint / "tracked.patch"
            if self._sha256(patch) != manifest["tracked_patch_sha256"]:
                raise RecoveryUnavailable(f"Workspace patch failed verification: {identifier}")
            shutil.copy2(patch, output / "tracked.patch")
            records = manifest.get("untracked") or []
        else:
            records = manifest["targets"]
        for index, record in enumerate(records):
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
        records: list[dict[str, object]] = []
        manifests = [
            *(self.root / "checkpoints").glob("*/manifest.json"),
            *(self.root / "workspace-checkpoints").glob("*/manifest.json"),
        ]
        for manifest in sorted(manifests):
            try:
                record = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            records.append({
                "id": record.get("id"),
                "created_at": record.get("created_at"),
                "session_id": record.get("session_id"),
                "turn_id": record.get("turn_id"),
                "kind": record.get("kind", "paths"),
                "target_count": len(record.get("targets") or record.get("untracked") or []),
            })
        return records

    def _stored_bytes(self) -> int:
        if not self.root.exists():
            return 0
        return sum(path.stat().st_size for path in self.root.rglob("*") if path.is_file())

    def _secure_store_root(self) -> None:
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(self.root, 0o700)

    @staticmethod
    def _git(args: list[str], cwd: Path) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RecoveryUnavailable(f"Git recovery probe failed ({type(error).__name__}).") from error

    @staticmethod
    def _resolve(raw_path: str, cwd: Path) -> Path:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = cwd / candidate
        return Path(os.path.abspath(candidate))

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
