import json
from pathlib import Path
import tempfile
import unittest

from adapters.codex import process_payload
from adapters.cursor import process_cursor_payload
from engine.recovery import FileCheckpointStore, RecoveryUnavailable
from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[2]


class RecoveryTests(unittest.TestCase):
    def test_checkpoint_materializes_verified_original_without_overwriting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            target = workspace / "valuable.txt"
            target.write_text("before\n", encoding="utf-8")
            store = FileCheckpointStore(root / "state")

            checkpoint = store.checkpoint(["valuable.txt", "new.txt"], cwd=workspace)
            target.write_text("after\n", encoding="utf-8")
            materialized = store.materialize(str(checkpoint["id"]), root / "recovered")

            recovered = [
                child
                for child in materialized.iterdir()
                if json.loads((child / "metadata.json").read_text(encoding="utf-8"))["path"] == str(target.resolve())
            ][0]
            self.assertEqual("before\n", (recovered / "content").read_text(encoding="utf-8"))
            absent = [
                json.loads((child / "metadata.json").read_text(encoding="utf-8"))
                for child in materialized.iterdir()
                if json.loads((child / "metadata.json").read_text(encoding="utf-8"))["path"].endswith("new.txt")
            ][0]
            self.assertFalse(absent["existed"])
            self.assertEqual("after\n", target.read_text(encoding="utf-8"))

    def test_structured_write_is_checkpointed_before_allow(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            target = workspace / "valuable.txt"
            target.write_text("before\n", encoding="utf-8")
            policy = json.loads((ROOT / "policy" / "policy.json").read_text())
            engine = SafeYoloEngine(policy, path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            })
            store = FileCheckpointStore(root / "state")
            payload = {
                "session_id": "session",
                "turn_id": "turn",
                "cwd": str(workspace),
                "tool_name": "apply_patch",
                "tool_input": {"patch": "*** Begin Patch\n*** Update File: valuable.txt\n@@\n-before\n+after\n*** End Patch"},
            }

            response = process_payload(payload, engine, recovery_store=store)
            self.assertIsNone(response)
            manifests = list((root / "state" / "checkpoints").glob("*/manifest.json"))
            self.assertEqual(1, len(manifests))
            manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
            self.assertEqual("session", manifest["session_id"])
            self.assertEqual("turn", manifest["turn_id"])
            self.assertEqual(str(target.resolve()), manifest["targets"][0]["path"])

    def test_checkpoint_failure_blocks_the_write_without_exposing_paths(self):
        class FailingStore:
            def checkpoint(self, *_args, **_kwargs):
                raise RecoveryUnavailable("sensitive path detail")

        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            policy = json.loads((ROOT / "policy" / "policy.json").read_text())
            engine = SafeYoloEngine(policy, path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            })
            response = process_payload(
                {
                    "session_id": "session",
                    "cwd": str(workspace),
                    "tool_name": "write",
                    "tool_input": {"path": "valuable.txt", "content": "after"},
                },
                engine,
                recovery_store=FailingStore(),
            )
            self.assertEqual("block", response["decision"])
            self.assertIn("recovery.unavailable", response["reason"])
            self.assertNotIn("sensitive path detail", response["reason"])

    def test_cursor_structured_write_uses_the_same_checkpoint_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            target = workspace / "valuable.txt"
            target.write_text("before\n", encoding="utf-8")
            policy = json.loads((ROOT / "policy" / "policy.json").read_text())
            engine = SafeYoloEngine(policy, path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            })
            response = process_cursor_payload(
                {
                    "conversation_id": "conversation",
                    "generation_id": "generation",
                    "tool_name": "StrReplace",
                    "tool_input": {"path": "valuable.txt", "working_directory": str(workspace)},
                },
                engine,
                recovery_store=FileCheckpointStore(root / "state"),
            )
            self.assertEqual("allow", response["permission"])
            self.assertEqual(1, len(list((root / "state" / "checkpoints").glob("*/manifest.json"))))

    def test_store_capacity_fails_closed_before_copying(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            target = workspace / "large.txt"
            target.write_text("12345", encoding="utf-8")
            store = FileCheckpointStore(root / "state", max_total_bytes=4)
            with self.assertRaises(RecoveryUnavailable):
                store.checkpoint(["large.txt"], cwd=workspace)
            self.assertFalse((root / "state" / "checkpoints").exists())


if __name__ == "__main__":
    unittest.main()
