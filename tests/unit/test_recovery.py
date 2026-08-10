import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from adapters.codex import process_payload
from adapters.cursor import process_cursor_payload
from engine.recovery import FileCheckpointStore, RecoveryUnavailable
from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[2]


class RecoveryTests(unittest.TestCase):
    @staticmethod
    def make_repo(root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Safe YOLO Test"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "safe-yolo@example.invalid"], cwd=repo, check=True)
        (repo / "tracked.txt").write_text("committed\n", encoding="utf-8")
        subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "initial"], cwd=repo, check=True)
        return repo

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
            self.assertEqual(str(workspace.resolve() / target.name), manifest["targets"][0]["path"])

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

    def test_structured_symlink_write_and_external_workspace_symlink_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside.txt"
            outside.write_text("outside\n", encoding="utf-8")
            link = workspace / "link.txt"
            link.symlink_to(outside)
            store = FileCheckpointStore(root / "state")
            with self.assertRaises(RecoveryUnavailable):
                store.checkpoint(["link.txt"], cwd=workspace)

            repo = self.make_repo(root)
            (repo / "escape-link").symlink_to(outside)
            with self.assertRaises(RecoveryUnavailable):
                store.checkpoint_workspace(cwd=repo, session_id="session", turn_id="turn")

    def test_workspace_checkpoint_preserves_dirty_tracked_and_untracked_state(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            (repo / "tracked.txt").write_text("user change\n", encoding="utf-8")
            (repo / "untracked.txt").write_text("untracked value\n", encoding="utf-8")
            store = FileCheckpointStore(root / "state")

            checkpoint = store.checkpoint_workspace(cwd=repo, session_id="session", turn_id="turn")
            self.assertEqual(0o700, (root / "state").stat().st_mode & 0o777)
            checkpoint_root = root / "state" / "workspace-checkpoints" / str(checkpoint["id"])
            self.assertEqual(0o600, (checkpoint_root / "manifest.json").stat().st_mode & 0o777)
            self.assertEqual(0o600, (checkpoint_root / "tracked.patch").stat().st_mode & 0o777)
            (repo / "tracked.txt").write_text("agent accident\n", encoding="utf-8")
            (repo / "untracked.txt").write_text("overwritten\n", encoding="utf-8")
            materialized = store.materialize(str(checkpoint["id"]), root / "recovered")

            patch = (materialized / "tracked.patch").read_text(encoding="utf-8")
            self.assertIn("+user change", patch)
            recovered_untracked = [
                child
                for child in materialized.iterdir()
                if child.is_dir() and json.loads((child / "metadata.json").read_text(encoding="utf-8"))["path"] == "untracked.txt"
            ][0]
            self.assertEqual("untracked value\n", (recovered_untracked / "content").read_text(encoding="utf-8"))

    def test_shell_checkpoint_is_once_per_turn_and_non_git_shell_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = self.make_repo(root)
            state = root / "state"
            store = FileCheckpointStore(state)
            policy = json.loads((ROOT / "policy" / "policy.json").read_text())
            engine = SafeYoloEngine(policy, path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            })
            payload = {
                "session_id": "session",
                "turn_id": "turn",
                "cwd": str(repo),
                "tool_name": "shell",
                "tool_input": {"command": "git add tracked.txt"},
            }
            self.assertIsNone(process_payload(payload, engine, recovery_store=store))
            self.assertIsNone(process_payload(payload, engine, recovery_store=store))
            self.assertEqual(1, len(list((state / "workspace-checkpoints").glob("*/manifest.json"))))

            payload["cwd"] = str(root / "outside")
            (root / "outside").mkdir()
            payload["turn_id"] = "other"
            response = process_payload(payload, engine, recovery_store=store)
            self.assertEqual("block", response["decision"])
            self.assertIn("recovery.unavailable", response["reason"])

    def test_read_only_shell_diagnostics_do_not_require_a_git_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            policy = json.loads((ROOT / "policy" / "policy.json").read_text())
            engine = SafeYoloEngine(policy, path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            })
            store = FileCheckpointStore(root / "state")
            for command in ("pwd", "ls", "rg needle .", "find . -name '*.txt'", "date +%s"):
                with self.subTest(command=command):
                    response = process_payload(
                        {"cwd": str(root), "tool_name": "shell", "tool_input": {"command": command}},
                        engine,
                        recovery_store=store,
                    )
                    self.assertIsNone(response)
            self.assertFalse((root / "state").exists())

            for command in ("git status --short > status.txt", "sed -n 1,5p example.txt > excerpt.txt"):
                with self.subTest(command=command):
                    response = process_payload(
                        {"cwd": str(root), "tool_name": "shell", "tool_input": {"command": command}},
                        engine,
                        recovery_store=store,
                    )
                    self.assertEqual("block", response["decision"])
                    self.assertIn("recovery.unavailable", response["reason"])

            exploit_shapes = (
                "rg --pre 'touch escaped.txt' needle .",
                "sed -n -e 'w escaped.txt' example.txt",
                "find . -fprint escaped.txt",
                "git branch -m escaped",
                "git diff --output=escaped.txt",
            )
            for command in exploit_shapes:
                with self.subTest(command=command):
                    response = process_payload(
                        {"cwd": str(root), "tool_name": "shell", "tool_input": {"command": command}},
                        engine,
                        recovery_store=store,
                    )
                    self.assertEqual("block", response["decision"])
                    self.assertIn("recovery.unavailable", response["reason"])


if __name__ == "__main__":
    unittest.main()
