import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[2]


class GraphiteCommandTests(unittest.TestCase):
    def setUp(self):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        self.engine = SafeYoloEngine(
            policy,
            path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
                "HOME": "/home/test",
            },
        )

    def inspect(self, command: str, *, branch: str = "task/graphite-proof"):
        def git_result(git_command, **_kwargs):
            if git_command[1:] == ["rev-parse", "--show-toplevel"]:
                return SimpleNamespace(returncode=0, stdout="/workspace\n")
            if git_command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout=f"{branch}\n")
            raise AssertionError(git_command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            return self.engine.inspect_command(command, {"cwd": "/workspace"})

    def test_reviewed_stack_commands_are_allowed_and_reported(self):
        for command in (
            "gt submit",
            "gt submit --stack",
            "gt ss",
            "gt restack",
            "gt modify --message follow-up",
            "gt sync",
        ):
            with self.subTest(command=command):
                decision = self.inspect(command)
                self.assertEqual("allow_report", decision["decision"])
                self.assertEqual("git.graphite_stack", decision["policy_id"])

    def test_graphite_submit_bypass_flags_remain_hard_blocked(self):
        for command in (
            "gt submit --force",
            "gt submit --force=true",
            "gt submit -f",
            "gt submit -df",
            "gt submit --no-verify",
            "gt submit --no-verify=true",
            "gt submit --verify=false",
            "gt submit --ignore-out-of-sync-trunk",
            "gt submit --ignore-out-of-sync-trunk=true",
            "gt ss --force",
        ):
            with self.subTest(command=command):
                self.assertEqual("block_hard", self.inspect(command)["decision"])

    def test_graphite_sync_destructive_flags_remain_hard_blocked(self):
        for command in (
            "gt sync --force",
            "gt sync -f",
            "gt sync -af",
            "gt sync --delete-all",
            "gt sync --delete-all=true",
            "gt sync -d",
            "gt sync --no-verify",
        ):
            with self.subTest(command=command):
                self.assertEqual("block_hard", self.inspect(command)["decision"])

    def test_merge_when_ready_remains_separately_gated(self):
        for command in ("gt submit --merge-when-ready", "gt submit --merge-when-ready=true", "gt submit -m", "gt submit -dm"):
            with self.subTest(command=command):
                decision = self.inspect(command)
                self.assertEqual("require_capability", decision["decision"])
                self.assertEqual("github.pr_merge", decision["policy_id"])

    def test_protected_branch_stack_mutation_remains_gated(self):
        decision = self.inspect("gt submit", branch="main")
        self.assertEqual("require_capability", decision["decision"])
        self.assertEqual("git.push_protected", decision["policy_id"])

    def test_missing_repository_context_fails_closed(self):
        with patch(
            "engine.safe_yolo.subprocess.run",
            return_value=SimpleNamespace(returncode=128, stdout=""),
        ):
            decision = self.engine.inspect_command("gt submit", {"cwd": "/not-a-repository"})
        self.assertEqual("block_method", decision["decision"])
        self.assertEqual("graphite.context_missing", decision["policy_id"])

    def test_raw_git_force_push_is_still_hard_blocked(self):
        for command in (
            "git push --force-with-lease origin task/graphite-proof",
            "git push --force-with-lease=refs/heads/task/graphite-proof origin task/graphite-proof",
        ):
            with self.subTest(command=command):
                decision = self.inspect(command)
                self.assertEqual("block_hard", decision["decision"])
                self.assertEqual("git.force_push", decision["policy_id"])


if __name__ == "__main__":
    unittest.main()
