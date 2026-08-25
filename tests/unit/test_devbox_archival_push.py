import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[2]
DEVBOX_OPS = "/home/dev/devbox-ops"


class DevboxArchivalPushTests(unittest.TestCase):
    def setUp(self):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        self.engine = SafeYoloEngine(
            policy,
            host_contract={
                "version": "1",
                "git_protected_push_exceptions": [
                    {
                        "repository": DEVBOX_OPS,
                        "remote": "origin",
                        "branch": "main",
                        "policy_id": "git.devbox_ops_archival_push",
                        "reason": "Devbox Ops origin/main is backup persistence, not a deployment lane.",
                    }
                ],
            },
            path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
                "HOME": "/home/test",
            },
        )

    def inspect(
        self,
        command: str,
        *,
        cwd: str = DEVBOX_OPS,
        repository: str = DEVBOX_OPS,
        branch: str = "main",
    ):
        def git_result(git_command, **_kwargs):
            if git_command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout=f"{branch}\n")
            if git_command[1:] == ["rev-parse", "--show-toplevel"]:
                return SimpleNamespace(returncode=0, stdout=f"{repository}\n")
            raise AssertionError(git_command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            return self.engine.inspect_command(command, {"cwd": cwd})

    def assert_blocked(self, command: str, **state):
        decision = self.inspect(command, **state)
        self.assertNotIn(decision["decision"], {"allow", "allow_report"}, decision)

    def test_exact_current_main_to_origin_main_is_allowed_and_reported(self):
        decision = self.inspect("git push origin main")

        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual("git.devbox_ops_archival_push", decision["policy_id"])

    def test_repository_remote_source_and_destination_must_all_match(self):
        cases = (
            ("git push origin main", {"repository": "/home/dev/other"}),
            ("git push upstream main", {}),
            ("git push origin main", {"branch": "task/not-main"}),
            ("git push origin task/not-main", {}),
            ("git push origin main:backup", {}),
            ("git push origin HEAD:main", {}),
            ("git push", {}),
        )
        for command, state in cases:
            with self.subTest(command=command, state=state):
                self.assert_blocked(command, **state)

    def test_force_delete_tag_broad_and_multi_ref_shapes_remain_blocked(self):
        cases = (
            "git push --force origin main",
            "git push --force-with-lease origin main",
            "git push origin +main",
            "git push --delete origin main",
            "git push origin :main",
            "git push --all origin",
            "git push --mirror origin",
            "git push --tags origin",
            "git push origin v1.2.3",
            "git push origin main task/other",
        )
        for command in cases:
            with self.subTest(command=command):
                self.assert_blocked(command)

    def test_other_protected_branches_remain_gated(self):
        for branch in ("master", "production", "prod", "release/1.2.3"):
            with self.subTest(branch=branch):
                decision = self.inspect(f"git push origin {branch}", branch=branch)
                self.assertEqual("require_capability", decision["decision"])
                self.assertEqual("git.push_protected", decision["policy_id"])


if __name__ == "__main__":
    unittest.main()
