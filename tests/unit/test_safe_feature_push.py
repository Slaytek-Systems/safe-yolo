import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class SafeFeaturePushTests(unittest.TestCase):
    def setUp(self):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        self.engine = SafeYoloEngine(policy, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
        })

    def test_clean_feature_branch_with_matching_origin_upstream_is_reportable(self):
        def git_result(command, **_kwargs):
            if command[1:] == ["config", "--get", "alias.push"]:
                return SimpleNamespace(returncode=1, stdout="")
            if command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout="task/fix-sandbox-sql-bootstrap\n")
            if command[1:] == ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
                return SimpleNamespace(returncode=0, stdout="origin/task/fix-sandbox-sql-bootstrap\n")
            if command[1:] == ["status", "--porcelain"]:
                return SimpleNamespace(returncode=0, stdout="")
            raise AssertionError(command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            decision = self.engine.inspect_command("git push", {"cwd": "/workspace"})
        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual("git.push_feature", decision["policy_id"])


if __name__ == "__main__":
    unittest.main()
