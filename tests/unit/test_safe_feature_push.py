import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class FeaturePushTests(unittest.TestCase):
    def setUp(self):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        self.engine = SafeYoloEngine(policy, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
            "HOME": "/home/test",
        })

    def inspect_push(
        self,
        command: str,
        *,
        branch: str | None = "task/repair-0160-attestation",
    ):
        def git_result(git_command, **_kwargs):
            if git_command[1:] == ["branch", "--show-current"]:
                if branch is None:
                    return SimpleNamespace(returncode=128, stdout="")
                return SimpleNamespace(returncode=0, stdout=f"{branch}\n")
            raise AssertionError(git_command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            return self.engine.inspect_command(command, {"cwd": "/workspace"})

    def assert_push_allowed(self, command: str, **state):
        decision = self.inspect_push(command, **state)
        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual("git.push_feature", decision["policy_id"])

    def assert_push_gated(self, command: str, **state):
        decision = self.inspect_push(command, **state)
        self.assertNotIn(decision["decision"], {"allow", "allow_report"})

    def test_feature_branch_bare_push_is_allowed(self):
        self.assert_push_allowed("git push")

    def test_initial_feature_push_does_not_require_a_preexisting_upstream(self):
        self.assert_push_allowed("git push -u origin feat/consequence-kernel")

    def test_feature_branch_set_upstream_shapes_are_allowed(self):
        for command in (
            "git push -u origin task/repair-0160-attestation",
            "git push --set-upstream origin task/repair-0160-attestation",
            "git push -u origin HEAD",
            "git push origin task/repair-0160-attestation",
            "git push -u upstream task/repair-0160-attestation",
            "git push -u origin task/different",
        ):
            with self.subTest(command=command):
                self.assert_push_allowed(command)

    def test_dirty_tree_does_not_gate_feature_push(self):
        # Branch classification no longer inspects porcelain status.
        self.assert_push_allowed("git push -u origin task/repair-0160-attestation")

    def test_git_dash_c_overrides_context_working_directory(self):
        seen_cwds = []

        def git_result(git_command, **kwargs):
            seen_cwds.append(kwargs["cwd"])
            if git_command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout="task/proof\n")
            raise AssertionError(git_command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            decision = self.engine.inspect_command(
                "git -C /tmp/disposable-repository push -u origin task/proof",
                {"cwd": "/task/root"},
            )
        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual([str(Path("/tmp/disposable-repository").resolve(strict=False))], seen_cwds)

    def test_git_dash_c_missing_or_unknown_directory_fails_closed(self):
        missing = self.engine.inspect_command("git -C", {"cwd": ""})
        with patch(
            "engine.safe_yolo.subprocess.run",
            return_value=SimpleNamespace(returncode=128, stdout=""),
        ):
            unknown = self.engine.inspect_command(
                "git -C /definitely/missing/safe-yolo-proof push -u origin task/proof",
                {"cwd": "/task/root"},
            )
        self.assertNotIn(missing["decision"], {"allow", "allow_report"})
        self.assertNotIn(unknown["decision"], {"allow", "allow_report"})

    def test_protected_and_release_branches_remain_gated(self):
        for branch in ("main", "master", "production", "prod", "release/1.2.3"):
            with self.subTest(branch=branch):
                decision = self.inspect_push(f"git push -u origin {branch}", branch=branch)
                self.assertEqual("require_capability", decision["decision"])
                self.assertEqual("git.push_protected", decision["policy_id"])

    def test_unknown_branch_with_cwd_fails_closed(self):
        decision = self.inspect_push("git push", branch=None)
        self.assertEqual("require_capability", decision["decision"])
        self.assertEqual("git.push_protected", decision["policy_id"])

    def test_force_broad_delete_and_forced_refspec_remain_hard_blocked(self):
        for command in (
            "git push --force origin task/repair-0160-attestation",
            "git push --force-with-lease origin task/repair-0160-attestation",
            "git push --all origin",
            "git push --delete origin task/repair-0160-attestation",
            "git push origin +task/repair-0160-attestation",
        ):
            with self.subTest(command=command):
                decision = self.inspect_push(command)
                self.assertEqual("block_hard", decision["decision"])


if __name__ == "__main__":
    unittest.main()
