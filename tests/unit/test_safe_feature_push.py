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

    def inspect_push(
        self,
        command: str,
        *,
        branch: str = "task/repair-0160-attestation",
        upstream: str | None = None,
        status: str = "",
    ):
        def git_result(git_command, **_kwargs):
            if git_command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout=f"{branch}\n")
            if git_command[1:] == ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
                if upstream is None:
                    return SimpleNamespace(returncode=128, stdout="")
                return SimpleNamespace(returncode=0, stdout=f"{upstream}\n")
            if git_command[1:] == ["status", "--porcelain"]:
                return SimpleNamespace(returncode=0, stdout=status)
            raise AssertionError(git_command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            return self.engine.inspect_command(command, {"cwd": "/workspace"})

    def assert_push_allowed(self, command: str, **state):
        decision = self.inspect_push(command, **state)
        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual("git.push_feature", decision["policy_id"])

    def assert_push_blocked(self, command: str, **state):
        decision = self.inspect_push(command, **state)
        self.assertNotIn(decision["decision"], {"allow", "allow_report"})

    def test_initial_push_allows_exact_short_set_upstream_to_matching_branch(self):
        self.assert_push_allowed("git push -u origin task/repair-0160-attestation")

    def test_initial_push_allows_exact_long_set_upstream_to_matching_branch(self):
        self.assert_push_allowed("git push --set-upstream origin task/repair-0160-attestation")

    def test_initial_push_allows_head_as_matching_source(self):
        self.assert_push_allowed("git push -u origin HEAD")

    def test_git_dash_c_overrides_context_working_directory(self):
        seen_cwds = []

        def git_result(git_command, **kwargs):
            seen_cwds.append(kwargs["cwd"])
            if git_command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout="task/proof\n")
            if git_command[1:] == ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"]:
                return SimpleNamespace(returncode=128, stdout="")
            if git_command[1:] == ["status", "--porcelain"]:
                return SimpleNamespace(returncode=0, stdout="")
            raise AssertionError(git_command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            decision = self.engine.inspect_command(
                "git -C /tmp/disposable-repository push -u origin task/proof",
                {"cwd": "/task/root"},
            )
        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual(["/tmp/disposable-repository"] * 3, seen_cwds)

    def test_git_dash_c_missing_or_unknown_directory_fails_closed(self):
        missing = self.engine.inspect_command("git -C", {"cwd": ""})
        unknown = self.engine.inspect_command(
            "git -C /definitely/missing/safe-yolo-proof push -u origin task/proof",
            {"cwd": "/task/root"},
        )
        self.assertNotIn(missing["decision"], {"allow", "allow_report"})
        self.assertNotIn(unknown["decision"], {"allow", "allow_report"})

    def test_initial_push_rejects_missing_set_upstream(self):
        self.assert_push_blocked("git push origin task/repair-0160-attestation")

    def test_initial_push_rejects_mismatched_refspec(self):
        self.assert_push_blocked("git push -u origin task/different")

    def test_initial_push_rejects_arbitrary_remote(self):
        self.assert_push_blocked("git push -u upstream task/repair-0160-attestation")

    def test_initial_push_rejects_dirty_tree(self):
        self.assert_push_blocked(
            "git push -u origin task/repair-0160-attestation",
            status=" M app.ts\n",
        )

    def test_initial_push_rejects_protected_and_release_branches(self):
        for branch in ("main", "release/1.2.3"):
            with self.subTest(branch=branch):
                self.assert_push_blocked(f"git push -u origin {branch}", branch=branch)

    def test_existing_matching_upstream_still_allows_bare_push(self):
        self.assert_push_allowed(
            "git push",
            upstream="origin/task/repair-0160-attestation",
        )

    def test_force_broad_delete_and_forced_refspec_remain_hard_blocked(self):
        for command in (
            "git push --force origin task/repair-0160-attestation",
            "git push --all origin",
            "git push --delete origin task/repair-0160-attestation",
            "git push origin +task/repair-0160-attestation",
        ):
            with self.subTest(command=command):
                decision = self.inspect_push(command)
                self.assertEqual("block_hard", decision["decision"])


if __name__ == "__main__":
    unittest.main()
