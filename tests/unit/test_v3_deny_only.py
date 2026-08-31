import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from adapters.codex_v3 import build_kernel, handle_pre_tool


ROOT = Path(__file__).resolve().parents[2]


class V3DenyOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.kernel = build_kernel(
            safe_yolo_home=root / "safe-yolo",
            codex_home=root / "codex",
            user_home=root / "home",
        )

    def tearDown(self):
        self.temp.cleanup()

    def payload(self, command: str) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "cwd": "/workspace",
            "tool_name": "exec_command",
            "tool_input": {"cmd": command},
        }

    def test_ordinary_work_and_guarded_shipping_default_to_allow(self):
        commands = (
            "git status --short",
            "git push -u origin fix/safe-yolo",
            "gh pr create --fill",
            "gh pr merge 232 --merge --delete-branch",
            "python3 -m unittest discover -s tests/unit",
        )

        for command in commands:
            with self.subTest(command=command):
                self.assertIsNone(handle_pre_tool(self.payload(command), self.kernel))

        unknown = {
            "hook_event_name": "PreToolUse",
            "cwd": "/workspace",
            "tool_name": "future_tool",
            "tool_input": {"action": "ordinary"},
        }
        self.assertIsNone(handle_pre_tool(unknown, self.kernel))

    def test_explicit_restrictions_are_stable_denials_without_approval(self):
        commands = {
            "rm obsolete.txt": "filesystem.delete",
            "git push --force-with-lease": "git.history_mutation",
            "gh pr merge 232 --merge --admin": "production.mutate",
            "railway up": "production.mutate",
            "ssh example.com": "remote.execute",
            "sudo apt update": "privilege.modify",
            "vite --host 0.0.0.0": "network.public_exposure",
        }

        for command, consequence in commands.items():
            with self.subTest(command=command):
                first = handle_pre_tool(self.payload(command), self.kernel)
                second = handle_pre_tool(self.payload(command), self.kernel)
                self.assertEqual(first, second)
                self.assertEqual(
                    "deny",
                    first["hookSpecificOutput"]["permissionDecision"],
                )
                reason = first["hookSpecificOutput"]["permissionDecisionReason"]
                self.assertIn(consequence, reason)
                self.assertIn("different safe method", reason)
                self.assertNotIn("request_user_input", reason)
                self.assertNotIn("approval", reason.lower())

    def test_request_user_input_is_not_part_of_the_runtime(self):
        payload = {
            "hook_event_name": "PostToolUse",
            "cwd": "/workspace",
            "tool_name": "request_user_input",
            "tool_input": {},
            "tool_response": {},
        }

        self.assertIsNone(handle_pre_tool(payload, self.kernel))

    def test_executable_hook_has_no_stateful_retry_path(self):
        command = [
            sys.executable,
            str(ROOT / "adapters" / "codex_v3.py"),
            "--state-dir",
            str(Path(self.temp.name) / "unused-state"),
            "--safe-yolo-home",
            str(Path(self.temp.name) / "safe-yolo"),
            "--codex-home",
            str(Path(self.temp.name) / "codex"),
            "--user-home",
            str(Path(self.temp.name) / "home"),
        ]
        action = self.payload("rm obsolete.txt")

        first = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(action),
            text=True,
            capture_output=True,
            check=False,
        )
        second = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(action),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        denial = json.loads(first.stdout)
        self.assertEqual(
            "deny",
            denial["hookSpecificOutput"]["permissionDecision"],
        )
        self.assertFalse((Path(self.temp.name) / "unused-state").exists())


if __name__ == "__main__":
    unittest.main()
