import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from adapters.codex_v2 import approval_request_from_denial
from scripts.install import install_release


ROOT = Path(__file__).resolve().parents[2]


class V2HookRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name) / "state"
        self.direct_command = [
            sys.executable,
            str(ROOT / "adapters" / "codex_v2.py"),
            "--state-dir",
            str(self.state),
            "--safe-yolo-home",
            str(Path(self.temp.name) / "safe-yolo"),
            "--codex-home",
            str(Path(self.temp.name) / "codex"),
        ]

    def tearDown(self):
        self.temp.cleanup()

    def test_block_ask_approve_retry_through_executable_hook(self):
        self._assert_block_ask_approve_retry(self.direct_command)

    def test_block_ask_approve_retry_through_verified_installed_release(self):
        installed = install_release(ROOT, Path(self.temp.name) / "installed")
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "codex_v2",
            "--state-dir",
            str(Path(self.temp.name) / "installed-state"),
        ]
        self._assert_block_ask_approve_retry(command)

    def test_executable_hook_denies_operator_only_paths_from_move_and_workdir(self):
        codex_home = Path(self.temp.name) / "codex"
        cases = (
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/workspace",
                "tool_name": "exec_command",
                "tool_input": {
                    "cmd": "cat auth.json",
                    "workdir": str(codex_home),
                },
            },
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/workspace",
                "tool_name": "apply_patch",
                "tool_input": {
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Update File: /workspace/source.txt\n"
                        f"*** Move to: {codex_home / 'hooks.json'}\n"
                        "@@\n"
                        "-before\n"
                        "+after\n"
                        "*** End Patch"
                    )
                },
            },
        )
        for payload in cases:
            with self.subTest(payload=payload):
                result = self._run(self.direct_command, payload)
                self.assertEqual(0, result.returncode, result.stderr)
                denial = json.loads(result.stdout)
                reason = denial["hookSpecificOutput"]["permissionDecisionReason"]
                self.assertIn("operator-only", reason)
                self.assertNotIn("SAFE_YOLO_REQUEST_USER_INPUT=", reason)

    def test_executable_hook_denies_malformed_or_non_object_payloads(self):
        for raw_payload in ("", "not-json", "[]"):
            with self.subTest(raw_payload=raw_payload):
                result = subprocess.run(
                    self.direct_command,
                    cwd=ROOT,
                    input=raw_payload,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                denial = json.loads(result.stdout)
                self.assertEqual(
                    "deny",
                    denial["hookSpecificOutput"]["permissionDecision"],
                )
                self.assertIn(
                    "unreadable hook payload",
                    denial["hookSpecificOutput"]["permissionDecisionReason"],
                )

    def _assert_block_ask_approve_retry(self, command):
        action = {
            "hook_event_name": "PreToolUse",
            "session_id": "session-runtime",
            "turn_id": "turn-runtime",
            "cwd": "/workspace",
            "tool_name": "Bash",
            "tool_input": {"command": "rm obsolete.txt"},
        }
        first = self._run(command, action)
        self.assertEqual(0, first.returncode, first.stderr)
        denial = json.loads(first.stdout)
        approval_input = approval_request_from_denial(denial)

        approval = {
            "hook_event_name": "PostToolUse",
            "session_id": "session-runtime",
            "turn_id": "turn-runtime",
            "cwd": "/workspace",
            "tool_name": "request_user_input",
            "tool_input": approval_input,
            "tool_response": json.dumps(
                {
                    "answers": {
                        "safe_yolo_approval": {
                            "answers": ["Approve once (Recommended)"],
                        }
                    }
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
        }
        recorded = self._run(command, approval)
        self.assertEqual(0, recorded.returncode, recorded.stderr)
        self.assertIn("one exact retry approval", recorded.stdout)

        retry = self._run(command, action)
        self.assertEqual(0, retry.returncode, retry.stderr)
        self.assertEqual("", retry.stdout)

    def test_candidate_hook_wires_pretool_and_ask_user_posttool_to_v2(self):
        candidate = json.loads(
            (ROOT / "hosts" / "linux" / "devbox.v2-candidate.hooks.json").read_text(
                encoding="utf-8"
            )
        )
        pretool = candidate["hooks"]["PreToolUse"][0]
        posttool = candidate["hooks"]["PostToolUse"][0]

        self.assertEqual("*", pretool["matcher"])
        self.assertEqual("request_user_input", posttool["matcher"])
        for event in (pretool, posttool):
            command = event["hooks"][0]["command"]
            self.assertIn("--entry codex_v2", command)
            self.assertIn("REPLACE_AFTER_INSTALL", command)

    @staticmethod
    def _run(command, payload):
        return subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
