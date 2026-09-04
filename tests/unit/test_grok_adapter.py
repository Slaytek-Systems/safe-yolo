import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from adapters.grok_v3 import build_kernel, handle_pre_tool, normalize_payload
from scripts.install import install_release


ROOT = Path(__file__).resolve().parents[2]


class GrokAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            grok_home=self.root / "home" / ".grok",
            user_home=self.root / "home",
            cwd=self.project,
        )

    def tearDown(self):
        self.temp.cleanup()

    def payload(
        self,
        tool_name: str,
        tool_input: dict,
        *,
        event: str = "pre_tool_use",
    ) -> dict:
        return {
            "hookEventName": event,
            "sessionId": "abc",
            "cwd": str(self.project),
            "workspaceRoot": str(self.project),
            "permissionMode": "bypassPermissions",
            "toolName": tool_name,
            "toolInput": tool_input,
            "toolUseId": "t1",
            "promptId": "p1",
        }

    def test_ordinary_command_is_allowed(self):
        self.assertIsNone(
            handle_pre_tool(self.payload("run_terminal_command", {"command": "npm test"}), self.kernel)
        )

    def test_rm_outside_scratch_is_denied_and_inside_tmp_is_allowed(self):
        denied = handle_pre_tool(
            self.payload("run_terminal_command", {"command": "rm /workspace/build"}),
            self.kernel,
        )
        output = denied["hookSpecificOutput"]
        self.assertEqual("PreToolUse", output["hookEventName"])
        self.assertEqual("deny", output["permissionDecision"])
        self.assertIn("filesystem.delete", output["permissionDecisionReason"])
        self.assertNotIn("approval", output["permissionDecisionReason"].lower())

        self.assertIsNone(
            handle_pre_tool(
                self.payload("run_terminal_command", {"command": "rm /tmp/stale.json"}),
                self.kernel,
            )
        )

    def test_sudo_and_force_push_are_denied(self):
        for command, consequence in (
            ("sudo apt install jq", "privilege.modify"),
            ("git push --force origin main", "git.history_mutation"),
        ):
            with self.subTest(command=command):
                denied = handle_pre_tool(
                    self.payload("run_terminal_command", {"command": command}),
                    self.kernel,
                )
                self.assertIsNotNone(denied, command)
                self.assertIn(consequence, denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_structured_edits_to_enforcement_are_denied(self):
        for tool_name, path in (
            ("search_replace", self.root / "home" / ".grok" / "config.toml"),
            ("Write", self.root / "home" / ".claude" / "settings.json"),
            ("edit_file", self.root / "home" / ".cursor" / "hooks.json"),
            ("MultiEdit", self.root / "safe-yolo" / "bootstrap.py"),
            ("create_file", self.project / ".grok" / "hooks" / "guard.json"),
            ("Edit", self.project / ".claude" / "settings.local.json"),
            ("write_file", self.project / ".cursor" / "hooks.json"),
        ):
            with self.subTest(tool_name=tool_name, path=path):
                denied = handle_pre_tool(self.payload(tool_name, {"path": str(path)}), self.kernel)
                self.assertIsNotNone(denied)
                self.assertIn("enforcement.modify", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_credential_reads_are_denied(self):
        credentials = (
            self.root / "home" / ".grok" / "auth.json",
            self.root / "home" / ".claude" / ".credentials.json",
            self.root / "home" / ".ssh" / "id_ed25519",
            self.root / "home" / ".gnupg" / "pubring.kbx",
        )
        for path in credentials:
            with self.subTest(path=path):
                denied = handle_pre_tool(self.payload("read_file", {"path": str(path)}), self.kernel)
                self.assertIn("credentials.access", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_normalization_maps_grok_tools_and_path_aliases(self):
        cases = (
            ("run_terminal_command", {"command": "npm test"}, "bash", "command", "npm test"),
            ("Bash", {"command": "ls"}, "bash", "command", "ls"),
            ("read_file", {"path": "/tmp/a.txt"}, "read", "file_path", "/tmp/a.txt"),
            ("Read", {"filePath": "/tmp/b.txt"}, "read", "file_path", "/tmp/b.txt"),
            ("search_replace", {"target_file": "/tmp/c.txt"}, "edit", "file_path", "/tmp/c.txt"),
            ("delete_file", {"path": "/tmp/d.txt"}, "delete_file", "path", "/tmp/d.txt"),
            ("Delete", {"file_path": "/tmp/e.txt"}, "delete_file", "path", "/tmp/e.txt"),
        )
        for tool_name, tool_input, mapped, key, expected in cases:
            with self.subTest(tool_name=tool_name):
                normalized = normalize_payload(self.payload(tool_name, tool_input))
                self.assertEqual(mapped, normalized["tool_name"])
                self.assertEqual(expected, normalized["tool_input"][key])

    def test_unmapped_tools_pass_through_for_default_open(self):
        for tool_name in ("list_dir", "grep", "web_search", "spawn_subagent", "use_tool", "linear__save_issue"):
            with self.subTest(tool_name=tool_name):
                self.assertIsNone(handle_pre_tool(self.payload(tool_name, {"query": "ok"}), self.kernel))

    def test_allow_emits_no_output_and_deny_uses_claude_shape(self):
        command = [
            sys.executable,
            str(ROOT / "adapters" / "grok_v3.py"),
            "--safe-yolo-home",
            str(self.root / "safe-yolo"),
            "--grok-home",
            str(self.root / "home" / ".grok"),
            "--user-home",
            str(self.root / "home"),
        ]
        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("run_terminal_command", {"command": "npm test"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("", allowed.stdout)

        denied = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("run_terminal_command", {"command": "rm /workspace/obsolete.txt"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, denied.returncode, denied.stderr)
        output = json.loads(denied.stdout)["hookSpecificOutput"]
        self.assertEqual("deny", output["permissionDecision"])
        self.assertEqual("PreToolUse", output["hookEventName"])
        self.assertIn("filesystem.delete", output["permissionDecisionReason"])

    def test_verified_release_emits_grok_hook_response(self):
        installed = install_release(ROOT, self.root / "installed")
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "grok_v3",
            "--state-dir",
            str(self.root / "unused-state"),
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("run_terminal_command", {"command": "rm /workspace/obsolete.txt"})),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("deny", json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"])
        self.assertFalse((self.root / "unused-state").exists())
        manifest = json.loads((installed["release"] / "manifest.json").read_text())
        self.assertIn("adapters/grok_v3.py", manifest["files"])
        self.assertEqual("adapters/grok_v3.py", manifest["entrypoints"]["grok_v3"])

        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("run_terminal_command", {"command": "npm test"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("", allowed.stdout)


if __name__ == "__main__":
    unittest.main()
