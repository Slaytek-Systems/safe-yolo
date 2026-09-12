import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from adapters.claude_code_v3 import build_kernel, handle_pre_tool, normalize_payload
from scripts.doctor import inspect_claude_code_wiring
from scripts.install import install_release


ROOT = Path(__file__).resolve().parents[2]


class ClaudeCodeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            claude_home=self.root / "home" / ".claude",
            user_home=self.root / "home",
            cwd=self.project,
        )

    def tearDown(self):
        self.temp.cleanup()

    def payload(self, tool_name: str, tool_input: dict) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "session_id": "session-1",
            "transcript_path": str(self.root / "transcript.jsonl"),
            "cwd": str(self.project),
            "permission_mode": "bypassPermissions",
            "tool_name": tool_name,
            "tool_use_id": "toolu_1",
            "tool_input": tool_input,
        }

    def test_bash_uses_shared_deny_only_kernel(self):
        self.assertIsNone(handle_pre_tool(self.payload("Bash", {"command": "git status --short"}), self.kernel))

        denied = handle_pre_tool(self.payload("Bash", {"command": "rm -rf /workspace/build"}), self.kernel)

        output = denied["hookSpecificOutput"]
        self.assertEqual("PreToolUse", output["hookEventName"])
        self.assertEqual("deny", output["permissionDecision"])
        self.assertIn("filesystem.delete", output["permissionDecisionReason"])
        self.assertNotIn("approval", output["permissionDecisionReason"].lower())

    def test_bash_consequence_families_are_denied(self):
        for command, consequence in (
            ("sudo apt install jq", "privilege.modify"),
            ("git push --force origin main", "git.history_mutation"),
            ("ssh devbox", "remote.execute"),
            ("gh pr merge 12 --admin", "production.mutate"),
            ("vite --host 0.0.0.0", "network.public_exposure"),
            ("printenv", "credentials.access"),
        ):
            with self.subTest(command=command):
                denied = handle_pre_tool(self.payload("Bash", {"command": command}), self.kernel)
                self.assertIsNotNone(denied, command)
                self.assertIn(consequence, denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_structured_edits_to_enforcement_are_denied(self):
        for tool_name, path in (
            ("Edit", self.root / "home" / ".claude" / "settings.json"),
            ("Write", self.root / "home" / ".claude" / "settings.local.json"),
            ("MultiEdit", self.root / "safe-yolo" / "bootstrap.py"),
            ("Write", self.project / ".claude" / "settings.json"),
            ("Edit", self.project / ".claude" / "settings.local.json"),
        ):
            with self.subTest(tool_name=tool_name, path=path):
                denied = handle_pre_tool(self.payload(tool_name, {"file_path": str(path)}), self.kernel)
                self.assertIsNotNone(denied)
                self.assertIn("enforcement.modify", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_ordinary_project_edits_are_allowed(self):
        for tool_name, tool_input in (
            ("Edit", {"file_path": str(self.project / "src" / "main.py"), "old_string": "a", "new_string": "b"}),
            ("Write", {"file_path": str(self.project / "README.md"), "content": "hi"}),
            ("Read", {"file_path": str(self.project / ".claude" / "settings.json")}),
            ("Bash", {"command": "cat ~/.claude/settings.json"}),
        ):
            with self.subTest(tool_name=tool_name):
                self.assertIsNone(handle_pre_tool(self.payload(tool_name, tool_input), self.kernel))

    def test_shell_mutation_of_enforcement_is_denied(self):
        settings = self.root / "home" / ".claude" / "settings.json"
        for command in (
            f"sed -i 's/a/b/' {settings}",
            f"tee {settings}",
            f"echo '{{}}' > {settings}",
        ):
            with self.subTest(command=command):
                denied = handle_pre_tool(self.payload("Bash", {"command": command}), self.kernel)
                self.assertIsNotNone(denied, command)
                self.assertIn("enforcement.modify", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_shell_reads_of_enforcement_redirected_outside_are_allowed(self):
        settings = self.root / "home" / ".claude" / "settings.json"
        for command in (
            f"jq . {settings} > /tmp/out.json",
            f"cat {settings} > /tmp/p.json",
            f"cp {settings} /tmp/backup.json",
            f"printf 'a -> b' {settings}",
        ):
            with self.subTest(command=command):
                self.assertIsNone(handle_pre_tool(self.payload("Bash", {"command": command}), self.kernel))

    def test_mutating_shell_targets_stay_denied(self):
        settings = self.root / "home" / ".claude" / "settings.json"
        local_settings = self.root / "home" / ".claude" / "settings.local.json"
        bootstrap = self.root / "safe-yolo" / "bootstrap.py"
        for command in (
            f"echo '{{}}' > {settings}",
            f"tee {settings}",
            f"sed -i s/a/b/ {bootstrap}",
            f"cp /tmp/x {settings}",
            f"mv {settings} /tmp/x",
            f"mv /tmp/x {settings}",
            f"chmod 600 {bootstrap}",
            f"truncate -s0 {local_settings}",
            f"rm {bootstrap}",
            f"install /tmp/x {bootstrap}",
        ):
            with self.subTest(command=command):
                denied = handle_pre_tool(self.payload("Bash", {"command": command}), self.kernel)
                self.assertIsNotNone(denied, command)
                self.assertIn(
                    "enforcement.modify",
                    denied["hookSpecificOutput"]["permissionDecisionReason"],
                )

    def test_default_scratch_roots_allow_tmp_deletes(self):
        self.assertIsNone(handle_pre_tool(self.payload("Bash", {"command": "rm /tmp/stale.json"}), self.kernel))
        home_tmp = self.root / "home" / "tmp" / "stale.json"
        self.assertIsNone(
            handle_pre_tool(self.payload("Bash", {"command": f"rm {home_tmp}"}), self.kernel)
        )
        denied = handle_pre_tool(self.payload("Bash", {"command": "rm /var/tmp/stale.json"}), self.kernel)
        self.assertIn("filesystem.delete", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_scratch_cli_flag_replaces_default_roots(self):
        custom = self.root / "custom-scratch"
        command = [
            sys.executable,
            str(ROOT / "adapters" / "claude_code_v3.py"),
            "--safe-yolo-home",
            str(self.root / "safe-yolo"),
            "--claude-home",
            str(self.root / "home" / ".claude"),
            "--user-home",
            str(self.root / "home"),
            "--scratch",
            str(custom),
        ]
        payload = self.payload("Bash", {"command": f"rm {custom / 'stale.json'}"})
        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("", allowed.stdout)

        denied = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("Bash", {"command": "rm /tmp/stale.json"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, denied.returncode, denied.stderr)
        self.assertIn("filesystem.delete", denied.stdout)

    def test_notebook_edit_is_normalized_to_a_path_edit(self):
        notebook = self.root / "home" / ".claude" / "settings.json"
        normalized = normalize_payload(self.payload("NotebookEdit", {"notebook_path": str(notebook)}))

        self.assertEqual("edit", normalized["tool_name"])
        self.assertEqual(str(notebook), normalized["tool_input"]["file_path"])
        denied = handle_pre_tool(self.payload("NotebookEdit", {"notebook_path": str(notebook)}), self.kernel)
        self.assertIn("enforcement.modify", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_credential_paths_are_denied_for_read_and_shell(self):
        credentials = (
            self.root / "home" / ".ssh" / "id_ed25519",
            self.root / "home" / ".gnupg" / "pubring.kbx",
            self.root / "home" / ".claude" / ".credentials.json",
        )
        for path in credentials:
            with self.subTest(path=path):
                denied = handle_pre_tool(self.payload("Read", {"file_path": str(path)}), self.kernel)
                self.assertIn("credentials.access", denied["hookSpecificOutput"]["permissionDecisionReason"])
                denied = handle_pre_tool(self.payload("Bash", {"command": f"cat {path}"}), self.kernel)
                self.assertIn("credentials.access", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_camelcase_grok_shaped_payload_is_evaluated(self):
        payload = {
            "hookEventName": "pre_tool_use",
            "sessionId": "abc",
            "cwd": str(self.project),
            "workspaceRoot": str(self.project),
            "permissionMode": "bypassPermissions",
            "toolName": "Bash",
            "toolInput": {"command": "rm /workspace/obsolete.txt"},
            "toolUseId": "t1",
            "promptId": "p1",
        }

        denied = handle_pre_tool(payload, self.kernel)

        self.assertIsNotNone(denied)
        self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("filesystem.delete", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_grok_run_terminal_command_is_denied(self):
        payload = {
            "hookEventName": "pre_tool_use",
            "sessionId": "abc",
            "cwd": str(self.project),
            "workspaceRoot": str(self.project),
            "permissionMode": "bypassPermissions",
            "toolName": "run_terminal_command",
            "toolInput": {"command": "rm -rf /home/test/project/src"},
            "toolUseId": "t1",
            "promptId": "p1",
        }

        denied = handle_pre_tool(payload, self.kernel)

        self.assertIsNotNone(denied)
        self.assertEqual("deny", denied["hookSpecificOutput"]["permissionDecision"])
        self.assertIn("filesystem.delete", denied["hookSpecificOutput"]["permissionDecisionReason"])

    def test_non_pretool_event_is_ignored(self):
        payload = self.payload("Bash", {"command": "rm obsolete.txt"})
        payload["hook_event_name"] = "PostToolUse"

        self.assertIsNone(handle_pre_tool(payload, self.kernel))

    def test_verified_release_emits_claude_code_hook_response(self):
        installed = install_release(ROOT, self.root / "installed")
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "claude_code_v3",
            "--state-dir",
            str(self.root / "unused-state"),
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("Bash", {"command": "rm /workspace/obsolete.txt"})),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("deny", json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"])
        self.assertFalse((self.root / "unused-state").exists())
        manifest = json.loads((installed["release"] / "manifest.json").read_text())
        self.assertIn("adapters/claude_code_v3.py", manifest["files"])
        self.assertEqual("adapters/claude_code_v3.py", manifest["entrypoints"]["claude_code_v3"])

        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("Bash", {"command": "git status --short"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("", allowed.stdout)

    def test_doctor_checks_claude_code_settings_pin(self):
        installed = install_release(ROOT, self.root / "installed")
        command = (
            f"/usr/bin/python3 {installed['bootstrap']} --release {installed['release']} "
            f"--manifest-sha256 {installed['manifest_sha256']} --entry claude_code_v3 "
            f"--state-dir {self.root / 'state'}"
        )
        settings = self.root / "settings.json"
        document = {
            "model": "claude-fable-5-1",
            "skipDangerousModePermissionPrompt": True,
            "hooks": {
                "PreToolUse": [
                    {"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 10}]}
                ]
            },
        }
        settings.write_text(json.dumps(document))
        healthy = inspect_claude_code_wiring(
            settings,
            installed["bootstrap"],
            installed["manifest_sha256"],
            release_path=installed["release"],
        )
        self.assertTrue(healthy["healthy"], healthy)

        document["disableAllHooks"] = True
        settings.write_text(json.dumps(document))
        disabled = inspect_claude_code_wiring(
            settings,
            installed["bootstrap"],
            installed["manifest_sha256"],
            release_path=installed["release"],
        )
        self.assertIn("disableAllHooks must not be set", disabled["problems"])

        del document["disableAllHooks"]
        document["hooks"]["PostToolUse"] = document["hooks"]["PreToolUse"]
        document["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = command.replace("alpha", "beta")
        settings.write_text(json.dumps(document))
        stale = inspect_claude_code_wiring(
            settings,
            installed["bootstrap"],
            installed["manifest_sha256"],
            release_path=installed["release"],
        )
        self.assertFalse(stale["healthy"])
        self.assertIn(
            "PreToolUse hook is not pinned to the expected Safe YOLO bootstrap release",
            stale["problems"],
        )


if __name__ == "__main__":
    unittest.main()
