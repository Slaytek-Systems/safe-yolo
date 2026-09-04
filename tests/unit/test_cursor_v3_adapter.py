import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from adapters.cursor_v3 import build_kernel, handle, normalize_payload
from scripts.install import install_release


ROOT = Path(__file__).resolve().parents[2]


class CursorV3AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            cursor_home=self.root / "home" / ".cursor",
            user_home=self.root / "home",
            cwd=self.project,
        )

    def tearDown(self):
        self.temp.cleanup()

    def shell_payload(self, command: str, *, cwd: str | None = None) -> dict:
        return {
            "hook_event_name": "beforeShellExecution",
            "command": command,
            "cwd": cwd or str(self.project),
            "conversation_id": "conv-1",
            "generation_id": "gen-1",
        }

    def test_ordinary_command_is_allowed(self):
        response = handle(self.shell_payload("git status --short"), self.kernel)
        self.assertEqual({"permission": "allow"}, response)

    def test_rm_outside_scratch_is_denied_and_inside_tmp_is_allowed(self):
        denied = handle(self.shell_payload("rm /workspace/build"), self.kernel)
        self.assertEqual("deny", denied["permission"])
        self.assertIn("filesystem.delete", denied["user_message"])
        self.assertEqual(denied["user_message"], denied["agent_message"])
        self.assertNotIn("approval", denied["user_message"].lower())

        allowed = handle(self.shell_payload("rm /tmp/stale.json"), self.kernel)
        self.assertEqual({"permission": "allow"}, allowed)

        structured = handle(
            {
                "hook_event_name": "preToolUse",
                "tool_name": "Delete",
                "tool_input": {"path": "/tmp/stale.json"},
            },
            self.kernel,
        )
        self.assertEqual({"permission": "allow"}, structured)

    def test_sudo_and_force_push_are_denied(self):
        for command, consequence in (
            ("sudo apt install jq", "privilege.modify"),
            ("git push --force origin main", "git.history_mutation"),
        ):
            with self.subTest(command=command):
                denied = handle(self.shell_payload(command), self.kernel)
                self.assertEqual("deny", denied["permission"])
                self.assertIn(consequence, denied["user_message"])

    def test_structured_edits_to_enforcement_are_denied(self):
        for tool_name, path in (
            ("Write", self.root / "home" / ".cursor" / "hooks.json"),
            ("StrReplace", self.root / "home" / ".cursor" / "hooks" / "safe-yolo-cursor.sh"),
            ("EditNotebook", self.root / "safe-yolo" / "bootstrap.py"),
            ("Write", self.project / ".cursor" / "hooks.json"),
        ):
            with self.subTest(tool_name=tool_name, path=path):
                payload = {
                    "hook_event_name": "preToolUse",
                    "tool_name": tool_name,
                    "tool_input": {"path": str(path)},
                }
                if tool_name == "EditNotebook":
                    payload["tool_input"] = {"target_notebook": str(path)}
                denied = handle(payload, self.kernel)
                self.assertEqual("deny", denied["permission"])
                self.assertIn("enforcement.modify", denied["user_message"])

    def test_credential_reads_are_denied(self):
        for path in (
            self.root / "home" / ".ssh" / "id_ed25519",
            self.root / "home" / ".gnupg" / "pubring.kbx",
        ):
            with self.subTest(path=path):
                denied = handle(
                    {"hook_event_name": "beforeReadFile", "file_path": str(path)},
                    self.kernel,
                )
                self.assertEqual("deny", denied["permission"])
                self.assertIn("credentials.access", denied["user_message"])

    def test_normalization_maps_cursor_events(self):
        shell = normalize_payload(self.shell_payload("npm test", cwd="/tmp/work"))
        self.assertEqual("bash", shell["tool_name"])
        self.assertEqual("npm test", shell["tool_input"]["command"])
        self.assertEqual("/tmp/work", shell["cwd"])
        self.assertEqual("conv-1", shell["session_id"])
        self.assertEqual("gen-1", shell["turn_id"])

        working_directory = normalize_payload(
            {
                "hook_event_name": "beforeShellExecution",
                "command": "npm test",
                "working_directory": "/tmp/wd",
            }
        )
        self.assertEqual("/tmp/wd", working_directory["cwd"])

        mapped = (
            ("Write", {"path": "/tmp/a.txt"}, "write", "file_path"),
            ("StrReplace", {"path": "/tmp/b.txt"}, "edit", "file_path"),
            ("Delete", {"path": "/tmp/c.txt"}, "delete_file", "path"),
            ("EditNotebook", {"target_notebook": "/tmp/d.ipynb"}, "edit", "file_path"),
        )
        for tool_name, tool_input, expected_name, path_key in mapped:
            with self.subTest(tool_name=tool_name):
                normalized = normalize_payload(
                    {
                        "hook_event_name": "preToolUse",
                        "tool_name": tool_name,
                        "tool_input": tool_input,
                    }
                )
                self.assertEqual(expected_name, normalized["tool_name"])
                self.assertEqual(next(iter(tool_input.values())), normalized["tool_input"][path_key])

        read = normalize_payload({"hook_event_name": "beforeReadFile", "file_path": "/tmp/e.txt"})
        self.assertEqual("read", read["tool_name"])
        self.assertEqual("/tmp/e.txt", read["tool_input"]["file_path"])

    def test_mcp_and_unknown_tools_are_default_open(self):
        for payload in (
            {
                "hook_event_name": "beforeMCPExecution",
                "tool_name": "create_external_record",
                "tool_input": {"title": "Example"},
            },
            {
                "hook_event_name": "beforeMCPExecution",
                "tool_name": "linear__save_issue",
                "tool_input": '{"title": "Example"}',
            },
        ):
            with self.subTest(tool_name=payload["tool_name"]):
                self.assertEqual({"permission": "allow"}, handle(payload, self.kernel))

    def test_submit_prompt_always_continues(self):
        response = handle({"hook_event_name": "beforeSubmitPrompt", "prompt": "ship it"}, self.kernel)
        self.assertEqual({"continue": True}, response)

    def test_camelcase_cursor_payload_is_evaluated(self):
        denied = handle(
            {
                "hookEventName": "beforeShellExecution",
                "command": "rm /workspace/obsolete.txt",
                "cwd": str(self.project),
                "conversationId": "conv-1",
                "generationId": "gen-1",
            },
            self.kernel,
        )
        self.assertEqual("deny", denied["permission"])
        self.assertIn("filesystem.delete", denied["user_message"])

    def test_invalid_json_stdin_is_fail_closed(self):
        command = [
            sys.executable,
            str(ROOT / "adapters" / "cursor_v3.py"),
            "--safe-yolo-home",
            str(self.root / "safe-yolo"),
            "--cursor-home",
            str(self.root / "home" / ".cursor"),
            "--user-home",
            str(self.root / "home"),
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            input="not-json",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        denied = json.loads(result.stdout)
        self.assertEqual("deny", denied["permission"])
        self.assertIn("fail-closed", denied["user_message"])
        self.assertEqual(denied["user_message"], denied["agent_message"])

    def test_verified_release_emits_cursor_hook_response(self):
        installed = install_release(ROOT, self.root / "installed")
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "cursor_v3",
            "--state-dir",
            str(self.root / "unused-state"),
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.shell_payload("rm /workspace/obsolete.txt")),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("deny", json.loads(result.stdout)["permission"])
        self.assertFalse((self.root / "unused-state").exists())
        manifest = json.loads((installed["release"] / "manifest.json").read_text())
        self.assertIn("adapters/cursor_v3.py", manifest["files"])
        self.assertEqual("adapters/cursor_v3.py", manifest["entrypoints"]["cursor_v3"])

        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.shell_payload("git status --short")),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual({"permission": "allow"}, json.loads(allowed.stdout))


if __name__ == "__main__":
    unittest.main()
