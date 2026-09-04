import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from adapters.antigravity_v3 import build_kernel, handle_pre_tool, normalize_payload
from scripts.install import install_release


ROOT = Path(__file__).resolve().parents[2]


class AntigravityAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.gemini_home = self.root / "gemini-home"
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            gemini_home=self.gemini_home,
            user_home=self.root / "home",
            cwd=self.project,
        )

    def tearDown(self):
        self.temp.cleanup()

    def payload(
        self,
        name: str,
        args: dict,
        *,
        workspace_paths: list[str] | None = None,
    ) -> dict:
        return {
            "toolCall": {"name": name, "args": args},
            "stepIdx": 3,
            "conversationId": "c1",
            "workspacePaths": workspace_paths if workspace_paths is not None else [str(self.project)],
            "transcriptPath": str(self.root / "transcript.jsonl"),
            "artifactDirectoryPath": str(self.root / "artifacts"),
        }

    def test_ordinary_command_is_allowed(self):
        self.assertIsNone(handle_pre_tool(self.payload("run_command", {"CommandLine": "git status"}), self.kernel))

    def test_rm_outside_scratch_is_denied_and_inside_tmp_is_allowed(self):
        denied = handle_pre_tool(
            self.payload(
                "run_command",
                {"CommandLine": "rm -rf src"},
                workspace_paths=["/home/test/project"],
            ),
            self.kernel,
        )
        self.assertIsNotNone(denied)
        self.assertEqual("deny", denied["decision"])
        self.assertIn("filesystem.delete", denied["reason"])
        self.assertNotIn("approval", denied["reason"].lower())

        self.assertIsNone(
            handle_pre_tool(self.payload("run_command", {"CommandLine": "rm -rf /tmp/build"}), self.kernel)
        )

    def test_sudo_and_force_push_are_denied(self):
        for command, consequence in (
            ("sudo apt install jq", "privilege.modify"),
            ("git push --force origin main", "git.history_mutation"),
        ):
            with self.subTest(command=command):
                denied = handle_pre_tool(
                    self.payload("run_command", {"CommandLine": command}),
                    self.kernel,
                )
                self.assertIsNotNone(denied, command)
                self.assertEqual("deny", denied["decision"])
                self.assertIn(consequence, denied["reason"])

    def test_structured_edits_to_enforcement_are_denied(self):
        for tool_name, path in (
            ("edit_file", self.gemini_home / "config" / "hooks.json"),
            ("replace_file_content", self.root / "safe-yolo" / "bootstrap.py"),
        ):
            with self.subTest(tool_name=tool_name, path=path):
                denied = handle_pre_tool(
                    self.payload(tool_name, {"AbsolutePath": str(path)}),
                    self.kernel,
                )
                self.assertIsNotNone(denied)
                self.assertEqual("deny", denied["decision"])
                self.assertIn("enforcement.modify", denied["reason"])

    def test_credential_reads_are_denied(self):
        credentials = (
            self.gemini_home / "antigravity-acp" / "acp_token.json",
            self.root / "home" / ".ssh" / "id_ed25519",
        )
        for path in credentials:
            with self.subTest(path=path):
                denied = handle_pre_tool(self.payload("view_file", {"AbsolutePath": str(path)}), self.kernel)
                self.assertIsNotNone(denied)
                self.assertIn("credentials.access", denied["reason"])

    def test_pascalcase_and_lowercase_exec_args_and_cwd_resolve_relative_rm(self):
        cases = (
            {"CommandLine": "rm -rf src", "Cwd": "/home/test/other"},
            {"command": "rm -rf src", "cwd": "/home/test/other"},
        )
        for args in cases:
            with self.subTest(args=args):
                denied = handle_pre_tool(
                    self.payload("run_command", args, workspace_paths=["/tmp/workspace"]),
                    self.kernel,
                )
                self.assertIsNotNone(denied)
                self.assertIn("filesystem.delete", denied["reason"])
                normalized = normalize_payload(self.payload("run_command", args))
                self.assertEqual("bash", normalized["tool_name"])
                self.assertEqual("rm -rf src", normalized["tool_input"]["command"])
                self.assertEqual("/home/test/other", normalized["tool_input"]["workdir"])

    def test_call_mcp_tool_and_search_web_pass_through(self):
        mcp = handle_pre_tool(
            self.payload(
                "call_mcp_tool",
                {"ServerName": "linear", "ToolName": "save_issue", "Arguments": {"title": "ok"}},
            ),
            self.kernel,
        )
        self.assertIsNone(mcp)
        mapped = normalize_payload(
            self.payload(
                "call_mcp_tool",
                {"ServerName": "linear", "ToolName": "save_issue", "Arguments": {"title": "ok"}},
            )
        )
        self.assertEqual("linear_save_issue", mapped["tool_name"])
        self.assertIsNone(handle_pre_tool(self.payload("search_web", {"Query": "safe yolo"}), self.kernel))

    def test_invalid_json_stdin_is_denied(self):
        command = [
            sys.executable,
            str(ROOT / "adapters" / "antigravity_v3.py"),
            "--safe-yolo-home",
            str(self.root / "safe-yolo"),
            "--gemini-home",
            str(self.gemini_home),
            "--user-home",
            str(self.root / "home"),
        ]
        invalid = subprocess.run(
            command,
            cwd=ROOT,
            input="not-json",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, invalid.returncode, invalid.stderr)
        payload = json.loads(invalid.stdout)
        self.assertEqual("deny", payload["decision"])
        self.assertIn("payload.invalid", payload["reason"])

    def test_verified_release_emits_antigravity_hook_response(self):
        installed = install_release(ROOT, self.root / "installed")
        gemini_home = self.root / "hook-gemini"
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "antigravity_v3",
            "--state-dir",
            str(self.root / "unused-state"),
        ]
        env = os.environ.copy()
        env["GEMINI_HOME"] = str(gemini_home)

        denied = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(
                self.payload("edit_file", {"AbsolutePath": str(gemini_home / "config" / "hooks.json")})
            ),
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
        self.assertEqual(0, denied.returncode, denied.stderr)
        output = json.loads(denied.stdout)
        self.assertEqual("deny", output["decision"])
        self.assertIn("reason", output)
        self.assertIn("enforcement.modify", output["reason"])
        self.assertFalse((self.root / "unused-state").exists())
        manifest = json.loads((installed["release"] / "manifest.json").read_text())
        self.assertIn("adapters/antigravity_v3.py", manifest["files"])
        self.assertEqual("adapters/antigravity_v3.py", manifest["entrypoints"]["antigravity_v3"])

        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("run_command", {"CommandLine": "git status"})),
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("", allowed.stdout)


if __name__ == "__main__":
    unittest.main()
