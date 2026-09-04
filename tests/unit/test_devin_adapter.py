import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from adapters.devin_v3 import build_kernel, handle_pre_tool, normalize_payload
from scripts.install import install_release


ROOT = Path(__file__).resolve().parents[2]


class DevinAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.root = root
        self.kernel = build_kernel(
            safe_yolo_home=root / "safe-yolo",
            devin_config=root / "config" / "devin" / "config.json",
            user_home=root / "home",
        )

    def tearDown(self):
        self.temp.cleanup()

    def payload(self, command: str) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "session_id": "session-1",
            "prompt_id": "prompt-1",
            "tool_name": "exec",
            "tool_input": {"command": command, "workdir": "/workspace"},
        }

    def test_exec_uses_shared_deny_only_kernel(self):
        self.assertIsNone(handle_pre_tool(self.payload("git status --short"), self.kernel))

        denied = handle_pre_tool(self.payload("rm obsolete.txt"), self.kernel)

        self.assertEqual("block", denied["decision"])
        self.assertIn("filesystem.delete", denied["reason"])
        self.assertNotIn("approval", denied["reason"].lower())

    def test_normalization_maps_devin_exec_and_prompt_identity(self):
        normalized = normalize_payload(self.payload("git status --short"))

        self.assertEqual("exec_command", normalized["tool_name"])
        self.assertEqual("session-1", normalized["session_id"])
        self.assertEqual("prompt-1", normalized["turn_id"])
        self.assertEqual("/workspace", normalized["cwd"])

    def test_structured_write_to_devin_config_directory_is_denied(self):
        for path in (
            self.root / "config" / "devin" / "config.json",
            self.root / "config" / "devin" / "hooks.v1.json",
        ):
            with self.subTest(path=path):
                payload = {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "edit",
                    "tool_input": {"file_path": str(path)},
                }
                denied = handle_pre_tool(payload, self.kernel)
                self.assertEqual("block", denied["decision"])
                self.assertIn("enforcement.modify", denied["reason"])

    def test_default_scratch_roots_allow_tmp_deletes(self):
        self.assertIsNone(handle_pre_tool(self.payload("rm /tmp/stale.json"), self.kernel))
        home_tmp = self.root / "home" / "tmp" / "stale.json"
        self.assertIsNone(handle_pre_tool(self.payload(f"rm {home_tmp}"), self.kernel))
        denied = handle_pre_tool(self.payload("rm /var/tmp/stale.json"), self.kernel)
        self.assertEqual("block", denied["decision"])
        self.assertIn("filesystem.delete", denied["reason"])

    def test_empty_scratch_paths_preserve_delete_denials(self):
        kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            devin_config=self.root / "config" / "devin" / "config.json",
            user_home=self.root / "home",
            scratch_paths=(),
        )
        denied = handle_pre_tool(self.payload("rm /tmp/stale.json"), kernel)
        self.assertEqual("block", denied["decision"])
        self.assertIn("filesystem.delete", denied["reason"])

    def test_scratch_cli_flag_replaces_default_roots(self):
        custom = self.root / "custom-scratch"
        command = [
            sys.executable,
            str(ROOT / "adapters" / "devin_v3.py"),
            "--safe-yolo-home",
            str(self.root / "safe-yolo"),
            "--devin-config",
            str(self.root / "config" / "devin" / "config.json"),
            "--user-home",
            str(self.root / "home"),
            "--scratch",
            str(custom),
        ]
        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload(f"rm {custom / 'stale.json'}")),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("", allowed.stdout)

        denied = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("rm /tmp/stale.json")),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, denied.returncode, denied.stderr)
        self.assertIn("filesystem.delete", denied.stdout)

    def test_workdir_overrides_stale_top_level_cwd(self):
        payload = self.payload("printf safe")
        payload["cwd"] = "/stale"

        self.assertEqual("/workspace", normalize_payload(payload)["cwd"])

    def test_missing_workdir_does_not_invent_empty_cwd(self):
        payload = self.payload("printf safe")
        del payload["tool_input"]["workdir"]
        with patch.dict("os.environ", {}, clear=True):
            normalized = normalize_payload(payload)

        self.assertNotIn("cwd", normalized)

    def test_unbounded_process_writes_are_denied(self):
        payloads = (
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "write_to_process",
                "tool_input": {"text_input": "rm obsolete.txt"},
            },
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "exec",
                "tool_input": {"shell_id": "shell-1", "command": "printf safe"},
            },
        )
        for payload in payloads:
            with self.subTest(tool_name=payload["tool_name"]):
                denied = handle_pre_tool(payload, self.kernel)
                self.assertEqual("block", denied["decision"])
                self.assertIn("interactive.process_write", denied["reason"])

    def test_non_pretool_event_is_ignored(self):
        payload = self.payload("rm obsolete.txt")
        payload["hook_event_name"] = "PostToolUse"

        self.assertIsNone(handle_pre_tool(payload, self.kernel))

    def test_credential_paths_are_denied(self):
        for tool_name in ("edit", "read"):
            with self.subTest(tool_name=tool_name):
                denied = handle_pre_tool(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": tool_name,
                        "tool_input": {"file_path": str(self.root / "home" / ".ssh" / "config")},
                    },
                    self.kernel,
                )
                self.assertEqual("block", denied["decision"])
                self.assertIn("credentials.access", denied["reason"])

    def test_verified_release_emits_devin_hook_response(self):
        installed = install_release(ROOT, self.root / "installed")
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "devin_v3",
            "--state-dir",
            str(self.root / "unused-state"),
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("rm obsolete.txt")),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("block", json.loads(result.stdout)["decision"])
        self.assertFalse((self.root / "unused-state").exists())
        manifest = json.loads((installed["release"] / "manifest.json").read_text())
        self.assertIn("adapters/devin_v3.py", manifest["files"])

        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("git status --short")),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("", allowed.stdout)


if __name__ == "__main__":
    unittest.main()
