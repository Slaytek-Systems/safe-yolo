import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from adapters.opencode_v3 import build_kernel, handle, normalize_payload
from scripts.install import install_release


ROOT = Path(__file__).resolve().parents[2]


class OpenCodeV3AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            opencode_config=self.root / "config" / "opencode",
            user_home=self.root / "home",
            cwd=self.project,
        )

    def tearDown(self):
        self.temp.cleanup()

    def payload(self, tool: str, args: dict, *, cwd: str | None = None) -> dict:
        return {
            "tool": tool,
            "sessionID": "s",
            "callID": "c",
            "args": args,
            "cwd": cwd or str(self.project),
        }

    def test_ordinary_command_is_allowed(self):
        allowed = handle(self.payload("bash", {"command": "npm test"}), self.kernel)
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual("v3.allow", allowed["policy_id"])

    def test_rm_outside_scratch_is_denied_and_inside_tmp_is_allowed(self):
        denied = handle(self.payload("bash", {"command": "rm /workspace/build"}), self.kernel)
        self.assertEqual("deny", denied["decision"])
        self.assertEqual("filesystem.delete", denied["policy_id"])
        self.assertIn("filesystem.delete", denied["reason"])
        self.assertTrue(denied["reason"].startswith("Safe YOLO denied [filesystem.delete]"))
        self.assertNotIn("approval", denied["reason"].lower())

        allowed = handle(self.payload("bash", {"command": "rm /tmp/stale.json"}), self.kernel)
        self.assertEqual("allow", allowed["decision"])

    def test_sudo_and_force_push_are_denied(self):
        for command, consequence in (
            ("sudo apt install jq", "privilege.modify"),
            ("git push --force origin main", "git.history_mutation"),
        ):
            with self.subTest(command=command):
                denied = handle(self.payload("bash", {"command": command}), self.kernel)
                self.assertEqual("deny", denied["decision"])
                self.assertEqual(consequence, denied["policy_id"])

    def test_structured_edits_to_enforcement_are_denied(self):
        for tool, path in (
            ("edit", self.root / "config" / "opencode" / "opencode.json"),
            ("write", self.root / "config" / "opencode" / "plugins" / "safe-yolo.js"),
            ("edit", self.root / "safe-yolo" / "bootstrap.py"),
            ("write", self.project / "opencode.json"),
            ("edit", self.project / ".opencode" / "plugin.json"),
        ):
            with self.subTest(tool=tool, path=path):
                denied = handle(self.payload(tool, {"filePath": str(path)}), self.kernel)
                self.assertEqual("deny", denied["decision"])
                self.assertEqual("enforcement.modify", denied["policy_id"])

    def test_credential_reads_are_denied(self):
        credentials = (
            self.root / "home" / ".local" / "share" / "opencode" / "auth.json",
            self.root / "home" / ".ssh" / "id_ed25519",
            self.root / "home" / ".gnupg" / "pubring.kbx",
        )
        for path in credentials:
            with self.subTest(path=path):
                denied = handle(self.payload("read", {"filePath": str(path)}), self.kernel)
                self.assertEqual("deny", denied["decision"])
                self.assertEqual("credentials.access", denied["policy_id"])

    def test_normalization_maps_opencode_tools(self):
        bash = normalize_payload(self.payload("bash", {"command": "npm test"}))
        self.assertEqual("bash", bash["tool_name"])
        self.assertEqual("npm test", bash["tool_input"]["command"])
        self.assertEqual("s", bash["session_id"])
        self.assertEqual("c", bash["turn_id"])

        edit = normalize_payload(self.payload("write", {"filePath": "/tmp/a.txt"}))
        self.assertEqual("edit", edit["tool_name"])
        self.assertEqual("/tmp/a.txt", edit["tool_input"]["file_path"])

        read = normalize_payload(self.payload("read", {"path": "/tmp/b.txt"}))
        self.assertEqual("read", read["tool_name"])
        self.assertEqual("/tmp/b.txt", read["tool_input"]["file_path"])

        patch = normalize_payload(self.payload("patch", {"patchText": "*** Delete File: /tmp/c.txt\n"}))
        self.assertEqual("apply_patch", patch["tool_name"])
        self.assertEqual("*** Delete File: /tmp/c.txt\n", patch["tool_input"]["patch"])

        other = normalize_payload(self.payload("websearch", {"query": "safe yolo"}))
        self.assertEqual("websearch", other["tool_name"])

    def test_passthrough_tools_are_default_open(self):
        allowed = handle(self.payload("websearch", {"query": "safe yolo"}), self.kernel)
        self.assertEqual("allow", allowed["decision"])

    def test_cli_always_emits_one_json_line(self):
        command = [
            sys.executable,
            str(ROOT / "adapters" / "opencode_v3.py"),
            "--safe-yolo-home",
            str(self.root / "safe-yolo"),
            "--opencode-config",
            str(self.root / "config" / "opencode"),
            "--user-home",
            str(self.root / "home"),
        ]
        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("bash", {"command": "npm test"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("allow", json.loads(allowed.stdout)["decision"])
        self.assertEqual(1, allowed.stdout.count("\n"))

        denied = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("bash", {"command": "rm /workspace/obsolete.txt"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, denied.returncode, denied.stderr)
        payload = json.loads(denied.stdout)
        self.assertEqual("deny", payload["decision"])
        self.assertEqual("filesystem.delete", payload["policy_id"])
        self.assertTrue(payload["reason"].startswith("Safe YOLO denied [filesystem.delete]"))

        invalid = subprocess.run(
            command,
            cwd=ROOT,
            input="not-json",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, invalid.returncode, invalid.stderr)
        fail_closed = json.loads(invalid.stdout)
        self.assertEqual("deny", fail_closed["decision"])
        self.assertEqual("payload.invalid", fail_closed["policy_id"])
        self.assertIn("fail-closed", fail_closed["reason"])

    def test_verified_release_emits_opencode_hook_response(self):
        installed = install_release(ROOT, self.root / "installed")
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "opencode_v3",
            "--state-dir",
            str(self.root / "unused-state"),
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("bash", {"command": "rm /workspace/obsolete.txt"})),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("deny", json.loads(result.stdout)["decision"])
        self.assertFalse((self.root / "unused-state").exists())
        manifest = json.loads((installed["release"] / "manifest.json").read_text())
        self.assertIn("adapters/opencode_v3.py", manifest["files"])
        self.assertEqual("adapters/opencode_v3.py", manifest["entrypoints"]["opencode_v3"])

        allowed = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("bash", {"command": "npm test"})),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, allowed.returncode, allowed.stderr)
        self.assertEqual("allow", json.loads(allowed.stdout)["decision"])
        self.assertEqual("v3.allow", json.loads(allowed.stdout)["policy_id"])


if __name__ == "__main__":
    unittest.main()
