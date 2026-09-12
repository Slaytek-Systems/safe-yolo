import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.activate_v3 import activate_release


ROOT = Path(__file__).resolve().parents[2]


class V3OperatorActivationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for name in ("policy", "engine", "adapters"):
            shutil.copytree(ROOT / name, self.source / name)
        (self.source / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts" / "bootstrap.py", self.source / "scripts" / "bootstrap.py")
        (self.source / "VERSION").write_text("3.0.0-alpha.9\n")
        self.home = self.root / "safe-yolo"
        self.hooks = self.root / "hooks.json"
        self.config = self.root / "config.toml"
        self.config.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        self.original_hooks = {
            "description": "old release",
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python3 /old/bootstrap.py --release /old/release --manifest-sha256 " + "a" * 64 + " --entry codex_v3",
                                "timeout": 10,
                            }
                        ],
                    }
                ]
            },
        }
        self.hooks.write_text(json.dumps(self.original_hooks) + "\n")

    def tearDown(self):
        self.temp.cleanup()

    def test_operator_cli_is_directly_executable(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "activate_v3.py"), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("--expected-source-commit", completed.stdout)

    @patch("scripts.activate_v3.verify_source", return_value="a" * 40)
    def test_installs_repins_backs_up_and_doctors_candidate(self, _verify):
        receipt = activate_release(
            source=self.source,
            home=self.home,
            hooks_path=self.hooks,
            config_path=self.config,
            expected_commit="a" * 40,
        )

        self.assertTrue(receipt["healthy"])
        self.assertEqual("3.0.0-alpha.9", receipt["version"])
        self.assertTrue(Path(receipt["release"]).is_dir())
        self.assertTrue(Path(receipt["backup"]).is_file())
        active = json.loads(self.hooks.read_text())
        command = active["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn(receipt["release"], command)
        self.assertIn(receipt["manifest_sha256"], command)
        self.assertIn("--entry codex_v3", command)
        self.assertFalse((active["hooks"].get("PostToolUse") or []))

    @patch("scripts.activate_v3.verify_source", return_value="b" * 40)
    def test_malformed_hook_shape_fails_before_install(self, _verify):
        self.hooks.write_text('{"hooks": {"PreToolUse": []}}\n')

        with self.assertRaisesRegex(RuntimeError, "exactly one PreToolUse"):
            activate_release(
                source=self.source,
                home=self.home,
                hooks_path=self.hooks,
                config_path=self.config,
                expected_commit="b" * 40,
            )

        self.assertFalse((self.home / "releases").exists())

    @patch("scripts.activate_v3.inspect_codex_wiring", return_value={"healthy": False, "problems": ["canary"]})
    @patch("scripts.activate_v3.verify_source", return_value="c" * 40)
    def test_failed_doctor_restores_previous_hook_document(self, _verify, _doctor):
        original = self.hooks.read_bytes()

        with self.assertRaisesRegex(RuntimeError, "failed doctor"):
            activate_release(
                source=self.source,
                home=self.home,
                hooks_path=self.hooks,
                config_path=self.config,
                expected_commit="c" * 40,
            )

        self.assertEqual(original, self.hooks.read_bytes())

    @patch("scripts.activate_v3.inspect_codex_wiring", side_effect=OSError("canary"))
    @patch("scripts.activate_v3.verify_source", return_value="d" * 40)
    def test_crashed_doctor_restores_previous_hook_document(self, _verify, _doctor):
        original = self.hooks.read_bytes()

        with self.assertRaisesRegex(RuntimeError, "doctor crashed"):
            activate_release(
                source=self.source,
                home=self.home,
                hooks_path=self.hooks,
                config_path=self.config,
                expected_commit="d" * 40,
            )

        self.assertEqual(original, self.hooks.read_bytes())


if __name__ == "__main__":
    unittest.main()
