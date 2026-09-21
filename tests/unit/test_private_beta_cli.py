import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.distribute import deactivate_codex, doctor_codex, install_codex


ROOT = Path(__file__).resolve().parents[2]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PrivateBetaCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir()
        for name in ("policy", "engine", "adapters"):
            shutil.copytree(ROOT / name, self.source / name)
        (self.source / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts" / "bootstrap.py", self.source / "scripts" / "bootstrap.py")
        (self.source / "VERSION").write_text("3.0.0-beta.1\n")
        self.safe_yolo_home = self.root / ".safe-yolo"
        self.codex_home = self.root / ".codex"
        self.codex_home.mkdir()
        self.hooks = self.codex_home / "hooks.json"
        self.config = self.codex_home / "config.toml"
        self.config.write_text(
            'approval_policy = "never"\n'
            'sandbox_mode = "danger-full-access"\n'
            '[features]\n'
            'hooks = true\n'
        )

    def tearDown(self):
        self.temp.cleanup()

    @patch("scripts.distribute.verify_source", return_value="a" * 40)
    def test_fresh_install_creates_release_hook_receipt_and_canaries(self, _verify):
        receipt = install_codex(
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
            expected_commit="a" * 40,
        )

        self.assertEqual("active", receipt["status"])
        self.assertTrue(receipt["healthy"])
        self.assertEqual({"allow": True, "deny": True}, receipt["canaries"])
        self.assertFalse(receipt["previous_hooks_existed"])
        self.assertTrue(Path(receipt["release"]).is_dir())
        self.assertTrue((self.safe_yolo_home / "state" / "codex-install.json").is_file())
        active = json.loads(self.hooks.read_text())
        command = active["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn("--entry codex_v3", command)
        self.assertEqual(sha256(self.hooks), receipt["installed_hooks_sha256"])

    @patch("scripts.distribute.verify_source", return_value="b" * 40)
    def test_install_preserves_unrelated_events_and_refuses_conflicting_pretool(self, _verify):
        original = {
            "hooks": {
                "SessionStart": [
                    {"matcher": "*", "hooks": [{"type": "command", "command": "echo ready"}]}
                ]
            }
        }
        self.hooks.write_text(json.dumps(original) + "\n")
        receipt = install_codex(
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
            expected_commit="b" * 40,
        )
        active = json.loads(self.hooks.read_text())
        self.assertEqual(original["hooks"]["SessionStart"], active["hooks"]["SessionStart"])
        self.assertTrue(receipt["previous_hooks_existed"])

        deactivate_codex(safe_yolo_home=self.safe_yolo_home, codex_home=self.codex_home)
        conflict = {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "*", "hooks": [{"type": "command", "command": "echo foreign"}]}
                ]
            }
        }
        self.hooks.write_text(json.dumps(conflict) + "\n")
        with self.assertRaisesRegex(RuntimeError, "existing PreToolUse"):
            install_codex(
                source=self.source,
                safe_yolo_home=self.safe_yolo_home,
                codex_home=self.codex_home,
                expected_commit="b" * 40,
            )

    @patch("scripts.distribute.verify_source", return_value="c" * 40)
    def test_doctor_and_deactivate_restore_exact_previous_hooks(self, _verify):
        original = {"hooks": {"SessionStart": [{"matcher": "*", "hooks": []}]}}
        self.hooks.write_text(json.dumps(original, indent=2) + "\n")
        original_bytes = self.hooks.read_bytes()
        install_codex(
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
            expected_commit="c" * 40,
        )

        report = doctor_codex(
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
        )
        self.assertTrue(report["healthy"])
        self.assertEqual({"allow": True, "deny": True}, report["canaries"])

        result = deactivate_codex(
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
        )
        self.assertEqual("inactive", result["status"])
        self.assertEqual(original_bytes, self.hooks.read_bytes())
        self.assertTrue(Path(result["retained_release"]).is_dir())

    @patch("scripts.distribute.verify_source", return_value="d" * 40)
    def test_deactivate_refuses_to_overwrite_hook_changed_after_install(self, _verify):
        install_codex(
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
            expected_commit="d" * 40,
        )
        self.hooks.write_text('{"hooks": {}}\n')

        with self.assertRaisesRegex(RuntimeError, "changed since installation"):
            deactivate_codex(
                safe_yolo_home=self.safe_yolo_home,
                codex_home=self.codex_home,
            )

    @patch("scripts.distribute.verify_source", return_value="e" * 40)
    def test_install_rolls_back_when_codex_hooks_are_disabled(self, _verify):
        self.config.write_text(
            'approval_policy = "never"\n'
            'sandbox_mode = "danger-full-access"\n'
            '[features]\n'
            'hooks = false\n'
        )

        with self.assertRaisesRegex(RuntimeError, "hooks feature must be enabled"):
            install_codex(
                source=self.source,
                safe_yolo_home=self.safe_yolo_home,
                codex_home=self.codex_home,
                expected_commit="e" * 40,
            )

        self.assertFalse(self.hooks.exists())

    def test_cli_exposes_install_doctor_and_deactivate(self):
        completed = subprocess.run(
            [sys.executable, str(ROOT / "safe-yolo"), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("install", completed.stdout)
        self.assertIn("doctor", completed.stdout)
        self.assertIn("deactivate", completed.stdout)


if __name__ == "__main__":
    unittest.main()
