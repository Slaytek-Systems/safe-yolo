import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.bootstrap import verified_entry
from scripts.doctor import inspect_codex_wiring, inspect_cursor_wiring, inspect_release
from scripts.release_manifest import build_manifest, manifest_digest, verify_manifest

ROOT = Path(__file__).resolve().parents[2]


class ReleaseToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.release = Path(self.temp.name) / "release"
        self.release.mkdir()
        shutil.copytree(ROOT / "policy", self.release / "policy")
        shutil.copytree(ROOT / "engine", self.release / "engine")
        shutil.copytree(ROOT / "adapters", self.release / "adapters")
        (self.release / "VERSION").write_text("1.0.0-test\n")

    def tearDown(self):
        self.temp.cleanup()

    def test_verified_release_entry_rejects_tampering(self):
        build_manifest(self.release)
        entry = verified_entry(self.release, "codex", expected_manifest_hash=manifest_digest(self.release))
        self.assertEqual((self.release / "adapters" / "codex.py").resolve(), entry)
        (self.release / "policy" / "policy.json").write_text("{}\n")
        with self.assertRaises(ValueError):
            verified_entry(self.release, "codex", expected_manifest_hash=manifest_digest(self.release))

    def test_verified_release_exposes_v2_codex_entry(self):
        build_manifest(self.release)
        entry = verified_entry(
            self.release,
            "codex_v2",
            expected_manifest_hash=manifest_digest(self.release),
        )
        self.assertEqual((self.release / "adapters" / "codex_v2.py").resolve(), entry)

    def test_doctor_reports_healthy_codex_wiring(self):
        build_manifest(self.release)
        digest = manifest_digest(self.release)
        config = Path(self.temp.name) / "config.toml"
        hooks = Path(self.temp.name) / "hooks.json"
        config.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        hooks.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": f"python3 /safe-yolo/bootstrap.py --release {self.release} --manifest-sha256 {digest} --entry codex"}]}]}}))
        report = inspect_codex_wiring(config, hooks, "/safe-yolo/bootstrap.py", digest)
        self.assertTrue(report["healthy"])

    def test_doctor_proves_v2_pretool_and_approval_posttool_wiring(self):
        build_manifest(self.release)
        digest = manifest_digest(self.release)
        config = Path(self.temp.name) / "config.toml"
        hooks = Path(self.temp.name) / "hooks.json"
        config.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        command = (
            f"python3 /safe-yolo/bootstrap.py --release {self.release} "
            f"--manifest-sha256 {digest} --entry codex_v2"
        )
        hook_config = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [{"type": "command", "command": command}],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": "request_user_input",
                        "hooks": [{"type": "command", "command": command}],
                    }
                ],
            }
        }
        hooks.write_text(json.dumps(hook_config))

        healthy = inspect_codex_wiring(
            config,
            hooks,
            "/safe-yolo/bootstrap.py",
            digest,
            entry="codex_v2",
            approval_post_tool=True,
        )
        del hook_config["hooks"]["PostToolUse"]
        hooks.write_text(json.dumps(hook_config))
        missing_posttool = inspect_codex_wiring(
            config,
            hooks,
            "/safe-yolo/bootstrap.py",
            digest,
            entry="codex_v2",
            approval_post_tool=True,
        )

        self.assertTrue(healthy["healthy"])
        self.assertFalse(missing_posttool["healthy"])
        self.assertIn(
            "exactly one request_user_input PostToolUse command hook is required",
            missing_posttool["problems"],
        )

    def test_doctor_cli_reports_v2_release_and_wiring_health(self):
        build_manifest(self.release)
        digest = manifest_digest(self.release)
        config = Path(self.temp.name) / "config.toml"
        hooks = Path(self.temp.name) / "hooks.json"
        config.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        command = (
            f"python3 /safe-yolo/bootstrap.py --release {self.release} "
            f"--manifest-sha256 {digest} --entry codex_v2"
        )
        hooks.write_text(
            json.dumps(
                {
                    "hooks": {
                        "PreToolUse": [
                            {
                                "matcher": "*",
                                "hooks": [{"type": "command", "command": command}],
                            }
                        ],
                        "PostToolUse": [
                            {
                                "matcher": "request_user_input",
                                "hooks": [{"type": "command", "command": command}],
                            }
                        ],
                    }
                }
            )
        )

        result = subprocess.run(
            (
                sys.executable,
                str(ROOT / "scripts" / "doctor.py"),
                "--release",
                str(self.release),
                "--manifest-sha256",
                digest,
                "--codex-config",
                str(config),
                "--codex-hooks",
                str(hooks),
                "--bootstrap",
                "/safe-yolo/bootstrap.py",
                "--entry",
                "codex_v2",
            ),
            text=True,
            capture_output=True,
            check=False,
        )
        report = json.loads(result.stdout)

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue(report["healthy"])
        self.assertTrue(report["codex_wiring"]["healthy"])

    def test_doctor_rejects_non_object_hooks_and_missing_wiring_hash(self):
        build_manifest(self.release)
        config = Path(self.temp.name) / "config.toml"
        hooks = Path(self.temp.name) / "hooks.json"
        config.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        hooks.write_text("[]")

        report = inspect_codex_wiring(
            config,
            hooks,
            "/safe-yolo/bootstrap.py",
            "0" * 64,
            entry="codex_v2",
            approval_post_tool=True,
        )
        result = subprocess.run(
            (
                sys.executable,
                str(ROOT / "scripts" / "doctor.py"),
                "--release",
                str(self.release),
                "--codex-config",
                str(config),
                "--codex-hooks",
                str(hooks),
                "--bootstrap",
                "/safe-yolo/bootstrap.py",
                "--entry",
                "codex_v2",
            ),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertFalse(report["healthy"])
        self.assertNotEqual(0, result.returncode)
        self.assertIn("--manifest-sha256 is required", result.stderr)

    def test_doctor_reports_manifest_and_required_entries(self):
        build_manifest(self.release)
        report = inspect_release(self.release)
        self.assertTrue(report["healthy"])
        self.assertEqual([], report["problems"])
        self.assertEqual("1.0.0-test", report["version"])

    def test_doctor_checks_every_present_cursor_hook_pin_and_entrypoint(self):
        digest = "a" * 64
        tool = Path(self.temp.name) / "safe-yolo-cursor.sh"
        prompt = Path(self.temp.name) / "safe-yolo-cursor-prompt.sh"
        tool.write_text(f"--manifest-sha256 {digest} --entry cursor\n")
        prompt.write_text(f"--manifest-sha256 {digest} --entry cursor_prompt\n")
        healthy = inspect_cursor_wiring((tool, prompt), digest)
        prompt.write_text(f"--manifest-sha256 {'b' * 64} --entry cursor_prompt\n")
        stale = inspect_cursor_wiring((tool, prompt), digest)
        self.assertTrue(healthy["healthy"])
        self.assertFalse(stale["healthy"])


if __name__ == "__main__":
    unittest.main()
