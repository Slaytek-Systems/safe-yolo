import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts.bootstrap import verified_entry
from scripts.doctor import inspect_codex_wiring, inspect_cursor_wiring, inspect_macos_asset_recovery, inspect_release
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

    def test_doctor_reports_healthy_codex_wiring(self):
        build_manifest(self.release)
        digest = manifest_digest(self.release)
        config = Path(self.temp.name) / "config.toml"
        hooks = Path(self.temp.name) / "hooks.json"
        config.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        hooks.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": f"python3 /safe-yolo/bootstrap.py --release {self.release} --manifest-sha256 {digest} --entry codex"}]}]}}))
        report = inspect_codex_wiring(config, hooks, "/safe-yolo/bootstrap.py", digest)
        self.assertTrue(report["healthy"])

    def test_doctor_reports_manifest_and_required_entries(self):
        build_manifest(self.release)
        report = inspect_release(self.release)
        self.assertTrue(report["healthy"])
        self.assertEqual([], report["problems"])
        self.assertEqual("1.0.0-test", report["version"])

    def test_doctor_reports_healthy_cursor_wiring(self):
        build_manifest(self.release)
        digest = manifest_digest(self.release)
        bootstrap = "/safe-yolo/bootstrap.py"
        hooks = Path(self.temp.name) / "cursor-hooks.json"
        hooks.write_text(json.dumps({
            "version": 1,
            "hooks": {
                event: [{
                    "command": f"python3 {bootstrap} --release {self.release} --manifest-sha256 {digest} --entry {entry}",
                    "failClosed": True,
                }]
                for event, entry in {
                    "beforeShellExecution": "cursor",
                    "beforeMCPExecution": "cursor",
                    "preToolUse": "cursor",
                    "beforeSubmitPrompt": "cursor_prompt",
                }.items()
            },
        }))
        report = inspect_cursor_wiring(hooks, bootstrap, digest)
        self.assertTrue(report["healthy"], report["problems"])

    def test_cursor_doctor_rejects_fail_open_hook(self):
        hooks = Path(self.temp.name) / "cursor-hooks.json"
        hooks.write_text(json.dumps({
            "version": 1,
            "hooks": {
                event: [{"command": "untrusted", "failClosed": False}]
                for event in ("beforeShellExecution", "beforeMCPExecution", "preToolUse", "beforeSubmitPrompt")
            },
        }))
        report = inspect_cursor_wiring(hooks, "/safe-yolo/bootstrap.py", "expected")
        self.assertFalse(report["healthy"])
        self.assertTrue(any("failClosed" in problem for problem in report["problems"]))

    def test_macos_asset_recovery_requires_a_completed_backup_and_private_state(self):
        safe_yolo_home = Path(self.temp.name) / "safe-yolo"
        for name in ("state", "backups", "releases"):
            directory = safe_yolo_home / name
            directory.mkdir(parents=True)
            os.chmod(directory, 0o700)

        outputs = iter((
            subprocess.CompletedProcess([], 0, "Name : Backup\n", ""),
            subprocess.CompletedProcess([], 0, "/Volumes/Backup/Backups.backupdb/latest\n", ""),
            subprocess.CompletedProcess([], 0, "Snapshots for volume group containing disk /:\n", ""),
        ))
        healthy = inspect_macos_asset_recovery(safe_yolo_home, run=lambda *_args, **_kwargs: next(outputs))
        self.assertTrue(healthy["healthy"], healthy["problems"])
        self.assertTrue(healthy["backup_destination_configured"])
        self.assertTrue(healthy["completed_backup_present"])

        outputs = iter((
            subprocess.CompletedProcess([], 0, "", "tmutil: No destinations configured.\n"),
            subprocess.CompletedProcess([], 1, "", "No backups found\n"),
            subprocess.CompletedProcess([], 0, "Snapshots for volume group containing disk /:\ncom.apple.os.update-example\n", ""),
        ))
        os.chmod(safe_yolo_home / "state", 0o755)
        unhealthy = inspect_macos_asset_recovery(safe_yolo_home, run=lambda *_args, **_kwargs: next(outputs))
        self.assertFalse(unhealthy["healthy"])
        self.assertFalse(unhealthy["backup_destination_configured"])
        self.assertFalse(unhealthy["completed_backup_present"])
        self.assertTrue(any("private" in problem for problem in unhealthy["problems"]))

    def test_control_terminal_reports_backup_gap_without_failing_host_health(self):
        safe_yolo_home = Path(self.temp.name) / "control-safe-yolo"
        for name in ("state", "backups", "releases"):
            directory = safe_yolo_home / name
            directory.mkdir(parents=True)
            os.chmod(directory, 0o700)
        outputs = iter((
            subprocess.CompletedProcess([], 0, "", "tmutil: No destinations configured.\n"),
            subprocess.CompletedProcess([], 1, "", "No backups found\n"),
            subprocess.CompletedProcess([], 0, "Snapshots for volume group containing disk /:\n", ""),
        ))
        report = inspect_macos_asset_recovery(
            safe_yolo_home,
            development_role="control_terminal",
            run=lambda *_args, **_kwargs: next(outputs),
        )
        self.assertTrue(report["healthy"], report["problems"])
        self.assertFalse(report["host_backup_ready"])
        self.assertEqual("control_terminal", report["development_role"])


if __name__ == "__main__":
    unittest.main()
