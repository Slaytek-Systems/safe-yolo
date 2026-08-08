import json
from pathlib import Path
import shutil
import tempfile
import unittest

from scripts.bootstrap import verified_entry
from scripts.doctor import inspect_codex_wiring, inspect_release
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


if __name__ == "__main__":
    unittest.main()
