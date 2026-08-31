import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.bootstrap import verified_entry
from scripts.doctor import inspect_codex_wiring
from scripts.install import install_release
from scripts.release_manifest import build_manifest, manifest_digest


ROOT = Path(__file__).resolve().parents[2]


class V3ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.release = Path(self.temp.name) / "release"
        self.release.mkdir()
        for name in ("policy", "engine", "adapters"):
            shutil.copytree(ROOT / name, self.release / name)
        shutil.copy2(ROOT / "VERSION", self.release / "VERSION")

    def tearDown(self):
        self.temp.cleanup()

    def test_manifest_and_bootstrap_expose_deny_only_entry(self):
        build_manifest(self.release)
        entry = verified_entry(
            self.release,
            "codex_v3",
            expected_manifest_hash=manifest_digest(self.release),
        )

        self.assertEqual((self.release / "adapters" / "codex_v3.py").resolve(), entry)

    def test_doctor_requires_pretool_only_and_rejects_approval_hook(self):
        build_manifest(self.release)
        digest = manifest_digest(self.release)
        config = Path(self.temp.name) / "config.toml"
        hooks = Path(self.temp.name) / "hooks.json"
        config.write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        command = (
            f"python3 /safe-yolo/bootstrap.py --release {self.release} "
            f"--manifest-sha256 {digest} --entry codex_v3"
        )
        document = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [{"type": "command", "command": command}],
                    }
                ]
            }
        }
        hooks.write_text(json.dumps(document))

        healthy = inspect_codex_wiring(
            config,
            hooks,
            "/safe-yolo/bootstrap.py",
            digest,
            release_path=self.release,
            entry="codex_v3",
        )
        document["hooks"]["PostToolUse"] = [
            {
                "matcher": "request_user_input",
                "hooks": [{"type": "command", "command": command}],
            }
        ]
        hooks.write_text(json.dumps(document))
        stale = inspect_codex_wiring(
            config,
            hooks,
            "/safe-yolo/bootstrap.py",
            digest,
            release_path=self.release,
            entry="codex_v3",
        )

        self.assertTrue(healthy["healthy"], healthy)
        self.assertFalse(stale["healthy"], stale)
        self.assertIn(
            "request_user_input PostToolUse hook must be absent for codex_v3",
            stale["problems"],
        )

    def test_candidate_hook_has_no_posttool_approval_path(self):
        candidate = json.loads(
            (ROOT / "hosts" / "linux" / "devbox.v3-candidate.hooks.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertEqual({"PreToolUse"}, set(candidate["hooks"]))
        pretool = candidate["hooks"]["PreToolUse"][0]
        self.assertEqual("*", pretool["matcher"])
        self.assertIn("--entry codex_v3", pretool["hooks"][0]["command"])

    def test_installed_release_executes_deny_only_entry(self):
        installed = install_release(ROOT, Path(self.temp.name) / "installed")
        command = [
            sys.executable,
            str(installed["bootstrap"]),
            "--release",
            str(installed["release"]),
            "--manifest-sha256",
            str(installed["manifest_sha256"]),
            "--entry",
            "codex_v3",
            "--state-dir",
            str(Path(self.temp.name) / "unused-state"),
        ]
        action = {
            "hook_event_name": "PreToolUse",
            "cwd": "/workspace",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "rm obsolete.txt"},
        }

        result = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(action),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, result.returncode, result.stderr)
        denial = json.loads(result.stdout)
        self.assertEqual(
            "deny",
            denial["hookSpecificOutput"]["permissionDecision"],
        )
        self.assertNotIn(
            "approval",
            denial["hookSpecificOutput"]["permissionDecisionReason"].lower(),
        )
        self.assertFalse((Path(self.temp.name) / "unused-state").exists())


if __name__ == "__main__":
    unittest.main()
