import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.global_cli import restore
from scripts.distribute import (
    deactivate_codex,
    deactivate_harness,
    doctor_codex,
    doctor_harness,
    harness_catalog,
    install_codex,
    install_harness,
)


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
        (self.source / "VERSION").write_text("3.0.0-beta.2\n")
        self.safe_yolo_home = self.root / ".safe-yolo"
        self.user_home = self.root / "home"
        self.user_home.mkdir()
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
        self.assertIn("/releases/3.0.0-beta.2/scripts/bootstrap.py", command)
        self.assertIn(f"--safe-yolo-home {self.safe_yolo_home}", command)
        self.assertIn(f"--harness-home {self.codex_home}", command)
        self.assertEqual(sha256(self.hooks), receipt["installed_hooks_sha256"])

    @patch("scripts.distribute.verify_source", return_value="8" * 40)
    def test_install_keeps_an_older_legacy_bootstrap_and_pins_the_release_copy(self, _verify):
        self.safe_yolo_home.mkdir()
        legacy_bootstrap = self.safe_yolo_home / "bootstrap.py"
        legacy_bootstrap.write_text("# beta.1 bootstrap\n")

        receipt = install_codex(
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
            expected_commit="8" * 40,
        )

        self.assertEqual("# beta.1 bootstrap\n", legacy_bootstrap.read_text())
        self.assertTrue(Path(receipt["bootstrap"]).is_file())
        command = json.loads(self.hooks.read_text())["hooks"]["PreToolUse"][0]["hooks"][0][
            "command"
        ]
        self.assertIn(str(receipt["bootstrap"]), command)

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

        self.hooks.write_text(json.dumps({"hooks": {"PreToolUse": {"command": "echo malformed"}}}))
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

    @patch("scripts.distribute.verify_source", return_value="9" * 40)
    def test_beta_one_codex_receipt_remains_doctorable_and_reversible(self, _verify):
        original = b'{"hooks":{"SessionStart":[]}}\n'
        self.hooks.write_bytes(original)
        install_codex(
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
            expected_commit="9" * 40,
        )
        generic = self.safe_yolo_home / "state" / "installations" / "codex.json"
        generic.rename(self.root / "hidden-generic-receipt.json")

        report = doctor_codex(
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
        )
        self.assertTrue(report["healthy"], report)
        result = deactivate_codex(
            safe_yolo_home=self.safe_yolo_home,
            codex_home=self.codex_home,
        )

        self.assertEqual("inactive", result["status"])
        self.assertEqual(original, self.hooks.read_bytes())

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
        self.assertIn("harnesses", completed.stdout)

    def test_catalog_distinguishes_lifecycle_support_from_adapter_availability(self):
        catalog = {item["id"]: item for item in harness_catalog(self.user_home)}

        self.assertEqual("supported", catalog["codex"]["status"])
        self.assertEqual("beta", catalog["claude-code"]["status"])
        self.assertEqual("beta", catalog["cursor"]["status"])
        self.assertEqual("beta", catalog["opencode"]["status"])
        self.assertTrue(catalog["opencode"]["lifecycle_supported"])
        self.assertEqual("adapter-only", catalog["grok"]["status"])
        self.assertFalse(catalog["grok"]["lifecycle_supported"])
        self.assertEqual(
            {"codex", "claude-code", "cursor", "grok", "opencode", "antigravity", "devin"},
            set(catalog),
        )

    @patch("scripts.distribute.verify_source", return_value="f" * 40)
    def test_claude_code_install_doctor_and_deactivate_preserve_settings(self, _verify):
        claude = self.user_home / ".claude"
        claude.mkdir()
        settings = claude / "settings.json"
        original = {"model": "claude-sonnet", "env": {"SAFE": "yes"}}
        settings.write_text(json.dumps(original, indent=2) + "\n")
        original_bytes = settings.read_bytes()

        receipt = install_harness(
            harness="claude-code",
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            user_home=self.user_home,
            expected_commit="f" * 40,
        )

        self.assertEqual("claude-code", receipt["harness"])
        self.assertEqual({"allow": True, "deny": True}, receipt["canaries"])
        active = json.loads(settings.read_text())
        self.assertEqual("claude-sonnet", active["model"])
        self.assertEqual({"SAFE": "yes"}, active["env"])
        command = active["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertIn("--entry claude_code_v3", command)
        self.assertTrue(
            (self.safe_yolo_home / "state" / "installations" / "claude-code.json").is_file()
        )

        report = doctor_harness(
            harness="claude-code",
            safe_yolo_home=self.safe_yolo_home,
            user_home=self.user_home,
        )
        self.assertTrue(report["healthy"], report)
        result = deactivate_harness(
            harness="claude-code",
            safe_yolo_home=self.safe_yolo_home,
            user_home=self.user_home,
        )
        self.assertEqual("inactive", result["status"])
        self.assertEqual(original_bytes, settings.read_bytes())

    def claude(self, version=None):
        if version:
            (self.source / "VERSION").write_text(version + "\n")
        return install_harness(
            harness="claude-code",
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            user_home=self.user_home,
            expected_commit="f" * 40,
        )

    def claude_settings(self, document=None, mode=None):
        settings = self.user_home / ".claude" / "settings.json"
        settings.parent.mkdir(exist_ok=True)
        if document is not None:
            settings.write_text(json.dumps(document) + "\n")
        if mode is not None:
            settings.chmod(mode)
        return settings

    def claude_doctor(self):
        return doctor_harness(harness="claude-code", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home)

    def claude_uninstall(self):
        return restore(self.safe_yolo_home, self.user_home, "claude-code", uninstall=True)

    @patch("scripts.distribute.verify_source", return_value="f" * 40)
    def test_claude_code_install_appends_its_hook_and_uninstall_restores_the_others(self, _verify):
        before = [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo other"}]},
            {"matcher": "*", "hooks": [
                {"type": "command", "command": "python3 /opt/tool/bin/bootstrap.py --release /opt/tool/releases/1 "
                                               "--manifest-sha256 x --entry codex"},
                {"type": "http", "url": "https://example.invalid/hook"},
            ]},
            {"matcher": "Bash", "hooks": []},
        ]
        settings = self.claude_settings({"model": "kept", "hooks": {"PreToolUse": before}}, mode=0o644)
        original_bytes = settings.read_bytes()

        self.claude()

        groups = json.loads(settings.read_text())["hooks"]["PreToolUse"]
        self.assertEqual(before, groups[:3])
        self.assertEqual("*", groups[3]["matcher"])
        self.assertIn("--entry claude_code_v3", groups[3]["hooks"][0]["command"])
        self.assertTrue(self.claude_doctor()["healthy"])
        settings.chmod(0o600)
        self.claude_uninstall()
        self.assertEqual(original_bytes, settings.read_bytes())
        self.assertEqual(0o600, settings.stat().st_mode & 0o777)

    @patch("scripts.distribute.verify_source", return_value="f" * 40)
    def test_claude_code_update_replaces_its_hook_in_place_beside_hooks_added_since(self, _verify):
        settings = self.claude_settings({"model": "kept"})
        self.claude()
        document = json.loads(settings.read_text())
        sibling = {"type": "command", "command": "echo sibling"}
        later = {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo later"}]}
        document["hooks"]["PreToolUse"][0]["hooks"].append(sibling)
        document["hooks"]["PreToolUse"].append(later)
        settings.write_text(json.dumps(document))

        self.claude("3.0.0-beta.3")

        groups = json.loads(settings.read_text())["hooks"]["PreToolUse"]
        self.assertEqual(2, len(groups))
        self.assertIn("/releases/3.0.0-beta.3/", groups[0]["hooks"][0]["command"])
        self.assertEqual(sibling, groups[0]["hooks"][1])
        self.assertEqual(later, groups[1])
        report = self.claude_doctor()
        self.assertTrue(report["healthy"], report)
        self.assertEqual("3.0.0-beta.3", report["version"])

        self.claude_uninstall()

        self.assertEqual(
            {"model": "kept", "hooks": {"PreToolUse": [{"matcher": "*", "hooks": [sibling]}, later]}},
            json.loads(settings.read_text()),
        )

    @patch("scripts.distribute.verify_source", return_value="f" * 40)
    def test_claude_code_uninstall_refuses_when_the_file_is_saved_while_it_stages_the_new_one(self, _verify):
        settings = self.claude_settings({"model": "kept"})
        self.claude()
        newer = b'{"model": "changed"}\n'
        real_fsync = os.fsync
        saved = []

        def save_once(descriptor):
            if not saved:
                saved.append(True)
                settings.write_bytes(newer)
            real_fsync(descriptor)

        with patch("scripts.global_cli.os.fsync", side_effect=save_once):
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite newer work"):
                self.claude_uninstall()
        self.assertEqual(newer, settings.read_bytes())
        self.assertEqual(["settings.json"], [path.name for path in settings.parent.iterdir()])

    @patch("scripts.distribute.verify_source", return_value="f" * 40)
    def test_claude_code_install_refuses_a_safe_yolo_hook_it_did_not_write(self, _verify):
        elsewhere = (
            "/usr/bin/python3 /srv/other/.safe-yolo/releases/9/scripts/bootstrap.py --release "
            "/srv/other/.safe-yolo/releases/9 --manifest-sha256 abc --entry claude_code_v3 "
            "--state-dir /srv/other/state"
        )
        legacy_elsewhere = elsewhere.replace("/releases/9/scripts/bootstrap.py", "/bootstrap.py")
        for hook in (
            {"type": "command", "command": elsewhere},
            {"type": "command", "command": legacy_elsewhere},
            {"type": "command", "command": "/usr/bin/python3", "args": elsewhere.split()[1:]},
            {"type": "command", "command": "/opt/my tools/python3", "args": elsewhere.split()[1:]},
        ):
            with self.subTest(hook=hook):
                settings = self.claude_settings({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [hook]}]}})
                original_bytes = settings.read_bytes()
                with self.assertRaisesRegex(RuntimeError, "existing PreToolUse"):
                    self.claude()
                self.assertEqual(original_bytes, settings.read_bytes())

    @patch("scripts.distribute.verify_source", return_value="f" * 40)
    def test_claude_code_doctor_reports_a_second_safe_yolo_pretool_hook(self, _verify):
        settings = self.claude_settings({"model": "kept"})
        self.claude()
        own = json.loads(settings.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]
        arguments = shlex.split(own["command"])[1:]
        for extra in (
            dict(own),
            {"type": "command", "command": "/usr/bin/python3", "args": arguments},
            {"type": "command", "command": "/opt/my tools/python3", "args": arguments},
        ):
            with self.subTest(extra=extra):
                document = json.loads(settings.read_text())
                document["hooks"]["PreToolUse"] = [{"matcher": "*", "hooks": [own]}, {"matcher": "*", "hooks": [extra]}]
                settings.write_text(json.dumps(document))
                self.assertIn(
                    "exactly one Safe YOLO PreToolUse command hook is required", self.claude_doctor()["problems"]
                )

    @patch("scripts.distribute.verify_source", return_value="b" * 40)
    def test_codex_update_accepts_a_receipt_older_than_the_release_bootstrap(self, _verify):
        def install():
            return install_codex(
                source=self.source,
                safe_yolo_home=self.safe_yolo_home,
                codex_home=self.codex_home,
                expected_commit="b" * 40,
            )

        install()
        receipt_path = self.safe_yolo_home / "state" / "installations" / "codex.json"
        receipt = json.loads(receipt_path.read_text())
        legacy = (
            f"/usr/bin/python3 {self.safe_yolo_home / 'bootstrap.py'} --release {receipt['release']} "
            f"--manifest-sha256 {receipt['manifest_sha256']} --entry codex_v3 "
            f"--state-dir {self.safe_yolo_home / 'state'}"
        )
        document = json.loads(self.hooks.read_text())
        document["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = legacy
        document["description"] = "mine"
        self.hooks.write_text(json.dumps(document))
        for key in ("bootstrap", "user_home", "harness_home"):
            receipt.pop(key)
        receipt_path.write_text(json.dumps(receipt))
        (self.source / "VERSION").write_text("3.0.0-beta.3\n")

        install()

        updated = json.loads(self.hooks.read_text())
        self.assertIn("/releases/3.0.0-beta.3/scripts/bootstrap.py", updated["hooks"]["PreToolUse"][0]["hooks"][0]["command"])
        self.assertEqual("mine", updated["description"])

    @patch("scripts.distribute.verify_source", return_value="1" * 40)
    def test_cursor_install_doctor_and_deactivate_use_native_permission_hook(self, _verify):
        cursor = self.user_home / ".cursor"
        cursor.mkdir()
        hooks = cursor / "hooks.json"
        original = {"version": 1, "hooks": {"sessionStart": [{"command": "echo ready"}]}}
        hooks.write_text(json.dumps(original, indent=2) + "\n")
        original_bytes = hooks.read_bytes()

        receipt = install_harness(
            harness="cursor",
            source=self.source,
            safe_yolo_home=self.safe_yolo_home,
            user_home=self.user_home,
            expected_commit="1" * 40,
        )

        self.assertEqual({"allow": True, "deny": True}, receipt["canaries"])
        active = json.loads(hooks.read_text())
        self.assertEqual(original["hooks"]["sessionStart"], active["hooks"]["sessionStart"])
        hook = active["hooks"]["preToolUse"][0]
        self.assertEqual("*", hook["matcher"])
        self.assertTrue(hook["failClosed"])
        self.assertIn("--entry cursor_v3", hook["command"])
        self.assertIn(f"--safe-yolo-home {self.safe_yolo_home}", hook["command"])
        self.assertIn(f"--harness-home {cursor}", hook["command"])
        self.assertIn(f"--user-home {self.user_home}", hook["command"])
        protected_write = subprocess.run(
            shlex.split(hook["command"]),
            input=json.dumps(
                {
                    "hook_event_name": "preToolUse",
                    "tool_name": "Write",
                    "tool_input": {"file_path": str(hooks)},
                }
            ),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, protected_write.returncode, protected_write.stderr)
        self.assertEqual("deny", json.loads(protected_write.stdout)["permission"])

        report = doctor_harness(
            harness="cursor",
            safe_yolo_home=self.safe_yolo_home,
            user_home=self.user_home,
        )
        self.assertTrue(report["healthy"], report)
        deactivate_harness(
            harness="cursor",
            safe_yolo_home=self.safe_yolo_home,
            user_home=self.user_home,
        )
        self.assertEqual(original_bytes, hooks.read_bytes())

    def test_adapter_only_harness_refuses_lifecycle_commands_honestly(self):
        with self.assertRaisesRegex(RuntimeError, "adapter-only"):
            doctor_harness(
                harness="grok",
                safe_yolo_home=self.safe_yolo_home,
                user_home=self.user_home,
            )


if __name__ == "__main__":
    unittest.main()
