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
import zipfile

from scripts.distribute import deactivate_harness, doctor_harness, install_harness
from scripts.global_cli import restore
from scripts.package import MANIFEST, build_bundle, digest


ROOT = Path(__file__).resolve().parents[2]
HERDR = {"PreInvocation": [{"type": "command", "command": "herdr agent-state --event pre-invocation"}]}
OTHER_FILE = json.dumps({"herdr": HERDR}, indent=4) + "\n"


def owned_group(command: str) -> dict:
    return {
        "enabled": True,
        "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 10}]}],
    }


class AntigravityLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.source.mkdir()
        for name in ("policy", "engine", "adapters"):
            shutil.copytree(ROOT / name, self.source / name)
        (self.source / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts" / "bootstrap.py", self.source / "scripts" / "bootstrap.py")
        (self.source / "VERSION").write_text("3.0.0-beta.2\n")
        self.safe_yolo_home = self.root / ".safe-yolo"
        self.user_home = self.root / "home"
        self.gemini = self.user_home / ".gemini"
        self.hooks = self.gemini / "config" / "hooks.json"
        self.hooks.parent.mkdir(parents=True)
        self.hooks.write_text(OTHER_FILE)
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        os.environ.pop("GEMINI_HOME", None)

    def install(self, **options):
        with patch("scripts.distribute.verify_source", return_value="e" * 40):
            return install_harness(
                harness="antigravity",
                source=self.source,
                safe_yolo_home=self.safe_yolo_home,
                user_home=self.user_home,
                expected_commit="e" * 40,
                **options,
            )

    def doctor(self):
        return doctor_harness(harness="antigravity", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home)

    def receipt_path(self):
        return self.safe_yolo_home / "state" / "installations" / "antigravity.json"

    def installed_command(self, receipt: dict, root: Path | None = None) -> str:
        release = Path(receipt["release"])
        return shlex.join([
            sys.executable, str(release / "scripts" / "bootstrap.py"),
            "--release", str(release),
            "--manifest-sha256", receipt["manifest_sha256"],
            "--entry", "antigravity_v3",
            "--state-dir", str(self.safe_yolo_home / "state"),
            "--safe-yolo-home", str(self.safe_yolo_home),
            "--user-home", str(self.user_home),
            "--harness-home", str(root or self.gemini),
        ])

    def hand_wired(self, release_name: str = "3.0.0-alpha.8", bootstrap: Path | None = None) -> dict:
        release = self.safe_yolo_home / "releases" / release_name
        return owned_group(shlex.join([
            "/usr/bin/python3", str(bootstrap or release / "scripts" / "bootstrap.py"),
            "--release", str(release),
            "--manifest-sha256", "f" * 64,
            "--entry", "antigravity_v3",
            "--state-dir", str(self.safe_yolo_home / "state"),
        ]))

    def reply(self, command: str, tool: str, args: dict) -> tuple[int, dict | None, str]:
        payload = {"toolCall": {"name": tool, "args": args}, "stepIdx": 0, "conversationId": "c",
                   "workspacePaths": [str(self.root)]}
        completed = subprocess.run(shlex.split(command), input=json.dumps(payload), text=True,
                                   capture_output=True, check=False)
        try:
            decoded = json.loads(completed.stdout)
        except json.JSONDecodeError:
            decoded = None
        return completed.returncode, decoded, completed.stderr

    def test_install_adds_one_named_group_and_keeps_the_others(self):
        receipt = self.install()

        document = json.loads(self.hooks.read_text())
        self.assertEqual(["herdr", "safe-yolo"], list(document))
        self.assertEqual(HERDR, document["herdr"])
        self.assertEqual(owned_group(self.installed_command(receipt)), document["safe-yolo"])
        self.assertEqual(str(self.hooks), receipt["config_path"])
        self.assertEqual(str(self.gemini), receipt["harness_home"])
        self.assertEqual({"allow": True, "deny": True}, receipt["canaries"])
        self.assertIn("/hooks", receipt["next_action"])
        self.assertTrue(self.doctor()["healthy"], self.doctor())

    def test_pinned_command_replies_allow_and_deny_with_exit_zero(self):
        receipt = self.install()
        command = json.loads(self.hooks.read_text())["safe-yolo"]["PreToolUse"][0]["hooks"][0]["command"]

        self.assertEqual((0, {"decision": "allow"}), self.reply(command, "run_command", {"CommandLine": "git status"})[:2])
        code, denied, _ = self.reply(command, "run_command", {"CommandLine": "git push --force origin main"})
        self.assertEqual(0, code)
        self.assertEqual("deny", denied["decision"])
        self.assertIn("git.history_mutation", denied["reason"])
        self.assertTrue(Path(receipt["release"]).is_dir())

    def test_bootstrap_failures_reply_deny_with_exit_zero(self):
        receipt = self.install()
        command = self.installed_command(receipt)
        release = Path(receipt["release"])

        crash_dir = self.root / "crash"
        crash_dir.mkdir()
        (crash_dir / "sitecustomize.py").write_text(
            "import os\n"
            f"if os.environ.get('PYTHONPATH', '').startswith({str(release)!r}):\n"
            "    os._exit(3)\n"
        )
        with patch.dict(os.environ, {"PYTHONPATH": str(crash_dir)}):
            code, crashed, _ = self.reply(command, "run_command", {"CommandLine": "git status"})
        self.assertEqual(0, code)
        self.assertEqual("deny", crashed["decision"])
        self.assertIn("adapter", crashed["reason"])

        (release / "adapters" / "antigravity_v3.py").chmod(0o644)
        with (release / "adapters" / "antigravity_v3.py").open("a") as handle:
            handle.write("\n")
        code, tampered, _ = self.reply(command, "run_command", {"CommandLine": "git status"})
        self.assertEqual(0, code)
        self.assertEqual("deny", tampered["decision"])
        self.assertIn("release verification failed", tampered["reason"])

        missing = command.replace(f"--release {release}", f"--release {release}-missing")
        code, absent, _ = self.reply(missing, "run_command", {"CommandLine": "git status"})
        self.assertEqual(0, code)
        self.assertEqual("deny", absent["decision"])
        self.assertIn("manifest", absent["reason"])

    def test_other_entries_still_exit_two_on_integrity_failure(self):
        receipt = self.install()
        release = Path(receipt["release"])
        completed = subprocess.run(
            [sys.executable, str(release / "scripts" / "bootstrap.py"), "--release", str(release),
             "--manifest-sha256", "0" * 64, "--entry", "claude_code_v3", "--state-dir", str(self.root / "s")],
            input="{}", text=True, capture_output=True, check=False)
        self.assertEqual(2, completed.returncode)
        self.assertEqual("", completed.stdout)

    def test_root_is_config_home_else_default_and_ignores_gemini_home(self):
        profile = self.root / "t3-profile"
        os.environ["GEMINI_HOME"] = str(profile)
        receipt = self.install()
        self.assertEqual(str(self.hooks), receipt["config_path"])
        self.assertEqual(owned_group(self.installed_command(receipt)),
                         json.loads(self.hooks.read_text())["safe-yolo"])
        self.assertFalse(profile.exists())
        restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=True)

        chosen = self.root / "chosen"
        receipt = self.install(config_home=chosen)
        self.assertEqual(str(chosen / "config" / "hooks.json"), receipt["config_path"])
        code, denied, _ = self.reply(self.installed_command(receipt, chosen), "edit_file",
                                     {"AbsolutePath": str(chosen / "config" / "hooks.json")})
        self.assertEqual(0, code)
        self.assertEqual("deny", denied["decision"])
        self.assertIn("enforcement.modify", denied["reason"])

    def test_a_second_root_under_the_same_home_is_refused(self):
        self.install()
        with self.assertRaisesRegex(RuntimeError, "is wired to"):
            self.install(config_home=self.root / "t3-profile")
        self.assertFalse((self.root / "t3-profile").exists())

    def test_a_foreign_safe_yolo_group_is_refused_untouched(self):
        cases = {
            "other command": owned_group("/usr/bin/python3 /opt/elsewhere/guard.py"),
            "unknown release": self.hand_wired("3.0.0-alpha.0"),
            "string timeout": {**self.hand_wired(), "PreToolUse": [{"matcher": "*", "hooks": [
                {**self.hand_wired()["PreToolUse"][0]["hooks"][0], "timeout": "10"}]}]},
            "disabled": {**self.hand_wired(), "enabled": False},
            "extra field": {**self.hand_wired(), "note": "mine"},
            "narrow matcher": {**self.hand_wired(), "PreToolUse": [
                {**self.hand_wired()["PreToolUse"][0], "matcher": "run_command"}]},
        }
        (self.safe_yolo_home / "releases" / "3.0.0-alpha.8").mkdir(parents=True)
        for name, group in cases.items():
            with self.subTest(name):
                original = json.dumps({"herdr": HERDR, "safe-yolo": group}) + "\n"
                self.hooks.write_text(original)
                with self.assertRaisesRegex(RuntimeError, "safe-yolo"):
                    self.install()
                self.assertEqual(original, self.hooks.read_text())
                self.assertFalse(self.receipt_path().exists())

    def test_hand_wired_group_through_the_shared_bootstrap_is_replaced(self):
        (self.safe_yolo_home / "releases" / "3.0.0-alpha.8").mkdir(parents=True)
        hand_wired = self.hand_wired(bootstrap=self.safe_yolo_home / "bootstrap.py")
        self.hooks.write_text(json.dumps({"herdr": HERDR, "safe-yolo": hand_wired}))

        receipt = self.install()

        self.assertEqual(owned_group(self.installed_command(receipt)), json.loads(self.hooks.read_text())["safe-yolo"])

    def test_hand_wired_group_of_an_installed_release_is_backed_up_and_replaced(self):
        (self.safe_yolo_home / "releases" / "3.0.0-alpha.8").mkdir(parents=True)
        original = json.dumps({"safe-yolo": self.hand_wired(), "herdr": HERDR}, indent=2) + "\n"
        self.hooks.write_text(original)

        receipt = self.install()

        self.assertEqual(original, Path(receipt["previous_config_backup"]).read_text())
        document = json.loads(self.hooks.read_text())
        self.assertEqual(["safe-yolo", "herdr"], list(document))
        self.assertEqual(owned_group(self.installed_command(receipt)), document["safe-yolo"])
        self.assertEqual(HERDR, document["herdr"])

        restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=True)
        self.assertEqual({"herdr": HERDR}, json.loads(self.hooks.read_text()))

    def test_doctor_requires_the_exact_group_once(self):
        receipt = self.install()
        group = owned_group(self.installed_command(receipt))
        variants = {
            "disabled": {**group, "enabled": False},
            "float timeout": {**group, "PreToolUse": [{"matcher": "*", "hooks": [
                {**group["PreToolUse"][0]["hooks"][0], "timeout": 10.0}]}]},
            "other entry": owned_group(self.installed_command(receipt).replace("antigravity_v3", "codex_v3")),
            "reordered flags": owned_group(self.installed_command(receipt).replace(
                f"--entry antigravity_v3 --state-dir {self.safe_yolo_home / 'state'}",
                f"--state-dir {self.safe_yolo_home / 'state'} --entry antigravity_v3")),
        }
        for name, edited in variants.items():
            with self.subTest(name):
                self.hooks.write_text(json.dumps({"herdr": HERDR, "safe-yolo": edited}))
                report = self.doctor()
                self.assertFalse(report["healthy"])
                self.assertIn("Antigravity safe-yolo hook group is not the one Safe YOLO installed",
                              report["problems"])
        once = json.dumps({"safe-yolo": group})
        self.hooks.write_text(once[:-1] + ", " + once[1:])
        self.assertFalse(self.doctor()["healthy"])

    def test_uninstall_and_deactivate_keep_other_groups(self):
        self.install()
        restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=True)
        self.assertEqual(OTHER_FILE, self.hooks.read_text())

        self.install()
        deactivate_harness(harness="antigravity", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home)
        self.assertEqual(OTHER_FILE, self.hooks.read_text())

    def test_uninstall_without_a_previous_file_removes_it(self):
        self.hooks.unlink()
        self.install()
        restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=True)
        self.assertFalse(self.hooks.exists())


class AntigravityGlobalLifecycleTests(unittest.TestCase):
    @patch("scripts.package.verify_source", return_value="a" * 40)
    def test_update_rollback_and_uninstall_keep_other_groups(self, _verify):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = build_bundle(ROOT, root / "downloads", "a" * 40)
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(root / "first")
                bundle.extractall(root / "second")
            first = next((root / "first").iterdir())
            second = next((root / "second").iterdir())
            (second / "VERSION").write_text("3.0.0-beta.999\n")
            manifest = json.loads((second / MANIFEST).read_text())
            manifest["version"] = "3.0.0-beta.999"
            manifest["files"]["VERSION"] = digest((second / "VERSION").read_bytes())
            (second / MANIFEST).write_text(json.dumps(manifest))
            user = root / "user"
            home = root / "runtime"
            hooks = user / ".gemini/config/hooks.json"
            hooks.parent.mkdir(parents=True)
            hooks.write_text(OTHER_FILE)
            environment = {key: value for key, value in os.environ.items() if key != "GEMINI_HOME"}

            def run(command, *args):
                result = subprocess.run([*command, *args], capture_output=True, text=True, env=environment)
                self.assertEqual(0, result.returncode, result.stderr)
                return json.loads(result.stdout)

            run([sys.executable, str(first / "safe-yolo"), "--home", str(home), "--user-home", str(user)],
                "install", "--harness", "antigravity")
            launcher = [str(user / ".local/bin/safe-yolo")]
            first_version = (first / "VERSION").read_text().strip()
            environment["GEMINI_HOME"] = str(root / "another-root")
            run(launcher, "update", "--source", str(second))
            self.assertFalse((root / "another-root").exists())
            report = run(launcher, "doctor")
            self.assertTrue(report["healthy"], report)
            self.assertEqual("3.0.0-beta.999", report["reports"][0]["version"])
            self.assertIn("releases/3.0.0-beta.999/", json.dumps(json.loads(hooks.read_text())["safe-yolo"]))
            run(launcher, "rollback")
            self.assertEqual(first_version, run(launcher, "doctor")["reports"][0]["version"])
            run(launcher, "uninstall")

            self.assertEqual(OTHER_FILE, hooks.read_text())


if __name__ == "__main__":
    unittest.main()
