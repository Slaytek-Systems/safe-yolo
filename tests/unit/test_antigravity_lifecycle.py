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
import zipfile

from scripts.distribute import deactivate_harness, doctor_harness, install_harness
from scripts.global_cli import restore
from scripts.install import install_release
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

    def hand_wired(self, release_name: str = "3.0.0-alpha.8", bootstrap: Path | None = None,
                   manifest: str = "f" * 64) -> dict:
        release = self.safe_yolo_home / "releases" / release_name
        return owned_group(shlex.join([
            "/usr/bin/python3", str(bootstrap or release / "scripts" / "bootstrap.py"),
            "--release", str(release),
            "--manifest-sha256", manifest,
            "--entry", "antigravity_v3",
            "--state-dir", str(self.safe_yolo_home / "state"),
        ]))

    def legacy_release(self) -> dict:
        legacy = self.root / "legacy-source"
        shutil.copytree(self.source, legacy)
        (legacy / "VERSION").write_text("3.0.0-alpha.8\n")
        return install_release(legacy, self.safe_yolo_home)

    def legacy_without_antigravity(self, entrypoints: dict) -> str:
        manifest = Path(self.legacy_release()["release"]) / "manifest.json"
        manifest.chmod(0o600)
        manifest.write_text(json.dumps({**json.loads(manifest.read_text()), "entrypoints": entrypoints}))
        return hashlib.sha256(manifest.read_bytes()).hexdigest()

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

    def bootstrap(self, release: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(release / "scripts" / "bootstrap.py"), *args],
                              input="{}", text=True, capture_output=True, check=False)

    def test_argument_and_manifest_shape_failures_reply_deny_with_exit_zero(self):
        release = Path(self.install()["release"])
        state = str(self.root / "s")
        broken = self.root / "null-entrypoints"
        shutil.copytree(release, broken)
        manifest = broken / "manifest.json"
        manifest.chmod(0o600)
        manifest.write_text(json.dumps({**json.loads(manifest.read_text()), "entrypoints": None}))
        pin = hashlib.sha256(manifest.read_bytes()).hexdigest()
        cases = {
            "missing manifest pin": ["--release", str(release), "--entry", "antigravity_v3", "--state-dir", state],
            "entry spelled with =": ["--release", str(release), "--entry=antigravity_v3", "--state-dir", state],
            "null entrypoints": ["--release", str(broken), "--manifest-sha256", pin, "--entry", "antigravity_v3",
                                 "--state-dir", state],
        }
        for name, args in cases.items():
            with self.subTest(name):
                completed = self.bootstrap(release, *args)
                self.assertEqual(0, completed.returncode, completed.stderr)
                self.assertEqual("deny", json.loads(completed.stdout)["decision"])

    def test_antigravity_help_writes_only_a_deny_to_stdout(self):
        release = Path(self.install()["release"])
        for args in (["--entry", "antigravity_v3", "--help"], ["--entry=antigravity_v3", "-h"]):
            with self.subTest(args):
                completed = self.bootstrap(release, *args)
                self.assertEqual(0, completed.returncode)
                self.assertEqual("deny", json.loads(completed.stdout)["decision"])
                self.assertIn("usage:", completed.stderr)

    def test_another_flag_valued_antigravity_v3_keeps_the_base_contract(self):
        release = Path(self.install()["release"])
        for entry in ("codex_v3", "claude_code_v3", "cursor_v3", "opencode_v3"):
            with self.subTest(entry):
                missing_pin = self.bootstrap(release, "--release", str(release), "--entry", entry,
                                             "--state-dir", "antigravity_v3")
                self.assertEqual((2, ""), (missing_pin.returncode, missing_pin.stdout))
                self.assertTrue(missing_pin.stderr.startswith("usage: bootstrap.py"), missing_pin.stderr)
                self.assertTrue(missing_pin.stderr.endswith(
                    "bootstrap.py: error: the following arguments are required: --manifest-sha256\n"))
                mismatch = self.bootstrap(release, "--release", "antigravity_v3", "--manifest-sha256", "abc",
                                          "--entry", entry, "--state-dir", str(self.root / "s"))
                self.assertEqual((2, "", "Safe YOLO fail-closed: manifest hash mismatch\n"),
                                 (mismatch.returncode, mismatch.stdout, mismatch.stderr))

    def test_other_entries_keep_their_exit_codes(self):
        receipt = self.install()
        release = Path(receipt["release"])
        state = str(self.root / "s")
        missing_pin = self.bootstrap(release, "--release", str(release), "--entry", "codex_v3", "--state-dir", state)
        self.assertEqual((2, ""), (missing_pin.returncode, missing_pin.stdout))

        unreadable = self.root / "unreadable"
        shutil.copytree(release, unreadable)
        (unreadable / "manifest.json").chmod(0)
        if os.access(unreadable / "manifest.json", os.R_OK):
            self.skipTest("running with permission to read any file")
        completed = self.bootstrap(release, "--release", str(unreadable), "--manifest-sha256",
                                   receipt["manifest_sha256"], "--entry", "codex_v3", "--state-dir", state)
        self.assertEqual((1, ""), (completed.returncode, completed.stdout))

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

    def test_a_file_safe_yolo_cannot_rewrite_exactly_is_refused_untouched(self):
        cases = {
            "overflowing number": '{"herdr": {"metadata": 1e400, "PreInvocation": []}}\n',
            "NaN": '{"herdr": {"metadata": NaN}}\n',
            "duplicate group": '{"herdr": {"a": 1}, "herdr": {"b": 2}}\n',
            "duplicate field in another group": '{"herdr": {"a": 1, "a": 2}}\n',
            "underflowing number": '{"herdr": {"metadata": 1e-400}}\n',
            "more digits than a float keeps": '{"herdr": {"metadata": 0.1234567890123456789}}\n',
            "negative zero integer": '{"herdr": {"metadata": -0}}\n',
            "exponent spelling": '{"herdr": {"metadata": 1E5}}\n',
            "redundant exponent": '{"herdr": {"metadata": 1.0e2}}\n',
            "trailing zero": '{"herdr": {"metadata": 1.50}}\n',
            "-Infinity": '{"herdr": {"metadata": -Infinity}}\n',
        }
        for name, text in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.safe_yolo_home, ignore_errors=True)
                self.hooks.write_text(text)
                with self.assertRaisesRegex(RuntimeError, "hooks file"):
                    self.install()
                self.assertEqual(text, self.hooks.read_text())
                self.assertFalse(self.receipt_path().exists())

    def test_numbers_that_write_back_exactly_are_kept(self):
        text = '{"herdr": {"a": 0.1, "b": -0.0, "c": 12345678901234567890123, "d": 1e+300, "e": 7}}'
        self.hooks.write_text(text)
        self.install()
        restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=True)
        self.assertEqual(text, self.hooks.read_text())

    def test_a_hooks_file_that_cannot_be_rewritten_exactly_after_install_is_reported_and_refused(self):
        edits = {
            "duplicate key": lambda text: text.replace('"enabled": true', '"enabled": false, "enabled": true'),
            "1e-400": lambda text: text.replace('"PreInvocation"', '"metadata": 1e-400, "PreInvocation"'),
        }
        for problem, edit in edits.items():
            with self.subTest(problem):
                shutil.rmtree(self.safe_yolo_home, ignore_errors=True)
                self.hooks.write_text(OTHER_FILE)
                self.install()
                text = edit(self.hooks.read_text())
                self.hooks.write_text(text)

                report = self.doctor()
                self.assertFalse(report["healthy"])
                self.assertTrue(any(problem in line for line in report["problems"]), report)
                steps = {
                    "update": self.install,
                    "uninstall": lambda: restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=True),
                    "deactivate": lambda: deactivate_harness(harness="antigravity",
                                                             safe_yolo_home=self.safe_yolo_home,
                                                             user_home=self.user_home),
                }
                for step in steps.values():
                    with self.assertRaises(RuntimeError):
                        step()
                    self.assertEqual(text, self.hooks.read_text())

    def test_a_linked_or_irregular_hooks_path_is_refused_by_every_command(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "hooks.json").write_text(OTHER_FILE)
        config = self.hooks.parent

        def linked_config():
            shutil.rmtree(config)
            config.symlink_to(elsewhere)

        def linked_file():
            self.hooks.unlink()
            self.hooks.symlink_to(elsewhere / "hooks.json")

        def directory():
            self.hooks.unlink()
            self.hooks.mkdir()

        inside = self.gemini / "real-config"

        def linked_into_root():
            config.rename(inside)
            config.symlink_to(inside)

        def targets() -> dict:
            return {path: path.read_bytes() for path in (elsewhere / "hooks.json", inside / "hooks.json")
                    if path.is_file()}

        cases = {"linked config folder": linked_config, "linked hooks file": linked_file,
                 "hooks path is a folder": directory, "config folder linked inside the root": linked_into_root}
        for name, change in cases.items():
            with self.subTest(name):
                for path in (self.safe_yolo_home, self.gemini):
                    if path.is_symlink():
                        path.unlink()
                    shutil.rmtree(path, ignore_errors=True)
                config.mkdir(parents=True)
                self.hooks.write_text(OTHER_FILE)
                (elsewhere / "hooks.json").write_text(OTHER_FILE)
                change()
                before = targets()
                with self.assertRaisesRegex(RuntimeError, "symlink|regular file"):
                    self.install()
                self.assertFalse(self.receipt_path().exists())
                self.assertEqual(before, targets())

                if config.is_symlink():
                    config.unlink()
                    shutil.rmtree(inside, ignore_errors=True)
                elif self.hooks.is_symlink():
                    self.hooks.unlink()
                else:
                    self.hooks.rmdir()
                config.mkdir(exist_ok=True)
                self.hooks.write_text(OTHER_FILE)
                self.install()
                installed = self.hooks.read_bytes()
                (elsewhere / "hooks.json").write_bytes(installed)
                change()
                before = targets()
                report = self.doctor()
                self.assertFalse(report["healthy"])
                self.assertTrue(any("symlink" in line or "regular file" in line for line in report["problems"]),
                                report)
                for step in (
                    lambda: restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=True),
                    lambda: deactivate_harness(harness="antigravity", safe_yolo_home=self.safe_yolo_home,
                                               user_home=self.user_home),
                    self.install,
                ):
                    with self.assertRaisesRegex(RuntimeError, "symlink|regular file|changed"):
                        step()
                    self.assertEqual(before, targets())
                self.assertEqual("active", json.loads(self.receipt_path().read_text())["status"])

    def test_doctor_runs_the_configured_command_and_fails_when_it_cannot(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        interpreter = bin_dir / "python3"
        interpreter.symlink_to(sys.executable)
        with patch.object(sys, "executable", str(interpreter)):
            self.install()
        self.assertTrue(self.doctor()["healthy"], self.doctor())

        interpreter.rename(bin_dir / "python3.moved")
        report = self.doctor()
        self.assertFalse(report["healthy"])
        self.assertEqual({"allow": False, "deny": False}, report["canaries"])
        self.assertTrue(any(str(interpreter) in line for line in report["problems"]), report)

        interpreter.symlink_to(shutil.which("true"))
        report = self.doctor()
        self.assertFalse(report["healthy"])
        self.assertEqual({"allow": False, "deny": False}, report["canaries"])

    def test_rollback_keeps_the_working_hook_when_the_previous_command_cannot_start(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        interpreter = bin_dir / "python3"
        interpreter.symlink_to(sys.executable)
        with patch.object(sys, "executable", str(interpreter)):
            self.install()
        (self.source / "VERSION").write_text("3.0.0-beta.3\n")
        self.install()
        interpreter.unlink()
        before = self.hooks.read_bytes(), self.receipt_path().read_bytes()

        with self.assertRaisesRegex(RuntimeError, "rollback was not applied"):
            restore(self.safe_yolo_home, self.user_home, "antigravity", uninstall=False)

        self.assertEqual(before, (self.hooks.read_bytes(), self.receipt_path().read_bytes()))
        self.assertTrue(self.doctor()["healthy"], self.doctor())

    def test_a_hand_wired_group_whose_release_does_not_verify_is_refused_untouched(self):
        cases = {
            "empty release, missing bootstrap, bad pin": lambda: (
                (self.safe_yolo_home / "releases" / "3.0.0-alpha.8").mkdir(parents=True),
                self.hand_wired(manifest="bad"))[1],
            "pin does not match the release": lambda: self.hand_wired(
                manifest="0" * 64, bootstrap=Path(self.legacy_release()["bootstrap"])),
            "empty pin": lambda: (self.legacy_release(), self.hand_wired(manifest=""))[1],
            "release without entrypoints": lambda: self.hand_wired(manifest=self.legacy_without_antigravity({})),
            "release exposing only codex": lambda: self.hand_wired(
                manifest=self.legacy_without_antigravity({"codex_v3": "adapters/codex_v3.py"})),
        }
        for name, group in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.safe_yolo_home, ignore_errors=True)
                shutil.rmtree(self.root / "legacy-source", ignore_errors=True)
                original = json.dumps({"herdr": HERDR, "safe-yolo": group()}) + "\n"
                self.hooks.write_text(original)
                with self.assertRaisesRegex(RuntimeError, "safe-yolo"):
                    self.install()
                self.assertEqual(original, self.hooks.read_text())
                self.assertFalse(self.receipt_path().exists())

    def test_hand_wired_group_through_the_shared_bootstrap_is_replaced(self):
        legacy = self.legacy_release()
        hand_wired = self.hand_wired(bootstrap=self.safe_yolo_home / "bootstrap.py", manifest=legacy["manifest_sha256"])
        self.hooks.write_text(json.dumps({"herdr": HERDR, "safe-yolo": hand_wired}))

        receipt = self.install()

        self.assertEqual(owned_group(self.installed_command(receipt)), json.loads(self.hooks.read_text())["safe-yolo"])

    def test_hand_wired_group_of_an_installed_release_is_backed_up_and_replaced(self):
        legacy = self.legacy_release()
        hand_wired = self.hand_wired(manifest=legacy["manifest_sha256"])
        original = json.dumps({"safe-yolo": hand_wired, "herdr": HERDR}, indent=2) + "\n"
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
