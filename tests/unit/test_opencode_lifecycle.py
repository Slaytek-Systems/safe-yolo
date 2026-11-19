from contextlib import redirect_stderr, redirect_stdout
import errno
import io
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

from scripts.distribute import deactivate_harness, doctor_harness, harness_catalog, install_harness, main
from scripts.global_cli import restore
from scripts.package import MANIFEST, build_bundle, digest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
V1_PLUGIN = (ROOT / "adapters" / "opencode_v1_retired_plugin.js").read_bytes().replace(
    b'"/home/dev/.safe-yolo/bootstrap.py"', b'"/home/me/.safe-yolo/releases/3.0.0-beta.11/scripts/bootstrap.py"'
).replace(b'"REPLACE_AFTER_INSTALL"', b'"f55d65a7370e5bc910f2772f0f659adc26e2a37fd31ad59db0984b4b75514aa0"')
LOOKALIKE_PLUGIN = b"""// Interop note: Safe YOLO runs bootstrap.py with --manifest-sha256 and --entry opencode_v3.
export default { id: "safe-yolo-lookalike", setup() {} }
"""
OTHER_PLUGIN = b'export default { id: "herdr-agent-state", setup() {} }\n'
HOOK_DRIVER = """
const plugin = (await import(process.argv[1])).default;
let hook;
await plugin.setup({
  location: { directory: process.argv[2] },
  tool: { hook: async (name, callback) => { if (name === "execute.before") hook = callback; } },
});
const results = [];
for (const command of JSON.parse(process.argv[3])) {
  try {
    await hook({ tool: "shell", sessionID: "s", agent: "build", messageID: "m", id: "c", input: { command } });
    results.push({ ran: true });
  } catch (error) {
    results.push({ ran: false, message: error.message });
  }
}
console.log(JSON.stringify(results));
"""


FAKE_CHILD = """
import { EventEmitter } from "node:events";
export function spawn(command, args, options) {
  const child = new EventEmitter();
  child.pid = 4242;
  child.kill = () => {};
  for (const name of ["stdin", "stdout", "stderr"]) child[name] = new EventEmitter();
  child.stdin.end = () => {};
  globalThis.spawnOptions = options;
  setImmediate(() => globalThis.scenario(child));
  return child;
}
"""
FAKE_DRIVER = """
const [pluginPath, scenario] = process.argv.slice(1);
const kills = [];
process.kill = (pid, signal) => { kills.push([pid, signal]); return true; };
globalThis.scenario = (child) => {
  if (scenario === "stdin-error-then-allow") {
    child.stdin.emit("error", new Error("write EPIPE"));
    child.stdout.emit("data", JSON.stringify({ decision: "allow", policy_id: "allow" }));
    child.emit("close", 0);
  } else if (scenario === "stdout-error") {
    child.stdout.emit("error", new Error("read ECONNRESET"));
  } else {
    child.stderr.emit("error", new Error("read ECONNRESET"));
  }
};
const plugin = (await import(pluginPath)).default;
let hook;
await plugin.setup({ location: { directory: "/" }, tool: { hook: async (_name, callback) => { hook = callback; } } });
let result;
try {
  await hook({ tool: "shell", sessionID: "s", id: "c", input: { command: "echo hello" } });
  result = { ran: true };
} catch (error) {
  result = { ran: false, message: error.message };
}
console.log(JSON.stringify({ ...result, kills, detached: globalThis.spawnOptions?.detached }));
"""
TIMEOUT_DRIVER = """
import { existsSync } from "node:fs";
const [pluginPath, pidFile] = process.argv.slice(1);
const realSetTimeout = globalThis.setTimeout;
let deadline;
globalThis.setTimeout = (callback, ms, ...rest) => {
  if (ms === 10000) { deadline = callback; return 0; }
  return realSetTimeout(callback, ms, ...rest);
};
const plugin = (await import(pluginPath)).default;
let hook;
await plugin.setup({ location: { directory: "/" }, tool: { hook: async (_name, callback) => { hook = callback; } } });
const pending = hook({ tool: "shell", sessionID: "s", id: "c", input: { command: "echo hello" } })
  .then(() => ({ ran: true }), (error) => ({ ran: false, message: error.message }));
for (let tries = 0; !existsSync(pidFile) && tries < 400; tries++) {
  await new Promise((resolve) => realSetTimeout(resolve, 50));
}
deadline();
console.log(JSON.stringify(await pending));
"""


class OpenCodeLifecycleTests(unittest.TestCase):
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
        self.config_home = self.user_home / ".config" / "opencode"
        self.plugins = self.config_home / "plugins"
        self.plugins.mkdir(parents=True)
        self.plugin = self.plugins / "safe-yolo.js"
        self.other = self.plugins / "herdr-agent-state.js"
        self.other.write_bytes(OTHER_PLUGIN)
        environment = patch.dict(os.environ)
        environment.start()
        os.environ.pop("XDG_CONFIG_HOME", None)
        os.environ.pop("OPENCODE_CONFIG_DIR", None)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        os.environ["PATH"] = os.pathsep.join([str(self.bin), "/usr/bin", "/bin"])
        self.addCleanup(environment.stop)

    def tearDown(self):
        self.temp.cleanup()

    def install(self):
        with patch("scripts.distribute.verify_source", return_value="e" * 40):
            return install_harness(
                harness="opencode",
                source=self.source,
                safe_yolo_home=self.safe_yolo_home,
                user_home=self.user_home,
                expected_commit="e" * 40,
            )

    def receipt(self):
        return json.loads((self.safe_yolo_home / "state" / "installations" / "opencode.json").read_text())

    def opencode_on_path(self, output: str):
        stub = self.bin / "opencode"
        stub.write_text(f"#!/bin/sh\nprintf '%s' {shlex.quote(output)}\n")
        stub.chmod(0o755)

    def uninstall(self):
        return restore(self.safe_yolo_home.resolve(), self.user_home, "opencode", uninstall=True)

    def retained_copies(self):
        backups = self.safe_yolo_home / "backups"
        return sorted(path for path in backups.rglob("*safe-yolo.js") if path.is_file()) if backups.exists() else []

    def doctor(self):
        return doctor_harness(
            harness="opencode", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home
        )

    def run_hook(self, plugin: Path, commands: list[str]) -> list[dict]:
        completed = subprocess.run(
            [NODE, "--input-type=module", "-e", HOOK_DRIVER, "--", str(plugin), str(self.root),
             json.dumps(commands)],
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        return json.loads(completed.stdout)

    def test_install_writes_only_its_plugin_and_deactivate_removes_it(self):
        receipt = self.install()

        self.assertEqual("opencode", receipt["harness"])
        self.assertEqual({"allow": True, "deny": True}, receipt["canaries"])
        self.assertEqual(str(self.plugin.resolve()), receipt["config_path"])
        self.assertEqual(str(self.config_home.resolve()), receipt["harness_home"])
        text = self.plugin.read_text()
        self.assertIn('"--entry", "opencode_v3"', text)
        self.assertIn(f'"--harness-home", "{self.config_home.resolve()}"', text)
        self.assertIn(receipt["manifest_sha256"], text)
        self.assertEqual(OTHER_PLUGIN, self.other.read_bytes())
        self.assertTrue(self.doctor()["healthy"])

        deactivate_harness(harness="opencode", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home)

        self.assertFalse(self.plugin.exists())
        self.assertEqual(OTHER_PLUGIN, self.other.read_bytes())
        self.assertEqual("inactive", json.loads(
            (self.safe_yolo_home / "state" / "installations" / "opencode.json").read_text())["status"])

    def test_hand_placed_v1_plugin_is_backed_up_replaced_and_restored(self):
        self.plugin.write_bytes(V1_PLUGIN)

        receipt = self.install()

        self.assertTrue(receipt["previous_config_existed"])
        self.assertEqual(V1_PLUGIN, Path(receipt["previous_config_backup"]).read_bytes())
        self.assertNotIn(b"tool.execute.before", self.plugin.read_bytes())
        self.assertIn(b'ctx.tool.hook("execute.before"', self.plugin.read_bytes())
        deactivate_harness(harness="opencode", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home)
        self.assertEqual(V1_PLUGIN, self.plugin.read_bytes())

    def test_a_plugin_that_is_not_safe_yolos_is_refused_untouched(self):
        foreign = b'export default { id: "safe-yolo-lookalike", setup() {} }\n'
        self.plugin.write_bytes(foreign)

        with self.assertRaisesRegex(RuntimeError, "not a Safe YOLO plugin"):
            self.install()

        self.assertEqual(foreign, self.plugin.read_bytes())
        self.assertFalse((self.safe_yolo_home / "state" / "installations" / "opencode.json").exists())

    def test_doctor_reports_an_edited_or_repinned_plugin(self):
        self.install()
        self.plugin.write_text(self.plugin.read_text().replace("3.0.0-beta.2", "3.0.0-beta.1"))

        report = self.doctor()

        self.assertFalse(report["healthy"])
        self.assertIn("installed harness configuration changed after activation", report["problems"])
        self.assertIn(
            "OpenCode plugin is not the Safe YOLO plugin pinned to the expected release",
            report["problems"],
        )

    def test_install_follows_xdg_config_home_like_opencode(self):
        xdg = self.root / "xdg"
        os.environ["XDG_CONFIG_HOME"] = str(xdg)

        receipt = self.install()

        self.assertEqual(str((xdg / "opencode" / "plugins" / "safe-yolo.js").resolve()), receipt["config_path"])
        self.assertFalse(self.plugin.exists())

    @unittest.skipUnless(NODE, "node is required to run the OpenCode plugin")
    def test_plugin_runs_allowed_calls_and_stops_denied_ones(self):
        self.install()

        allowed, denied = self.run_hook(self.plugin, ["echo hello", "git push --force origin main"])

        self.assertEqual({"ran": True}, allowed)
        self.assertFalse(denied["ran"])
        self.assertTrue(denied["message"].startswith("Safe YOLO denied [git.history_mutation]"), denied)

    @unittest.skipUnless(NODE, "node is required to run the OpenCode plugin")
    def test_plugin_fails_closed_when_the_adapter_cannot_decide(self):
        self.install()
        installed = self.plugin.read_text()
        release = str((self.safe_yolo_home / "releases" / "3.0.0-beta.2").resolve())
        cases = {
            "missing release": installed.replace(f'"--release", "{release}"', '"--release", "/nonexistent"'),
            "missing interpreter": installed.replace(f'["{sys.executable}"', '["/nonexistent/python3"'),
            "unparsable output": installed.replace(f'["{sys.executable}"', '["/bin/echo"'),
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertNotEqual(installed, text)
                broken = self.root / f"broken-{name.replace(' ', '-')}.js"
                broken.write_text(text)

                (result,) = self.run_hook(broken, ["echo hello"])

                self.assertFalse(result["ran"])
                self.assertIn("Safe YOLO fail-closed", result["message"])

    def test_install_uses_opencode_config_dir_ahead_of_xdg_like_opencode(self):
        native = self.root / "native"
        os.environ["XDG_CONFIG_HOME"] = str(self.root / "xdg")
        os.environ["OPENCODE_CONFIG_DIR"] = str(native)

        receipt = self.install()

        self.assertEqual(str((native / "plugins" / "safe-yolo.js").resolve()), receipt["config_path"])
        self.assertTrue((native / "plugins" / "safe-yolo.js").is_file())
        self.assertFalse((self.root / "xdg" / "opencode" / "plugins" / "safe-yolo.js").exists())

    def test_same_version_install_at_another_root_is_refused(self):
        self.install()
        other = self.root / "other-config"
        os.environ["OPENCODE_CONFIG_DIR"] = str(other)

        with self.assertRaisesRegex(RuntimeError, "active .*installation is wired to .*" + str(self.config_home)):
            self.install()

        self.assertFalse((other / "plugins" / "safe-yolo.js").exists())
        self.assertTrue(self.doctor()["healthy"])

    def test_catalog_detects_opencode_from_its_config_folder_without_a_binary(self):
        os.environ["XDG_CONFIG_HOME"] = str(self.root / "xdg")
        (self.root / "xdg" / "opencode").mkdir(parents=True)
        shutil.rmtree(self.user_home / ".config")

        catalog = {item["id"]: item for item in harness_catalog(self.user_home)}

        self.assertTrue(catalog["opencode"]["detected"])

    def test_lookalike_plugin_mentioning_safe_yolo_markers_is_refused_untouched(self):
        self.plugin.write_bytes(LOOKALIKE_PLUGIN)

        with self.assertRaisesRegex(RuntimeError, "not a Safe YOLO plugin"):
            self.install()

        self.assertEqual(LOOKALIKE_PLUGIN, self.plugin.read_bytes())
        self.assertFalse((self.safe_yolo_home / "state" / "installations" / "opencode.json").exists())

    def test_edited_v1_plugin_is_refused_untouched(self):
        edited = V1_PLUGIN.replace(b'"opencode_v3",', b'"opencode_v3", "--audit-only",')
        self.plugin.write_bytes(edited)

        with self.assertRaisesRegex(RuntimeError, "not a Safe YOLO plugin"):
            self.install()

        self.assertEqual(edited, self.plugin.read_bytes())

    def test_install_refuses_an_opencode_v1_binary_and_keeps_its_plugin(self):
        self.opencode_on_path("1.14.2\n")
        self.plugin.write_bytes(V1_PLUGIN)

        with self.assertRaisesRegex(RuntimeError, "OpenCode 1.14.2 .*V2"):
            self.install()

        self.assertEqual(V1_PLUGIN, self.plugin.read_bytes())

    def test_install_with_a_v2_binary_says_runtime_loading_is_unverified(self):
        self.opencode_on_path("opencode v2.3.2\n")

        receipt = self.install()

        self.assertIn("cannot prove", receipt["next_action"])
        self.assertIn("opencode api plugin.list", receipt["next_action"])
        self.assertIn("cannot prove", self.doctor()["activation_check"])

    def test_uninstall_and_deactivate_never_rename_the_plugin_out_of_its_folder(self):
        real_replace = os.replace

        def replace_across_mounts(source, destination):
            if Path(source).parent == self.plugins.resolve() and Path(destination).parent != self.plugins.resolve():
                raise OSError(errno.EXDEV, "Invalid cross-device link")
            return real_replace(source, destination)

        for name, remove in (
            ("uninstall", self.uninstall),
            ("deactivate", lambda: deactivate_harness(
                harness="opencode", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home)),
        ):
            with self.subTest(name):
                self.install()
                installed = self.plugin.read_bytes()
                with patch("os.replace", replace_across_mounts):
                    remove()

                self.assertFalse(self.plugin.exists())
                self.assertEqual("inactive", self.receipt()["status"])
                retained = self.receipt().get("uninstalled_config_backup") or self.receipt()["deactivated_config_backup"]
                self.assertEqual(installed, Path(retained).read_bytes())
                self.assertEqual(OTHER_PLUGIN, self.other.read_bytes())

    def test_failed_fresh_install_across_filesystems_leaves_no_plugin(self):
        real_replace = os.replace

        def replace_across_mounts(source, destination):
            if Path(source).parent == self.plugins.resolve() and Path(destination).parent != self.plugins.resolve():
                raise OSError(errno.EXDEV, "Invalid cross-device link")
            return real_replace(source, destination)

        with patch("os.replace", replace_across_mounts), \
                patch("scripts.distribute._run_canaries", return_value={"allow": True, "deny": False}):
            with self.assertRaisesRegex(RuntimeError, "activation failed"):
                self.install()

        self.assertFalse(self.plugin.exists())
        self.assertFalse((self.safe_yolo_home / "state" / "installations" / "opencode.json").exists())
        self.assertEqual(OTHER_PLUGIN, self.other.read_bytes())
        self.assertEqual(1, len(self.retained_copies()))

    def test_uninstall_says_how_to_confirm_removal(self):
        self.install()

        self.assert_removal_guidance(self.uninstall())

    def assert_removal_guidance(self, result):
        self.assertEqual("inactive", result["status"])
        self.assertIn("restart", result["next_action"].lower())
        self.assertIn("absent", result["next_action"])
        self.assertIn(str(self.plugins.resolve()), result["next_action"])
        self.assertNotIn("`active`", result["next_action"])
        self.assertNotIn("is denied", result["next_action"])

    def test_uninstall_interrupted_after_removal_reports_missing_then_finishes(self):
        self.install()
        installed = self.plugin.read_bytes()
        import scripts.distribute as distribute
        real_write = distribute._atomic_write
        receipt_path = self.safe_yolo_home.resolve() / "state" / "installations" / "opencode.json"

        def fail_inactive_receipt(path, payload, mode=0o600):
            if Path(path) == receipt_path and b'"inactive"' in payload:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write(path, payload, mode)

        with patch("scripts.distribute._atomic_write", fail_inactive_receipt):
            with self.assertRaises(OSError):
                self.uninstall()

        self.assertFalse(self.plugin.exists())
        self.assertEqual("active", self.receipt()["status"])
        report = self.doctor()
        self.assertFalse(report["healthy"])
        self.assertIn("installed harness configuration is missing", report["problems"])

        result = self.uninstall()

        self.assert_removal_guidance(result)
        self.assertEqual("inactive", self.receipt()["status"])
        self.assertEqual([Path(self.receipt()["uninstalled_config_backup"])], self.retained_copies())
        self.assertEqual(installed, Path(self.receipt()["uninstalled_config_backup"]).read_bytes())

    def test_uninstall_interrupted_before_removal_leaves_a_working_install_and_finishes(self):
        self.install()
        real_unlink = Path.unlink

        def fail_plugin_unlink(path, *args, **kwargs):
            if path == self.plugin.resolve():
                raise OSError(errno.EACCES, "Permission denied")
            return real_unlink(path, *args, **kwargs)

        with patch.object(Path, "unlink", fail_plugin_unlink):
            with self.assertRaises(OSError):
                self.uninstall()

        self.assertTrue(self.doctor()["healthy"])
        self.assertEqual("active", self.receipt()["status"])

        self.assert_removal_guidance(self.uninstall())
        self.assertFalse(self.plugin.exists())
        self.assertEqual(1, len(self.retained_copies()))

    def test_uninstall_refuses_a_plugin_edited_while_it_is_copied(self):
        self.install()
        import scripts.distribute as distribute
        real_write = distribute._atomic_write
        edited = self.plugin.read_bytes() + b"// edited\n"

        def edit_during_copy(path, payload, mode=0o600):
            result = real_write(path, payload, mode)
            if Path(path).is_relative_to(self.safe_yolo_home.resolve() / "backups"):
                self.plugin.write_bytes(edited)
            return result

        with patch("scripts.distribute._atomic_write", edit_during_copy):
            with self.assertRaisesRegex(RuntimeError, "changed"):
                self.uninstall()

        self.assertEqual(edited, self.plugin.read_bytes())
        self.assertEqual("active", self.receipt()["status"])

    def test_uninstall_without_plugin_or_verified_copy_refuses(self):
        self.install()
        self.plugin.unlink()

        with self.assertRaisesRegex(RuntimeError, "no verified copy"):
            self.uninstall()

        self.assertEqual("active", self.receipt()["status"])

    def test_resumed_uninstall_refuses_a_tampered_copy_or_a_symlinked_plugins_folder(self):
        self.install()
        import scripts.distribute as distribute
        real_write = distribute._atomic_write
        receipt_path = self.safe_yolo_home.resolve() / "state" / "installations" / "opencode.json"

        def fail_inactive_receipt(path, payload, mode=0o600):
            if Path(path) == receipt_path and b'"inactive"' in payload:
                raise OSError(errno.ENOSPC, "No space left on device")
            return real_write(path, payload, mode)

        with patch("scripts.distribute._atomic_write", fail_inactive_receipt):
            with self.assertRaises(OSError):
                self.uninstall()
        (copy,) = self.retained_copies()
        verified = copy.read_bytes()

        copy.write_bytes(verified + b"// tampered\n")
        with self.assertRaisesRegex(RuntimeError, "no verified copy"):
            self.uninstall()
        self.assertEqual("active", self.receipt()["status"])

        copy.write_bytes(verified)
        outside = self.root / "outside-plugins"
        self.plugins.rename(outside)
        self.plugins.symlink_to(outside)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.uninstall()
        self.assertEqual("active", self.receipt()["status"])

    def test_empty_opencode_config_dir_is_treated_as_unset(self):
        xdg = self.root / "xdg"
        (xdg / "opencode").mkdir(parents=True)
        shutil.rmtree(self.user_home / ".config")
        os.environ["XDG_CONFIG_HOME"] = str(xdg)
        os.environ["OPENCODE_CONFIG_DIR"] = ""
        working = self.root / "working-directory"
        working.mkdir()
        previous = os.getcwd()
        os.chdir(working)
        self.addCleanup(os.chdir, previous)

        catalog = {item["id"]: item for item in harness_catalog(self.user_home)}
        receipt = self.install()

        self.assertTrue(catalog["opencode"]["detected"])
        self.assertEqual(str((xdg / "opencode" / "plugins" / "safe-yolo.js").resolve()), receipt["config_path"])
        self.assertEqual([], list(working.iterdir()))

    def test_auto_install_skips_opencode_v1_but_explicit_install_refuses(self):
        self.opencode_on_path("1.14.2\n")
        self.plugin.write_bytes(V1_PLUGIN)
        (self.user_home / ".cursor").mkdir()
        arguments = ["--home", str(self.safe_yolo_home), "--user-home", str(self.user_home), "install",
                     "--source", str(self.source)]

        with patch("scripts.distribute.verify_source", return_value="e" * 40), \
                patch("scripts.distribute._current_commit", return_value="e" * 40):
            with redirect_stdout(io.StringIO()) as output:
                code = main(arguments)
            with redirect_stderr(io.StringIO()):
                explicit = main([*arguments, "--harness", "opencode"])

        result = json.loads(output.getvalue())
        self.assertEqual(0, code)
        self.assertEqual(["cursor"], [report["harness"] for report in result["reports"]])
        self.assertEqual(["opencode"], [item["harness"] for item in result["skipped"]])
        self.assertIn("V1", result["skipped"][0]["reason"])
        self.assertEqual(2, explicit)
        self.assertEqual(V1_PLUGIN, self.plugin.read_bytes())

    def test_install_accepts_only_a_whole_opencode_version_line(self):
        self.plugin.write_bytes(V1_PLUGIN)
        for output in (
            "other-app 4.12.3\n",
            "opencode wrapper 4.12.3\n1.14.2\n",
            "opencode v2.3.2\nopencode v1.14.2\n",
            "4.12.3 (other-app)\n",
            "1.19.6\n",
            "",
        ):
            with self.subTest(output=output):
                self.opencode_on_path(output)
                with self.assertRaises(RuntimeError):
                    self.install()
                self.assertEqual(V1_PLUGIN, self.plugin.read_bytes())

        self.opencode_on_path("2.3.2\n")
        self.assertEqual("active", self.install()["status"])

    def test_a_symlinked_plugin_is_refused_by_doctor_deactivate_and_uninstall(self):
        self.install()
        elsewhere = self.root / "elsewhere.js"
        shutil.copy2(self.plugin, elsewhere)
        self.plugin.unlink()
        self.plugin.symlink_to(elsewhere)

        self.assertFalse(self.doctor()["healthy"])
        with self.assertRaisesRegex(RuntimeError, "changed"):
            deactivate_harness(harness="opencode", safe_yolo_home=self.safe_yolo_home, user_home=self.user_home)
        with self.assertRaisesRegex(RuntimeError, "changed"):
            restore(self.safe_yolo_home.resolve(), self.user_home, "opencode", uninstall=True)
        self.assertTrue(self.plugin.is_symlink())
        self.assertTrue(elsewhere.is_file())

    def test_install_refuses_a_plugins_folder_that_links_outside_the_config_root(self):
        outside = self.root / "outside-plugins"
        self.other.unlink()
        self.plugins.rmdir()
        outside.mkdir()
        self.plugins.symlink_to(outside)

        with self.assertRaisesRegex(RuntimeError, "symlink"):
            self.install()

        self.assertEqual([], list(outside.iterdir()))

    @unittest.skipUnless(NODE, "node is required to run the OpenCode plugin")
    def test_plugin_fails_closed_on_any_pipe_error(self):
        self.install()
        fake = self.root / "fake_child.mjs"
        fake.write_text(FAKE_CHILD)
        plugin = self.root / "plugin-with-fake-child.mjs"
        installed = self.plugin.read_text()
        self.assertIn('from "node:child_process"', installed)
        plugin.write_text(installed.replace('from "node:child_process"', f'from "{fake.as_uri()}"'))

        for scenario in ("stdin-error-then-allow", "stdout-error", "stderr-error"):
            with self.subTest(scenario):
                completed = subprocess.run(
                    [NODE, "--input-type=module", "-e", FAKE_DRIVER, "--", str(plugin), scenario],
                    text=True, capture_output=True, check=False, timeout=60,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                result = json.loads(completed.stdout)
                self.assertFalse(result["ran"], result)
                self.assertIn("Safe YOLO fail-closed", result["message"])
                self.assertEqual([[-4242, "SIGKILL"]], result["kills"])

    @unittest.skipUnless(NODE and Path("/proc").is_dir(), "node and /proc are required")
    def test_timeout_stops_the_adapter_as_well_as_the_bootstrap(self):
        self.install()
        pid_file = self.root / "adapter.pid"
        bootstrap = self.root / "slow_bootstrap.py"
        bootstrap.write_text(
            "import subprocess, sys, time\n"
            "adapter = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            f"open({str(pid_file)!r}, 'w').write(str(adapter.pid))\n"
            "time.sleep(60)\n"
        )
        plugin = self.root / "slow.js"
        text = self.plugin.read_text()
        start = text.index("const COMMAND = ") + len("const COMMAND = ")
        end = text.index(";\n", start)
        plugin.write_text(text[:start] + json.dumps([sys.executable, str(bootstrap)]) + text[end:])
        try:
            completed = subprocess.run(
                [NODE, "--input-type=module", "-e", TIMEOUT_DRIVER, "--", str(plugin), str(pid_file)],
                text=True, capture_output=True, check=False, timeout=60,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            result = json.loads(completed.stdout)
            self.assertFalse(result["ran"], result)
            self.assertIn("no decision within 10000 ms", result["message"])
            self.assertTrue(self.process_ends(int(pid_file.read_text())), "adapter outlived the timeout")
        finally:
            if pid_file.is_file():
                try:
                    os.kill(int(pid_file.read_text()), 9)
                except ProcessLookupError:
                    pass

    def process_ends(self, pid: int) -> bool:
        import time
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                return True
            if state == "Z":
                return True
            time.sleep(0.05)
        return False


class OpenCodeGlobalLifecycleTests(unittest.TestCase):
    @patch("scripts.package.verify_source", return_value="a" * 40)
    def test_update_rollback_and_uninstall_keep_other_plugins(self, _verify):
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
            plugins = user / ".config/opencode/plugins"
            plugins.mkdir(parents=True)
            (plugins / "herdr-agent-state.js").write_bytes(OTHER_PLUGIN)
            (plugins / "safe-yolo.js").write_bytes(V1_PLUGIN)
            environment = {key: value for key, value in os.environ.items()
                           if key not in {"XDG_CONFIG_HOME", "OPENCODE_CONFIG_DIR"}}
            environment["PATH"] = os.pathsep.join(["/usr/bin", "/bin"])

            def run(command, *args):
                result = subprocess.run([*command, *args], capture_output=True, text=True, env=environment)
                self.assertEqual(0, result.returncode, result.stderr)
                return json.loads(result.stdout)

            run([sys.executable, str(first / "safe-yolo"), "--home", str(home), "--user-home", str(user)],
                "install", "--harness", "opencode")
            launcher = [str(user / ".local/bin/safe-yolo")]
            first_version = (first / "VERSION").read_text().strip()
            environment["OPENCODE_CONFIG_DIR"] = str(root / "another-config")
            run(launcher, "update", "--source", str(second))
            self.assertFalse((root / "another-config").exists())
            report = run(launcher, "doctor")
            self.assertTrue(report["healthy"], report)
            self.assertEqual("3.0.0-beta.999", report["reports"][0]["version"])
            self.assertIn("releases/3.0.0-beta.999/", (plugins / "safe-yolo.js").read_text())
            run(launcher, "rollback")
            self.assertEqual(first_version, run(launcher, "doctor")["reports"][0]["version"])
            self.assertIn(f"releases/{first_version}/", (plugins / "safe-yolo.js").read_text())
            run(launcher, "uninstall")

            self.assertEqual(["herdr-agent-state.js"], sorted(path.name for path in plugins.iterdir()))
            self.assertEqual(OTHER_PLUGIN, (plugins / "herdr-agent-state.js").read_bytes())


if __name__ == "__main__":
    unittest.main()
