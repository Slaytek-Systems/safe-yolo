import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.distribute import deactivate_harness, doctor_harness, install_harness
from scripts.package import MANIFEST, build_bundle, digest


ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
V1_PLUGIN = b"""const BOOTSTRAP = "/home/me/.safe-yolo/releases/3.0.0-beta.11/scripts/bootstrap.py";
const MANIFEST_SHA256 = "f55d";
function runAdapter(payload) {
  return Bun.spawnSync([PYTHON, BOOTSTRAP, "--manifest-sha256", MANIFEST_SHA256, "--entry", "opencode_v3"]);
}
export const SafeYolo = async () => ({ "tool.execute.before": async () => {} });
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
            environment = {key: value for key, value in os.environ.items() if key != "XDG_CONFIG_HOME"}

            def run(command, *args):
                result = subprocess.run([*command, *args], capture_output=True, text=True, env=environment)
                self.assertEqual(0, result.returncode, result.stderr)
                return json.loads(result.stdout)

            run([sys.executable, str(first / "safe-yolo"), "--home", str(home), "--user-home", str(user)],
                "install", "--harness", "opencode")
            launcher = [str(user / ".local/bin/safe-yolo")]
            first_version = (first / "VERSION").read_text().strip()
            run(launcher, "update", "--source", str(second))
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
