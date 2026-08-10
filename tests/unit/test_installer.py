from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

from scripts.cutover_macos import cutover
from scripts.install import install_release
from scripts.release_manifest import verify_manifest

ROOT = Path(__file__).resolve().parents[2]


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "safe-yolo-home"

    def tearDown(self):
        self.temp.cleanup()

    def test_installs_a_verified_version_without_touching_host_config(self):
        installed = install_release(ROOT, self.home)
        self.assertEqual((ROOT / "VERSION").read_text().strip(), installed["version"])
        self.assertEqual([], verify_manifest(installed["release"], installed["manifest_sha256"]))
        self.assertTrue((self.home / "bootstrap.py").is_file())
        self.assertFalse((self.home / "config.toml").exists())

    def test_never_overwrites_an_existing_release(self):
        install_release(ROOT, self.home)
        with self.assertRaises(FileExistsError):
            install_release(ROOT, self.home)

    def test_macos_cutover_script_is_directly_executable_by_python(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "cutover_macos.py"), "--help"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--codex-home", result.stdout)

    def test_atomic_macos_cutover_preserves_rollback_and_repins_exact_hooks(self):
        codex = Path(self.temp.name) / "codex"
        codex.mkdir()
        (codex / "config.toml").write_text('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        self.home.mkdir()
        old_bootstrap = b"old bootstrap\n"
        old_contract = b'{"version":"old"}\n'
        (self.home / "bootstrap.py").write_bytes(old_bootstrap)
        (self.home / "host-contract.json").write_bytes(old_contract)
        resolved_home = self.home.resolve()
        old_command = (
            f"python3 {resolved_home}/bootstrap.py --release {resolved_home}/releases/old "
            f"--manifest-sha256 {'a' * 64}"
        )
        hooks = {
            "hooks": {
                "UserPromptSubmit": [{"hooks": [{"type": "command", "command": f"{old_command} --entry prompt"}]}],
                "PreToolUse": [{"hooks": [{"type": "command", "command": f"{old_command} --entry codex"}]}],
            }
        }
        (codex / "hooks.json").write_text(json.dumps(hooks))

        report = cutover(ROOT, self.home, codex)

        self.assertTrue(report["healthy"])
        updated = (codex / "hooks.json").read_text()
        self.assertEqual(2, updated.count(f"--release {report['release']}"))
        self.assertEqual(2, updated.count(f"--manifest-sha256 {report['manifest_sha256']}"))
        rollback = Path(report["rollback"])
        self.assertEqual(old_bootstrap, (rollback / "bootstrap.py").read_bytes())
        self.assertEqual(old_contract, (rollback / "host-contract.json").read_bytes())
        self.assertEqual((ROOT / "scripts" / "bootstrap.py").read_bytes(), (self.home / "bootstrap.py").read_bytes())

    def test_macos_cutover_restores_active_files_when_post_write_doctor_fails(self):
        codex = Path(self.temp.name) / "codex"
        codex.mkdir()
        (codex / "config.toml").write_text('approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n')
        self.home.mkdir()
        originals = {
            "bootstrap.py": b"old bootstrap\n",
            "host-contract.json": b'{"version":"old"}\n',
        }
        for name, content in originals.items():
            (self.home / name).write_bytes(content)
        resolved_home = self.home.resolve()
        old_command = (
            f"python3 {resolved_home}/bootstrap.py --release {resolved_home}/releases/old "
            f"--manifest-sha256 {'a' * 64}"
        )
        original_hooks = json.dumps({
            "hooks": {
                "UserPromptSubmit": [{"hooks": [{"type": "command", "command": f"{old_command} --entry prompt"}]}],
                "PreToolUse": [{"hooks": [{"type": "command", "command": f"{old_command} --entry codex"}]}],
            }
        }).encode()
        (codex / "hooks.json").write_bytes(original_hooks)

        with self.assertRaises(RuntimeError):
            cutover(ROOT, self.home, codex)

        self.assertEqual(original_hooks, (codex / "hooks.json").read_bytes())
        for name, content in originals.items():
            self.assertEqual(content, (self.home / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
