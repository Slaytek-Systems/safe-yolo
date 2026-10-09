import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.package import build_bundle
from scripts.package import digest, MANIFEST
from scripts.global_cli import install_command

ROOT = Path(__file__).resolve().parents[2]


class GlobalLifecycleTests(unittest.TestCase):
    def test_modified_launcher_is_preserved_before_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            user = root / 'user'
            home = root / 'runtime'
            launcher = user / '.local/bin/safe-yolo'
            launcher.parent.mkdir(parents=True)
            original = b'#!/bin/sh\n# Safe YOLO managed command\necho my own wrapper\n'
            launcher.write_bytes(original)
            with self.assertRaisesRegex(RuntimeError, 'Refusing to overwrite'):
                install_command(ROOT, home, user)
            self.assertEqual(original, launcher.read_bytes())
            self.assertFalse(home.exists())

    @patch('scripts.package.verify_source', return_value='a' * 40)
    def test_real_version_update_preserves_customizations_and_rolls_back(self, _verify):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = build_bundle(ROOT, root / 'downloads', 'a' * 40)
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(root / 'first')
                bundle.extractall(root / 'second')
            first = next((root / 'first').iterdir())
            second = next((root / 'second').iterdir())
            # Distinct verified candidate so this exercises a real upgrade, not a no-op.
            (second / 'VERSION').write_text('3.0.0-beta.999\n')
            manifest = json.loads((second / MANIFEST).read_text())
            manifest['version'] = '3.0.0-beta.999'
            manifest['files']['VERSION'] = digest((second / 'VERSION').read_bytes())
            (second / MANIFEST).write_text(json.dumps(manifest))
            user = root / 'user'
            home = root / 'runtime'
            command = [sys.executable, str(first / 'safe-yolo'), '--home', str(home), '--user-home', str(user)]
            def run(command, *args):
                result = subprocess.run([*command, *args], capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stderr)
                return json.loads(result.stdout)
            run(command, 'install', '--harness', 'cursor')
            customization = home / 'customizations.json'
            customization.write_text('{"deny_tools": ["dangerous_tool"]}\n')
            config = user / '.cursor/hooks.json'
            document = json.loads(config.read_text())
            document['my_setting'] = 'retained'
            config.write_text(json.dumps(document))
            launcher = [str(user / '.local/bin/safe-yolo')]
            run(launcher, 'update', '--source', str(second))
            self.assertEqual('3.0.0-beta.999', run(launcher, 'doctor')['reports'][0]['version'])
            hook = json.loads(config.read_text())['hooks']['preToolUse'][0]['command']
            import shlex
            decision = subprocess.run(shlex.split(hook), input='{"tool_name": "dangerous_tool"}',
                                      capture_output=True, text=True)
            self.assertEqual('deny', json.loads(decision.stdout)['permission'])
            self.assertEqual('{"deny_tools": ["dangerous_tool"]}\n', customization.read_text())
            run(launcher, 'rollback')
            self.assertEqual((first / 'VERSION').read_text().strip(), run(launcher, 'doctor')['reports'][0]['version'])
            run(launcher, 'update', '--source', str(second))
            run(launcher, 'uninstall')
            self.assertEqual({'my_setting': 'retained'}, json.loads(config.read_text()))

    @patch('scripts.package.verify_source', return_value='a' * 40)
    def test_global_command_survives_download_removal_and_uninstalls_after_update(self, _verify):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = build_bundle(ROOT, root / 'downloads', 'a' * 40)
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(root / 'extracted')
            source = next((root / 'extracted').iterdir())
            user = root / 'user'
            config = user / '.cursor/hooks.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps({'version': 1, 'custom': 'keep me'}))
            original = config.read_bytes()
            command = [sys.executable, str(source / 'safe-yolo'), '--home', str(root / 'runtime'),
                       '--user-home', str(user)]
            result = subprocess.run(command + ['install', '--harness', 'cursor'], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            launcher = user / '.local/bin/safe-yolo'
            self.assertTrue(launcher.is_file(), 'installation must provide a global command')
            source.rename(root / 'moved-download')
            def run(*args):
                result = subprocess.run([str(launcher), *args], capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stderr)
                return json.loads(result.stdout)
            self.assertTrue(run('doctor')['healthy'])
            run('update', '--source', str(root / 'moved-download'))
            self.assertEqual('keep me', json.loads(config.read_text())['custom'])
            run('uninstall')
            self.assertEqual(original, config.read_bytes())

    @patch('scripts.package.verify_source', return_value='a' * 40)
    def test_versioned_interpreter_name_installs_and_updates_codex(self, _verify):
        # Homebrew and python.org report sys.executable as e.g. .../python3.14.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = build_bundle(ROOT, root / 'downloads', 'a' * 40)
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(root / 'extracted')
                bundle.extractall(root / 'next')
            source = next((root / 'extracted').iterdir())
            upgrade = next((root / 'next').iterdir())
            (upgrade / 'VERSION').write_text('3.0.0-beta.999\n')
            manifest = json.loads((upgrade / MANIFEST).read_text())
            manifest['version'] = '3.0.0-beta.999'
            manifest['files']['VERSION'] = digest((upgrade / 'VERSION').read_bytes())
            (upgrade / MANIFEST).write_text(json.dumps(manifest))
            interpreter = root / 'bin' / f'python{sys.version_info.major}.{sys.version_info.minor}'
            interpreter.parent.mkdir()
            interpreter.symlink_to(sys.executable)
            user = root / 'user'
            (user / '.codex').mkdir(parents=True)
            (user / '.codex/config.toml').write_text(
                'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
            command = [str(interpreter), str(source / 'safe-yolo'), '--home', str(root / 'runtime'),
                       '--user-home', str(user)]
            result = subprocess.run(command + ['install', '--harness', 'codex'], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            hook = json.loads((user / '.codex/hooks.json').read_text())
            self.assertIn(str(interpreter), json.dumps(hook))
            launcher = str(user / '.local/bin/safe-yolo')
            for args in (['doctor'], ['update', '--source', str(upgrade)], ['doctor']):
                result = subprocess.run([launcher, *args], capture_output=True, text=True)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report['healthy'])
            self.assertEqual('3.0.0-beta.999', report['reports'][0]['version'])


if __name__ == '__main__':
    unittest.main()
