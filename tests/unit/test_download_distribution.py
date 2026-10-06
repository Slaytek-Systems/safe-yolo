import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.package import build_bundle, verify_bundle


ROOT = Path(__file__).resolve().parents[2]


class DownloadDistributionTests(unittest.TestCase):
    @patch('scripts.package.verify_source', return_value='a' * 40)
    def test_bundle_is_reproducible_and_rejects_extra_executable_source(self, _verify):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = build_bundle(ROOT, root / 'first', 'a' * 40)
            second = build_bundle(ROOT, root / 'second', 'a' * 40)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as bundle:
                bundle.extractall(root / 'extracted')
            source = next((root / 'extracted').iterdir())
            (source / 'unexpected.py').write_text('print("unexpected")\n')
            with self.assertRaisesRegex(RuntimeError, 'unexpected'):
                verify_bundle(source)

    @patch('scripts.package.verify_source', return_value='a' * 40)
    def test_download_installs_without_git_and_detects_modified_payload(self, _verify):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = build_bundle(ROOT, root / 'downloads', 'a' * 40)
            with zipfile.ZipFile(archive) as bundle:
                bundle.extractall(root / 'extracted')
            source = next((root / 'extracted').iterdir())
            self.assertFalse((source / '.git').exists())
            self.assertEqual('a' * 40, verify_bundle(source))
            command = [sys.executable, str(source / 'safe-yolo'), '--home', str(root / 'runtime'),
                       '--user-home', str(root / 'user')]
            installed = subprocess.run(command + ['install', '--harness', 'cursor',
                '--config-home', str(root / 'user/.cursor')], cwd=root,
                text=True, capture_output=True)
            self.assertEqual(0, installed.returncode, installed.stderr)
            self.assertTrue(json.loads(installed.stdout)['healthy'])
            doctor = subprocess.run(command + ['doctor', '--all'], cwd=root,
                                    text=True, capture_output=True)
            self.assertEqual(0, doctor.returncode, doctor.stderr)
            self.assertTrue(json.loads(doctor.stdout)['healthy'])
            (source / 'engine/consequences_v3.py').write_text('# modified\n')
            with self.assertRaisesRegex(RuntimeError, 'checksum'):
                verify_bundle(source)


if __name__ == '__main__':
    unittest.main()
