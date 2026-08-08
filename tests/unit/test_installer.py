from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
