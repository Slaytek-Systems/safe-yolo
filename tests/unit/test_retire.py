import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.distribute import _retire


class RetireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.home = self.root / "safe-yolo"
        self.source = self.root / "harness" / "hooks.json"
        self.source.parent.mkdir(parents=True)
        self.payload = b'{"hooks": "safe-yolo"}\n'
        self.source.write_bytes(self.payload)
        self.digest = hashlib.sha256(self.payload).hexdigest()
        self.backup = self.home / "backups" / f"retired-codex-{self.digest}-hooks.json"
        self.backup.parent.mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_an_existing_backup_with_other_bytes_is_refused_and_kept(self):
        self.backup.write_bytes(b"operator recovery note\n")

        with self.assertRaises(RuntimeError):
            _retire("codex", self.source, self.digest, self.home)

        self.assertEqual(b"operator recovery note\n", self.backup.read_bytes())
        self.assertEqual(self.payload, self.source.read_bytes())

    def test_an_existing_identical_backup_is_reused_not_replaced(self):
        self.backup.write_bytes(self.payload)
        inode = self.backup.stat().st_ino

        self.assertEqual(self.backup, _retire("codex", self.source, self.digest, self.home))

        self.assertEqual(inode, self.backup.stat().st_ino)
        self.assertEqual(self.payload, self.backup.read_bytes())
        self.assertFalse(self.source.exists())

    def test_a_new_backup_is_created_and_the_source_removed(self):
        self.assertEqual(self.backup, _retire("codex", self.source, self.digest, self.home))

        self.assertEqual(self.payload, self.backup.read_bytes())
        self.assertFalse(self.source.exists())


if __name__ == "__main__":
    unittest.main()
