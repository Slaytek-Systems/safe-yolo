import tempfile
import unittest
from pathlib import Path


from engine.quarantine import Quarantine


class QuarantineTests(unittest.TestCase):
    def test_quarantine_and_restore_round_trip(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            workspace = base / "workspace"
            storage = base / "quarantine"
            workspace.mkdir()
            target = workspace / "obsolete.txt"
            target.write_text("recover me")

            quarantine = Quarantine(storage, workspace)
            record = quarantine.put(target)

            self.assertFalse(target.exists())
            self.assertTrue(Path(record["stored_path"]).exists())

            restored = quarantine.restore(record["id"])
            self.assertEqual(target, restored)
            self.assertEqual("recover me", target.read_text())

    def test_refuses_paths_outside_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            workspace = base / "workspace"
            workspace.mkdir()
            outside = base / "outside.txt"
            outside.write_text("leave me")

            quarantine = Quarantine(base / "quarantine", workspace)
            with self.assertRaises(ValueError):
                quarantine.put(outside)


if __name__ == "__main__":
    unittest.main()
