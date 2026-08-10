import json
from pathlib import Path
import tempfile
import unittest

from engine import quarantine as quarantine_module
from engine.quarantine import Quarantine
from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[2]


class QuarantineTests(unittest.TestCase):
    def test_file_can_be_quarantined_and_restored_without_loss(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            target = workspace / "valuable.txt"
            target.write_text("preserve this\n", encoding="utf-8")
            quarantine = Quarantine(root / "state", workspace)

            record = quarantine.put(target)
            self.assertFalse(target.exists())
            self.assertEqual("quarantined", quarantine.records()[-1]["status"])

            restored = quarantine.restore(record["id"])
            self.assertEqual(target, restored)
            self.assertEqual("preserve this\n", target.read_text(encoding="utf-8"))
            self.assertEqual("restored", quarantine.records()[-1]["status"])

    def test_only_manifest_pinned_quarantine_entry_is_classified_as_recovery(self):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        engine = SafeYoloEngine(
            policy,
            path_variables={
                "SAFE_YOLO_HOME": str(ROOT),
                "CODEX_HOME": "/home/test/.codex",
                "HOME": "/home/test",
            },
        )
        active_helper = Path(quarantine_module.__file__).resolve()
        allowed = engine.inspect_command(
            f"python3 {active_helper} put obsolete.txt",
            {"cwd": "/workspace"},
        )
        untrusted = engine.inspect_command("python3 ./quarantine.py put obsolete.txt", {"cwd": "/workspace"})
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual("block_method", untrusted["decision"])


if __name__ == "__main__":
    unittest.main()
