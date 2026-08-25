import json
from pathlib import Path
import tempfile
import unittest

from scripts.remote_update import install_host_contract, repin_command_text


class RemoteUpdatePinTests(unittest.TestCase):
    def test_repins_single_line_command(self):
        original = (
            "/usr/bin/python3 /home/dev/.safe-yolo/bootstrap.py "
            "--release /home/dev/.safe-yolo/releases/1.0.14 "
            "--manifest-sha256 86543e36741edaaf06e7e824ac71de3a7b96d3edc7ed5cbe8173e6efdd3df091 "
            "--entry codex"
        )
        updated, count = repin_command_text(
            original,
            Path("/home/dev/.safe-yolo/releases/1.0.16"),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        self.assertEqual(1, count)
        self.assertIn("--release /home/dev/.safe-yolo/releases/1.0.16", updated)
        self.assertIn(
            "--manifest-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            updated,
        )

    def test_repins_multiline_shell_continuation(self):
        original = """#!/usr/bin/env bash
exec /usr/bin/python3 /home/dev/.safe-yolo/bootstrap.py \\
  --release /home/dev/.safe-yolo/releases/1.0.14 \\
  --manifest-sha256 86543e36741edaaf06e7e824ac71de3a7b96d3edc7ed5cbe8173e6efdd3df091 \\
  --entry cursor \\
  --state-dir /home/dev/.safe-yolo/state
"""
        updated, count = repin_command_text(
            original,
            Path("/home/dev/.safe-yolo/releases/1.0.16"),
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        self.assertEqual(1, count)
        self.assertIn("--release /home/dev/.safe-yolo/releases/1.0.16", updated)
        self.assertIn(
            "--manifest-sha256 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            updated,
        )
        self.assertIn("--entry cursor", updated)

    def test_installs_reviewed_host_contract_atomically_with_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            target = root / "live" / "host-contract.json"
            backups = root / "backups"
            source.write_text(json.dumps({"version": "1", "git_protected_push_exceptions": []}))
            target.parent.mkdir()
            target.write_text(json.dumps({"version": "old"}))

            changed = install_host_contract(source, target, backups, "1.0.21")

            self.assertTrue(changed)
            self.assertEqual(json.loads(source.read_text()), json.loads(target.read_text()))
            self.assertEqual(
                {"version": "old"},
                json.loads((backups / "host-contract.json.pre-1.0.21").read_text()),
            )
            self.assertEqual(0o600, target.stat().st_mode & 0o777)

    def test_invalid_host_contract_does_not_replace_live_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.json"
            target = root / "host-contract.json"
            source.write_text("not json")
            target.write_text(json.dumps({"version": "live"}))

            with self.assertRaises(ValueError):
                install_host_contract(source, target, root / "backups", "1.0.21")

            self.assertEqual({"version": "live"}, json.loads(target.read_text()))


if __name__ == "__main__":
    unittest.main()
