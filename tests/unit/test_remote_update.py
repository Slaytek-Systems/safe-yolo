import unittest
from pathlib import Path

from scripts.remote_update import repin_command_text


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


if __name__ == "__main__":
    unittest.main()
