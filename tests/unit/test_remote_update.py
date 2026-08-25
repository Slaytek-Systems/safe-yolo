import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.remote_update import repin_command_text, repin_cursor_hooks


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

    def test_cursor_repin_is_optional_when_cursor_hooks_are_absent(self):
        with TemporaryDirectory() as tmpdir:
            missing = Path(tmpdir) / "safe-yolo-cursor.sh"
            with patch("scripts.remote_update.CURSOR_HOOKS", (missing,)):
                replaced = repin_cursor_hooks(
                    Path("/home/dev/.safe-yolo/releases/1.0.16"),
                    "c" * 64,
                )
        self.assertEqual(0, replaced)

    def test_cursor_repin_updates_present_hook(self):
        with TemporaryDirectory() as tmpdir:
            hook = Path(tmpdir) / "safe-yolo-cursor.sh"
            hook.write_text(
                "#!/usr/bin/env bash\n"
                "exec /usr/bin/python3 /home/dev/.safe-yolo/bootstrap.py "
                "--release /home/dev/.safe-yolo/releases/1.0.14 "
                "--manifest-sha256 86543e36741edaaf06e7e824ac71de3a7b96d3edc7ed5cbe8173e6efdd3df091 "
                "--entry cursor\n"
            )
            with patch("scripts.remote_update.CURSOR_HOOKS", (hook,)):
                replaced = repin_cursor_hooks(
                    Path("/home/dev/.safe-yolo/releases/1.0.16"),
                    "d" * 64,
                )
            updated = hook.read_text()
        self.assertEqual(1, replaced)
        self.assertIn("--release /home/dev/.safe-yolo/releases/1.0.16", updated)
        self.assertIn("--manifest-sha256 " + ("d" * 64), updated)


if __name__ == "__main__":
    unittest.main()
