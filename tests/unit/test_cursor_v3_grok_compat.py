import tempfile
import unittest
from pathlib import Path

from adapters.cursor_v3 import build_kernel, handle


class CursorGrokCompatTests(unittest.TestCase):
    """Grok loads ~/.cursor/hooks.json and replays PreToolUse with Grok tool names."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            cursor_home=self.root / "home" / ".cursor",
            user_home=self.root / "home",
            cwd=self.root / "project",
        )

    def tearDown(self):
        self.temp.cleanup()

    def grok(self, tool_name: str, tool_input: dict) -> dict:
        return {
            "hookEventName": "pre_tool_use",
            "sessionId": "s",
            "cwd": str(self.root / "project"),
            "permissionMode": "bypassPermissions",
            "toolName": tool_name,
            "toolInput": tool_input,
        }

    def test_grok_shell_payload_is_evaluated(self):
        self.assertEqual({"permission": "allow"}, handle(self.grok("run_terminal_command", {"command": "git status"}), self.kernel))
        denied = handle(self.grok("run_terminal_command", {"command": "rm -rf src"}), self.kernel)
        self.assertEqual("deny", denied["permission"])
        self.assertIn("filesystem.delete", denied["agent_message"])

    def test_grok_edit_and_read_payloads_are_evaluated(self):
        hooks = self.root / "home" / ".cursor" / "hooks.json"
        denied = handle(self.grok("search_replace", {"path": str(hooks)}), self.kernel)
        self.assertIn("enforcement.modify", denied["agent_message"])
        denied = handle(self.grok("read_file", {"path": str(self.root / "home" / ".ssh" / "id_ed25519")}), self.kernel)
        self.assertIn("credentials.access", denied["agent_message"])


if __name__ == "__main__":
    unittest.main()
