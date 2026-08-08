import json
from pathlib import Path
import unittest

from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class MacOSHostFactsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        contract = {
            "version": "1",
            "protected_paths": [
                {"path": "${HOME}/.ssh", "action": "system.modify"},
                {"path": "${HOME}/.netrc", "action": "credentials.expose"},
                {"path": "${HOME}/Library/LaunchAgents", "action": "system.modify"},
            ],
            "restricted_executables": {"security": "credentials.expose"},
        }
        cls.engine = SafeYoloEngine(policy, host_contract=contract, path_variables={
            "HOME": "/Users/test",
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/Users/test/.codex",
        })

    def test_macos_protected_paths_cannot_be_edited(self):
        for path in (
            "/Users/test/.ssh/config",
            "/Users/test/.netrc",
            "/Users/test/Library/LaunchAgents/com.example.agent.plist",
        ):
            with self.subTest(path=path):
                self.assertEqual("block_hard", self.engine.inspect_path_write(path)["decision"])

    def test_keychain_commands_are_credential_exposure(self):
        decision = self.engine.inspect_command("security find-generic-password -s Codex")
        self.assertEqual("block_hard", decision["decision"])
        self.assertEqual("credentials.expose", decision["policy_id"])


if __name__ == "__main__":
    unittest.main()
