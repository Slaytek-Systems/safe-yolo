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

    def test_only_explicit_devbox_safe_yolo_maintenance_commands_are_allowed(self):
        host_contract = json.loads((ROOT / "hosts" / "macos" / "macos.contract.json").read_text())
        engine = SafeYoloEngine(json.loads((ROOT / "policy" / "policy.json").read_text()), path_variables={"HOME": "/Users/test", "SAFE_YOLO_HOME": "/opt/safe-yolo", "CODEX_HOME": "/Users/test/.codex"}, host_contract=host_contract)
        allowed = engine.inspect_command("ssh -n devbox git -C /home/dev/safe-yolo-source pull --ff-only", {})
        blocked = engine.inspect_command("ssh devbox rm -rf /tmp/example", {})
        self.assertEqual("allow_report", allowed["decision"])
        self.assertEqual("remote.safe_yolo_maintenance", allowed["policy_id"])
        self.assertEqual("block_hard", blocked["decision"])

    def test_devbox_maintenance_command_rejects_cli_route_overrides(self):
        host_contract = json.loads((ROOT / "hosts" / "macos" / "macos.contract.json").read_text())
        engine = SafeYoloEngine(json.loads((ROOT / "policy" / "policy.json").read_text()), path_variables={"HOME": "/Users/test", "SAFE_YOLO_HOME": "/opt/safe-yolo", "CODEX_HOME": "/Users/test/.codex"}, host_contract=host_contract)
        remote = "git -C /home/dev/safe-yolo-source pull --ff-only"
        commands = (
            f"ssh -o HostName=evil.example devbox {remote}",
            f"ssh -oHostName=evil.example devbox {remote}",
            f"ssh -J jump.example devbox {remote}",
            f"ssh -Jjump.example devbox {remote}",
            f"ssh -o ProxyJump=jump.example devbox {remote}",
            f"ssh -o 'ProxyCommand=nc evil.example 22' devbox {remote}",
            f"ssh -oProxyCommand='nc evil.example 22' devbox {remote}",
            f"ssh -o Include=/tmp/alternate-config devbox {remote}",
            f"ssh -o User=root devbox {remote}",
            f"ssh -o Port=2222 devbox {remote}",
            f"ssh -o ControlPath=/tmp/alternate.sock devbox {remote}",
            f"ssh -o RemoteCommand=hostname devbox {remote}",
            f"ssh -F /tmp/alternate-config devbox {remote}",
            f"ssh -F/tmp/alternate-config devbox {remote}",
            f"ssh -p 2222 devbox {remote}",
            f"ssh -p2222 devbox {remote}",
            f"ssh -l root devbox {remote}",
            f"ssh -lroot devbox {remote}",
            f"ssh -S /tmp/alternate.sock devbox {remote}",
        )
        for command in commands:
            with self.subTest(command=command):
                decision = engine.inspect_command(command, {})
                self.assertEqual("block_hard", decision["decision"])
                self.assertEqual("remote.execute", decision["policy_id"])

    def test_keychain_commands_are_credential_exposure(self):
        decision = self.engine.inspect_command("security find-generic-password -s Codex")
        self.assertEqual("block_hard", decision["decision"])
        self.assertEqual("credentials.expose", decision["policy_id"])


if __name__ == "__main__":
    unittest.main()
