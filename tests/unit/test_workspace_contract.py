import json
from pathlib import Path
import tempfile
import unittest

from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class WorkspaceContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.operations = base / "operations"
        self.checkout = base / "workspaces" / "client" / "repos" / "app"
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        contract = {
            "version": "1",
            "operations_root": str(self.operations),
        }
        self.engine = SafeYoloEngine(policy, host_contract=contract, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
        })

    def tearDown(self):
        self.temp.cleanup()

    def test_repository_launchers_are_ordinary_execution(self):
        for command in (
            "./workspace status --json",
            "./workspace destroy",
            "./scripts/task.sh",
        ):
            with self.subTest(command=command):
                decision = self.engine.inspect_command(command, {"cwd": str(self.checkout)})
                self.assertEqual("allow", decision["decision"], decision)

    def test_global_workspace_from_operations_root_remains_ordinary(self):
        decision = self.engine.inspect_command("workspace status --json", {"cwd": str(self.operations)})
        self.assertEqual("allow", decision["decision"])
        self.assertEqual("shell.ordinary", decision["policy_id"])

    def test_registered_loopback_reads_are_green(self):
        self.engine.host_contract["workspace_loopback_ports"] = [3210, 3211, 5174]
        allowed = self.engine._inspect_fetch("curl", ["-fsS", "http://127.0.0.1:3210/version"])
        also = self.engine.inspect_command("curl http://127.0.0.1:5174/robots.txt")
        blocked = self.engine.inspect_command("curl http://127.0.0.1:9999/health")
        public_bind = self.engine.inspect_command("curl http://0.0.0.0:3210/version")
        self.assertEqual("allow", allowed["decision"], allowed)
        self.assertEqual("network.workspace_loopback", allowed["policy_id"])
        self.assertEqual("allow", also["decision"], also)
        self.assertEqual("require_capability", blocked["decision"])
        self.assertEqual("network.private_read", blocked["policy_id"])
        self.assertEqual("require_capability", public_bind["decision"])

    def test_raw_docker_requires_the_operations_root(self):
        allowed = self.engine.inspect_command("docker ps", {"cwd": str(self.operations)})
        blocked = self.engine.inspect_command("docker ps", {"cwd": str(self.checkout)})
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual("block_method", blocked["decision"])


if __name__ == "__main__":
    unittest.main()
