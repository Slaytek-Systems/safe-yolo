import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class WorkspaceContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.operations = base / "operations"
        self.workspace_root = base / "workspaces"
        self.checkout = self.workspace_root / "client" / "repos" / "app"
        self.checkout.mkdir(parents=True)
        (self.checkout / "workspace").write_text("#!/usr/bin/env bash\n")
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        contract = {
            "version": "1",
            "operations_root": str(self.operations),
            "workspaces_root": str(self.workspace_root),
            "workspace_lifecycle": ["status", "doctor"],
            "workspace_commands": [{
                "workspace": "client/repos/app",
                "command": ["functions", "push"],
                "policy_id": "workspace.local_functions_push",
                "reason": "Fixed local function push contract.",
            }],
        }
        self.engine = SafeYoloEngine(policy, host_contract=contract, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
        })

    def tearDown(self):
        self.temp.cleanup()

    def test_trusted_workspace_contract_allows_known_commands_only(self):
        clean = SimpleNamespace(returncode=0)
        with patch("engine.safe_yolo.subprocess.run", return_value=clean):
            status = self.engine.inspect_command("./workspace status", {"cwd": str(self.checkout)})
            contract = self.engine.inspect_command("./workspace functions push", {"cwd": str(self.checkout)})
            unknown = self.engine.inspect_command("./workspace destroy", {"cwd": str(self.checkout)})
        self.assertEqual("allow", status["decision"])
        self.assertEqual("allow_report", contract["decision"])
        self.assertEqual("workspace.local_functions_push", contract["policy_id"])
        self.assertEqual("block_method", unknown["decision"])

    def test_raw_docker_requires_the_operations_root(self):
        with patch("engine.safe_yolo.subprocess.run", return_value=SimpleNamespace(returncode=0)):
            allowed = self.engine.inspect_command("docker ps", {"cwd": str(self.operations)})
            blocked = self.engine.inspect_command("docker ps", {"cwd": str(self.checkout)})
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual("block_method", blocked["decision"])


if __name__ == "__main__":
    unittest.main()
