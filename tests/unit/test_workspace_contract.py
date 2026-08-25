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

    def test_missing_cwd_does_not_claim_the_host_contract_is_absent(self):
        decision = self.engine.inspect_command("./workspace status --json", {})
        self.assertEqual("block_method", decision["decision"])
        self.assertEqual("workspace.untrusted_launcher", decision["policy_id"])
        self.assertIn("actual working directory", decision["reason"])
        self.assertNotIn("approved host contract", decision["reason"])

    def test_repo_flag_allows_global_lifecycle_but_not_a_relative_launcher_mismatch(self):
        clean = SimpleNamespace(returncode=0)
        with patch("engine.safe_yolo.subprocess.run", return_value=clean):
            relative = self.engine.inspect_command(
                f"./workspace --repo {self.checkout} status --json",
                {"cwd": str(self.operations)},
            )
            global_command = self.engine.inspect_command(
                f"workspace --repo {self.checkout} status --json",
                {"cwd": str(self.operations)},
            )
        self.assertEqual("block_method", relative["decision"], relative)
        self.assertEqual("workspace.untrusted_launcher", relative["policy_id"])
        self.assertEqual("allow", global_command["decision"], global_command)

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
        with patch("engine.safe_yolo.subprocess.run", return_value=SimpleNamespace(returncode=0)):
            allowed = self.engine.inspect_command("docker ps", {"cwd": str(self.operations)})
            blocked = self.engine.inspect_command("docker ps", {"cwd": str(self.checkout)})
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual("block_method", blocked["decision"])


if __name__ == "__main__":
    unittest.main()
