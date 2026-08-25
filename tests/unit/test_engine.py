import json
from pathlib import Path
import unittest

from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class CanonicalEngineTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        self.engine = SafeYoloEngine(self.policy, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
        })

    def test_constitutional_red_cannot_be_overridden(self):
        decision = self.engine.evaluate({"action": "filesystem.delete", "capability_token": "ignored"})
        self.assertEqual("block_hard", decision["decision"])

    def test_production_release_requires_external_contract(self):
        blocked = self.engine.evaluate({"action": "deploy.production"})
        allowed = self.engine.evaluate({
            "action": "deploy.production",
            "external_release_contract": {
                "issuer": "github-and-provider",
                "valid": True,
                "current": True,
                "repository_match": True,
                "commit_match": True,
                "artifact_match": True,
                "target_match": True,
                "rollback_verified": True,
                "gates_passed": True,
                "expires_at": "2030-01-01T00:00:00Z",
            },
        })
        self.assertEqual("block_hard", blocked["decision"])
        self.assertEqual("allow_report", allowed["decision"])

    def test_symbolic_control_plane_path_requires_maintenance(self):
        decision = self.engine.inspect_path_write(
            "/home/test/.codex/config.toml", {"session_id": "test"}
        )
        self.assertEqual("require_capability", decision["decision"])
        self.assertEqual("harness.modify", decision["policy_id"])

    def test_secret_detection_exempts_only_known_benign_path(self):
        synthetic_credential = "sk" + "-" + ("A" * 20)
        blocked_commands = (
            f"printf {synthetic_credential}",
            f"printf '{synthetic_credential}'",
            f"printf 'key={synthetic_credential}'",
            f"printf './{synthetic_credential}'",
            f"printf '({synthetic_credential})'",
            f"true && printf '{synthetic_credential}'",
            f"printf 'x{synthetic_credential}'",
            f"printf 'task{synthetic_credential}'",
            f"git add docs/architecture/codex-task-session-operating-model.md {synthetic_credential}",
            f"printf 'codex-task-session-operating-model.md{synthetic_credential}'",
            f"git add /tmp/{synthetic_credential}/codex-task-session-operating-model.md",
            f"git add /tmp/x{synthetic_credential}/codex-task-session-operating-model.md",
            f"printf 'FILE=/tmp/{synthetic_credential}/codex-task-session-operating-model.md'",
            f"git add docs/codex-task-session-operating-model.md/{synthetic_credential}",
        )
        for command in blocked_commands:
            with self.subTest(command=command):
                blocked = self.engine.inspect_command(command)
                self.assertEqual("block_hard", blocked["decision"])
                self.assertEqual("credentials.expose", blocked["policy_id"])

        ordinary_path = "git add docs/architecture/codex-task-session-operating-model.md"
        allowed = self.engine.inspect_command(ordinary_path)
        self.assertEqual("allow", allowed["decision"])

        absolute_path = "git add /tmp/docs/codex-task-session-operating-model.md"
        allowed = self.engine.inspect_command(absolute_path)
        self.assertEqual("allow", allowed["decision"])


if __name__ == "__main__":
    unittest.main()
