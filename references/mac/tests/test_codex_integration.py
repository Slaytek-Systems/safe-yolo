import tempfile
import unittest
from pathlib import Path

from adapters.codex import evaluate_payload
from adapters.codex_prompt import authorize_prompt
from engine.capabilities import CapabilityStore
from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[1]


class CodexAuthorizationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CapabilityStore(Path(self.temp.name) / "capabilities")
        self.engine = SafeYoloEngine.from_file(ROOT / "policy.json", capability_store=self.store)

    def tearDown(self):
        self.temp.cleanup()

    def test_maintenance_authorizes_matching_structured_write_without_exposing_token(self):
        authorize_prompt("/maintenance codex hooks", "session-1__turn-1", self.store)
        decision = evaluate_payload(
            {
                "tool_name": "apply_patch",
                "session_id": "session-1",
                "turn_id": "turn-1",
                "tool_input": {
                    "patch": "*** Begin Patch\n*** Update File: /Users/slayga/.codex/hooks/probe.py\n*** End Patch"
                },
            },
            self.engine,
        )
        self.assertEqual("allow_report", decision["decision"])

    def test_merge_authorization_matches_exact_repository_pr_and_method(self):
        authorize_prompt("/merge-pr owner/repo#412 --squash", "session-1__turn-1", self.store)
        matching = self.engine.inspect_command(
            "gh pr merge 412 --repo owner/repo --squash",
            {"session_id": "session-1__turn-1"},
        )
        wrong_repo = self.engine.inspect_command(
            "gh pr merge 412 --repo other/repo --squash",
            {"session_id": "session-1__turn-1"},
        )
        self.assertEqual("allow_report", matching["decision"])
        self.assertEqual("require_capability", wrong_repo["decision"])

    def test_tag_authorization_matches_exact_repository_and_tag(self):
        authorize_prompt("/push-tag owner/repo v1.2.3", "session-1__turn-1", self.store)
        matching = self.engine.inspect_command(
            "git push origin v1.2.3",
            {"session_id": "session-1__turn-1", "repository": "owner/repo"},
        )
        wrong_tag = self.engine.inspect_command(
            "git push origin v1.2.4",
            {"session_id": "session-1__turn-1", "repository": "owner/repo"},
        )
        self.assertEqual("allow_report", matching["decision"])
        self.assertEqual("require_capability", wrong_tag["decision"])


if __name__ == "__main__":
    unittest.main()
