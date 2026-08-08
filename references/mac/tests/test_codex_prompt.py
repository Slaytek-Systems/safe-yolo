import tempfile
import unittest
from pathlib import Path


from adapters.codex_prompt import authorize_prompt
from engine.capabilities import CapabilityStore


class CodexPromptAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CapabilityStore(Path(self.temp.name) / "capabilities")

    def tearDown(self):
        self.temp.cleanup()

    def authorize(self, prompt: str, session: str = "session-1"):
        return authorize_prompt(prompt, session, self.store)

    def test_exact_maintenance_command(self):
        response = self.authorize("/maintenance codex hooks rules tests")
        self.assertEqual("maintenance", response["kind"])
        record = self.store.resolve_active({"session_id": "session-1"})
        self.assertEqual("codex", record["constraints"]["harness"])
        self.assertEqual(["hooks", "rules", "tests"], record["constraints"]["scopes"])

    def test_unknown_maintenance_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            self.authorize("/maintenance codex hooks everything")

    def test_natural_language_does_not_authorize(self):
        response = self.authorize("please go into maintenance mode for codex hooks")
        self.assertIsNone(response)
        self.assertIsNone(self.store.resolve_active({"session_id": "session-1"}))

    def test_next_prompt_revokes_previous_capability(self):
        self.authorize("/maintenance codex hooks")
        self.assertIsNotNone(self.store.resolve_active({"session_id": "session-1"}))
        self.authorize("continue with the work")
        self.assertIsNone(self.store.resolve_active({"session_id": "session-1"}))

    def test_merge_capability_is_repository_and_pr_bound(self):
        response = self.authorize("/merge-pr owner/repo#412 --squash")
        self.assertEqual("github.pr_merge", response["action"])
        record = self.store.resolve_active({"session_id": "session-1"})
        self.assertEqual("owner/repo", record["constraints"]["repository"])
        self.assertEqual("412", record["constraints"]["target"])
        self.assertEqual("squash", record["constraints"]["method"])

    def test_tag_capability_is_repository_and_tag_bound(self):
        response = self.authorize("/push-tag owner/repo v1.2.3")
        self.assertEqual("git.push_tag", response["action"])
        record = self.store.resolve_active({"session_id": "session-1"})
        self.assertEqual("v1.2.3", record["constraints"]["target"])

    def test_policy_maintenance_requires_named_policy_ids(self):
        response = self.authorize("/maintenance-policy git.force_push filesystem.delete")
        self.assertEqual("policy_maintenance", response["kind"])
        record = self.store.resolve_active({"session_id": "session-1"})
        self.assertEqual(
            ["git.force_push", "filesystem.delete"],
            record["constraints"]["policy_ids"],
        )


if __name__ == "__main__":
    unittest.main()
