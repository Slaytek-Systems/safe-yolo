import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "policy" / "policy.json"
CORPUS_PATH = ROOT / "tests" / "corpus" / "commands.jsonl"


class CanonicalPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads(POLICY_PATH.read_text())

    def test_constitutional_red_actions_are_non_overridable(self):
        actions = self.policy["actions"]
        for action in self.policy["constitutional_red"]:
            self.assertIn(action, actions)
            self.assertEqual("red", actions[action]["classification"])
            self.assertIs(False, actions[action].get("capability_override"))

    def test_release_requires_external_contract_not_capability_fallback(self):
        release = self.policy["actions"]["deploy.production"]
        self.assertEqual("amber", release["classification"])
        self.assertEqual("blue", release["promote_to"])
        self.assertEqual("external_release_contract", release["condition"])
        self.assertIs(False, release["condition_fallback_capability"])

    def test_corpus_ids_are_unique_and_expected_values_are_valid(self):
        cases = [json.loads(line) for line in CORPUS_PATH.read_text().splitlines() if line]
        self.assertEqual(len(cases), len({case["id"] for case in cases}))
        for case in cases:
            self.assertIn(case["expected"], {"allow", "allow_report", "require_capability", "block_method", "block_hard"})


if __name__ == "__main__":
    unittest.main()
