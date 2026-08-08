import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PolicyInvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = json.loads((ROOT / "policy.json").read_text())

    def test_every_constitutional_red_is_non_overridable(self):
        for action in self.policy["constitutional_red"]:
            with self.subTest(action=action):
                rule = self.policy["actions"][action]
                self.assertEqual("red", rule["classification"])
                self.assertIs(rule.get("capability_override"), False)

    def test_protected_path_actions_exist(self):
        actions = self.policy["actions"]
        for protected in self.policy["protected_paths"]:
            with self.subTest(path=protected["path"]):
                self.assertIn(protected["action"], actions)

    def test_policy_schema_reference_exists(self):
        schema = ROOT / self.policy["$schema"]
        self.assertTrue(schema.is_file())
        json.loads(schema.read_text())


if __name__ == "__main__":
    unittest.main()
