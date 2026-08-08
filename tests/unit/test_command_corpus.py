import json
from pathlib import Path
import unittest

from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]
PATH_VARIABLES = {
    "SAFE_YOLO_HOME": "/opt/safe-yolo",
    "CODEX_HOME": "/home/test/.codex",
}


class CommandCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        cls.engine = SafeYoloEngine(policy, path_variables=PATH_VARIABLES)
        cls.cases = [
            json.loads(line)
            for line in (ROOT / "tests" / "corpus" / "commands.jsonl").read_text().splitlines()
            if line
        ]

    def test_command_corpus(self):
        failures = []
        for case in self.cases:
            command = case["command"]
            for name, value in PATH_VARIABLES.items():
                command = command.replace(f"${{{name}}}", value)
            actual = self.engine.inspect_command(command, case.get("context"))
            if actual["decision"] != case["expected"]:
                failures.append(
                    f'{case["id"]}: expected {case["expected"]}, got {actual["decision"]} ({actual["policy_id"]})'
                )
        self.assertEqual([], failures, "\n" + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
