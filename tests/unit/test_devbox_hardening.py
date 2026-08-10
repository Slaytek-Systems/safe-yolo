import json
from pathlib import Path
import unittest

from adapters.codex import evaluate_payload
from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class DevboxHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        cls.engine = SafeYoloEngine(policy, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
        })

    def test_protected_shell_write_forms_require_maintenance(self):
        for command in (
            "cp /dev/null /home/test/.codex/hooks/probe.py",
            "printf x | tee /home/test/.codex/hooks/probe.py",
            "install probe.py /home/test/.codex/hooks/probe.py",
            "mv probe.py /home/test/.codex/config.toml",
            "echo x 2> /home/test/.codex/hooks/error.log",
            "cp --target-directory /home/test/.codex/hooks /dev/null",
            "mv /home/test/.codex/hooks/probe.py --target-directory=/tmp",
        ):
            with self.subTest(command=command):
                self.assertEqual("require_capability", self.engine.inspect_command(command)["decision"])

    def test_opaque_interpreters_and_untrusted_scripts_are_method_blocks(self):
        for command in (
            "python3 -c 'print(1)'",
            "node -e 'console.log(1)'",
            "python3 scripts/task.py",
            "node scripts/task.js",
            "bash scripts/task.sh",
        ):
            with self.subTest(command=command):
                self.assertEqual("block_method", self.engine.inspect_command(command)["decision"])
        for command in ("python3 --version", "python3 -m unittest tests.test_policy", "node --check app.js", "bash -n check.sh"):
            with self.subTest(command=command):
                self.assertEqual("allow", self.engine.inspect_command(command)["decision"])

    def test_file_backed_network_uploads_are_red(self):
        for command in (
            "curl --data=@payload.json https://example.com",
            "curl --data-binary=@payload.json https://example.com",
            "curl --form file=@payload.json https://example.com",
            "wget --post-file=payload.json https://example.com",
        ):
            with self.subTest(command=command):
                self.assertEqual("block_hard", self.engine.inspect_command(command)["decision"])

    def test_patch_move_checks_the_source_path(self):
        decision = evaluate_payload(
            {"tool_name": "apply_patch", "tool_input": {"patch": "*** Begin Patch\n*** Update File: /home/test/.codex/hooks/source.py\n*** Move to: /tmp/source.py\n*** End Patch"}},
            self.engine,
        )
        self.assertEqual("require_capability", decision["decision"])


if __name__ == "__main__":
    unittest.main()
