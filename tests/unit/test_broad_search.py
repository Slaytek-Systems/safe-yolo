"""Judge command text and hook payloads only. Nothing here runs a search or reads a storage root."""
import json
from pathlib import Path
import tempfile
import unittest

from adapters import claude_code_v3, codex_v3
from scripts.harness_specs import HARNESSES


ROOT = Path(__file__).resolve().parents[2]
HOME = "/home/test"
BROAD = "filesystem.broad_search"


class BroadSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        safe_yolo = Path(cls.temp.name) / "safe-yolo"
        cls.codex = codex_v3.build_kernel(
            safe_yolo_home=safe_yolo, codex_home=f"{HOME}/.codex", user_home=HOME
        )
        cls.claude = claude_code_v3.build_kernel(
            safe_yolo_home=safe_yolo, claude_home=f"{HOME}/.claude", user_home=HOME
        )
        cls.cases = [
            json.loads(line)
            for line in (ROOT / "tests" / "corpus" / "broad_search.jsonl").read_text().splitlines()
            if line
        ]

    def shell(self, command):
        return self.codex.evaluate({
            "hook_event_name": "PreToolUse",
            "cwd": "/workspace",
            "tool_name": "exec_command",
            "tool_input": {"cmd": command},
        })

    def claude_tool(self, tool_name, tool_input):
        return claude_code_v3.handle_pre_tool(
            {"hook_event_name": "PreToolUse", "cwd": "/workspace", "tool_name": tool_name, "tool_input": tool_input},
            self.claude,
        )

    def test_corpus(self):
        failures = []
        for case in self.cases:
            decision = self.shell(case["command"])
            actual = (decision.outcome, decision.consequence, decision.display)
            if case["expected"] == "allow":
                wrong = decision.outcome != "allow"
            else:
                wrong = actual[:2] != ("deny", BROAD) or not str(decision.display).endswith(" " + case["root"])
            if wrong:
                failures.append(f'{case["id"]}: expected {case["expected"]}, got {actual}')
        self.assertEqual([], failures, "\n" + "\n".join(failures))
        self.assertGreater(sum(case["expected"] == "deny" for case in self.cases), 30)
        self.assertGreater(sum(case["expected"] == "allow" for case in self.cases), 100)

    def test_denial_names_the_safer_route_and_repeats_unchanged(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "cwd": "/workspace",
            "tool_name": "exec_command",
            "tool_input": {"cmd": "find / -name approved-merge-admission.md"},
        }
        first = codex_v3.handle_pre_tool(payload, self.codex)
        self.assertEqual(first, codex_v3.handle_pre_tool(payload, self.codex))
        output = first["hookSpecificOutput"]
        self.assertEqual("deny", output["permissionDecision"])
        reason = output["permissionDecisionReason"]
        self.assertIn(BROAD, reason)
        self.assertIn("whole storage root /", reason)
        self.assertIn("ls <root>", reason)
        self.assertIn("subfolder", reason)
        self.assertIn("-maxdepth 3", reason)

    def test_every_known_harness_folder_is_a_root(self):
        for spec in HARNESSES:
            with self.subTest(harness=spec.id):
                decision = self.shell(f"rg needle ~/{spec.config_dir}")
                self.assertEqual(("deny", BROAD), (decision.outcome, decision.consequence))
                self.assertEqual("allow", self.shell(f"rg needle ~/{spec.config_dir}/child").outcome)

    def test_existing_denials_keep_their_consequence(self):
        for command, consequence in (
            ("sudo grep -r foo /var", "privilege.modify"),
            ("rm -rf build; grep -r foo /tmp", "filesystem.delete"),
            (f"grep -r foo {HOME}/.ssh /tmp", "credentials.access"),
        ):
            with self.subTest(command=command):
                self.assertEqual(consequence, self.shell(command).consequence)

    def test_command_too_long_to_read_is_allowed(self):
        self.assertEqual("deny", self.shell("grep -r foo /tmp; " + "x" * 1000).outcome)
        self.assertEqual("allow", self.shell("grep -r foo /tmp; " + "x" * 65536).outcome)

    def test_claude_code_bash_is_denied_like_codex(self):
        denied = self.claude_tool("Bash", {"command": 'grep -rl "5e6d3bdf" ~/.local/state'})
        reason = denied["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn(BROAD, reason)
        self.assertIn(f"{HOME}/.local/state", reason)
        self.assertIsNone(self.claude_tool("Bash", {"command": 'grep -rl "5e6d3bdf" ~/.local/state/some-app'}))

    def test_native_grep_tool_on_a_root_is_denied(self):
        for path in (f"{HOME}/.local/state", "/tmp/", "/", HOME):
            with self.subTest(path=path):
                denied = self.claude_tool("Grep", {"pattern": "x", "path": path})
                reason = denied["hookSpecificOutput"]["permissionDecisionReason"]
                self.assertIn(BROAD, reason)
                self.assertIn("root " + (path.rstrip("/") or "/"), reason)

    def test_native_grep_tool_elsewhere_and_other_tools_are_allowed(self):
        for tool_name, tool_input in (
            ("Grep", {"pattern": "x"}),
            ("Grep", {"pattern": "x", "path": "/tmp/claude-x"}),
            ("Grep", {"pattern": "x", "path": "."}),
            ("Grep", {"pattern": "x", "path": "~"}),
            ("Grep", {"pattern": "/tmp", "path": "src"}),
            ("Grep", {"pattern": "x", "path": ["/tmp"]}),
            ("Glob", {"pattern": "**/*.md", "path": "/tmp"}),
            ("Read", {"file_path": "/tmp"}),
            ("Bash", {"command": ["grep", "-r", "x", "/tmp"]}),
            ("Bash", "grep -r x /tmp"),
        ):
            with self.subTest(tool=tool_name, tool_input=tool_input):
                self.assertIsNone(self.claude_tool(tool_name, tool_input))


if __name__ == "__main__":
    unittest.main()
