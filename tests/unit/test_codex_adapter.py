import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from adapters.codex import audit_payload, evaluate_payload, process_payload
from adapters.codex_prompt import authorize_prompt
from engine.capabilities import CapabilityStore, PendingMaintenanceStore
from engine.safe_yolo import SafeYoloEngine

ROOT = Path(__file__).resolve().parents[2]


class CodexAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        self.store = CapabilityStore(Path(self.temp.name) / "capabilities")
        self.pending = PendingMaintenanceStore(Path(self.temp.name) / "pending")
        self.engine = SafeYoloEngine(policy, capability_store=self.store, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
        })

    def tearDown(self):
        self.temp.cleanup()

    def test_task_and_thread_tools_are_classified(self):
        expected = {
            "codex_appread_thread": "allow",
            "codex_appcreate_thread": "allow_report",
            "codex_appset_thread_archived": "allow_report",
            "codex_appsend_message_to_thread": "allow",
            "collaborationspawn_agent": "allow",
        }
        for tool_name, decision_name in expected.items():
            with self.subTest(tool_name=tool_name):
                decision = evaluate_payload({"tool_name": tool_name, "tool_input": {}}, self.engine)
                self.assertEqual(decision_name, decision["decision"])

    def test_codex_automation_tool_is_classified_by_operation(self):
        cases = {
            "view": ("allow", "codex.automation_inspection"),
            "update": ("allow_report", "codex.automation_management"),
            "create": ("allow_report", "codex.automation_management"),
            "pause": ("allow_report", "codex.automation_management"),
            "resume": ("allow_report", "codex.automation_management"),
            "delete": ("require_capability", "records.delete"),
        }
        for mode, (decision_name, policy_id) in cases.items():
            with self.subTest(mode=mode):
                decision = evaluate_payload(
                    {
                        "tool_name": "codex_appautomation_update",
                        "tool_input": {"mode": mode},
                    },
                    self.engine,
                )
                self.assertEqual(decision_name, decision["decision"])
                self.assertEqual(policy_id, decision["policy_id"])

    def test_codex_automation_tool_fails_closed_without_a_known_operation(self):
        decision = evaluate_payload(
            {
                "tool_name": "codex_appautomation_update",
                "tool_input": {"mode": "replace_everything"},
            },
            self.engine,
        )
        self.assertEqual("block_hard", decision["decision"])
        self.assertEqual("codex.automation_operation_unclassified", decision["policy_id"])

    def test_known_web_read_tool_is_allowed(self):
        decision = evaluate_payload({"tool_name": "webrun", "tool_input": {}}, self.engine)
        self.assertEqual("allow", decision["decision"])

    def test_shell_and_unknown_side_effects_are_blocked(self):
        shell = evaluate_payload(
            {"tool_name": "Bash", "tool_input": {"command": "rm obsolete.txt"}}, self.engine
        )
        unknown = evaluate_payload({"tool_name": "future_mutation_tool", "tool_input": {}}, self.engine)
        self.assertEqual("block_hard", shell["decision"])
        self.assertEqual("block_hard", unknown["decision"])

    def test_shell_workdir_overrides_task_root_for_git_classification(self):
        def git_result(command, **_kwargs):
            self.assertEqual("/tmp/disposable-repository", _kwargs["cwd"])
            if command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout="task/proof\n")
            raise AssertionError(command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            decision = evaluate_payload(
                {
                    "tool_name": "Bash",
                    "cwd": "/task/root",
                    "tool_input": {
                        "command": "git push -u origin task/proof",
                        "workdir": "/tmp/disposable-repository",
                    },
                },
                self.engine,
            )
        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual("git.push_feature", decision["policy_id"])

    def test_audit_only_records_a_block_without_returning_a_hook_block(self):
        audit = Path(self.temp.name) / "audit.jsonl"
        decision = audit_payload(
            {"tool_name": "Bash", "tool_input": {"command": "rm obsolete.txt"}},
            self.engine,
            audit,
        )
        self.assertEqual("block_hard", decision["decision"])
        self.assertNotIn("command", audit.read_text())

    def test_audit_failure_is_visible_without_denying_safe_action(self):
        parent = Path(self.temp.name) / "not-a-directory"
        parent.write_text("x")
        response = process_payload(
            {"tool_name": "Bash", "tool_input": {"command": "git status --short"}},
            self.engine,
            pending_store=self.pending,
            audit_log=parent / "audit.jsonl",
        )
        self.assertIsNotNone(response)
        self.assertNotIn("decision", response)
        self.assertIn("Audit unavailable", response["hookSpecificOutput"]["additionalContext"])

    def test_structured_patch_delete_is_constitutional_red(self):
        decision = evaluate_payload(
            {
                "tool_name": "apply_patch",
                "tool_input": {"patch": "*** Begin Patch\n*** Delete File: /workspace/obsolete.py\n*** End Patch"},
            },
            self.engine,
        )
        self.assertEqual("block_hard", decision["decision"])

    def test_approval_only_consumes_pending_maintenance_for_current_turn(self):
        first = {
            "tool_name": "apply_patch",
            "session_id": "session-1",
            "turn_id": "turn-1",
            "tool_input": {"path": "/home/test/.codex/config.toml"},
        }
        denied = process_payload(first, self.engine, pending_store=self.pending)
        self.assertEqual("block", denied["decision"])

        authorization = authorize_prompt(
            {"session_id": "session-1", "turn_id": "turn-2", "prompt": "approve"},
            self.store,
            self.pending,
        )
        self.assertEqual("maintenance", authorization["kind"])

        retry = {**first, "turn_id": "turn-2"}
        allowed = evaluate_payload(retry, self.engine)
        self.assertEqual("allow_report", allowed["decision"])


if __name__ == "__main__":
    unittest.main()
