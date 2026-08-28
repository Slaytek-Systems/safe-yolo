import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adapters.codex_v2 import approval_request_from_denial, handle_post_tool, handle_pre_tool
from engine.approvals_v2 import ApprovalLedger
from engine.consequences_v2 import ConsequenceKernel


class V2ApprovalJourneyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ledger = ApprovalLedger(Path(self.temp.name))
        self.kernel = ConsequenceKernel(
            enforcement_paths=("/home/test/.safe-yolo", "/home/test/.codex/hooks.json"),
            credential_paths=("/home/test/.codex/auth.json", "/home/test/.ssh"),
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_unknown_tools_are_allowed_by_default(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "session_id": "session-1",
            "turn_id": "turn-1",
            "cwd": "/workspace",
            "tool_name": "future_mutation_tool",
            "tool_input": {"target": "ordinary"},
        }

        self.assertIsNone(handle_pre_tool(payload, self.kernel, self.ledger))

    def test_approved_direct_delete_allows_one_identical_retry(self):
        action = {
            "hook_event_name": "PreToolUse",
            "session_id": "session-1",
            "turn_id": "turn-1",
            "cwd": "/workspace",
            "tool_name": "Bash",
            "tool_input": {"command": "rm obsolete.txt"},
        }

        denied = handle_pre_tool(action, self.kernel, self.ledger)
        self.assertEqual(
            "deny",
            denied["hookSpecificOutput"]["permissionDecision"],
        )
        approval_input = approval_request_from_denial(denied)
        self.assertEqual("safe_yolo_approval", approval_input["questions"][0]["id"])

        approval_result = {
            "hook_event_name": "PostToolUse",
            "session_id": "session-1",
            "turn_id": "turn-1",
            "cwd": "/workspace",
            "tool_name": "request_user_input",
            "tool_input": approval_input,
            "tool_response": {
                "answers": {
                    "safe_yolo_approval": {
                        "answers": ["Approve once (Recommended)"],
                    }
                }
            },
        }
        self.assertTrue(handle_post_tool(approval_result, self.ledger))

        self.assertIsNone(handle_pre_tool(action, self.kernel, self.ledger))

        denied_again = handle_pre_tool(action, self.kernel, self.ledger)
        self.assertEqual(
            "deny",
            denied_again["hookSpecificOutput"]["permissionDecision"],
        )
        self.assertNotEqual(
            json.dumps(approval_input, sort_keys=True),
            json.dumps(approval_request_from_denial(denied_again), sort_keys=True),
        )

    def test_codex_encoded_approval_response_allows_one_identical_retry(self):
        action = self._bash("rm obsolete.txt")
        denied = handle_pre_tool(action, self.kernel, self.ledger)
        approval_input = approval_request_from_denial(denied)
        approval = self._approval(approval_input)
        approval["tool_response"] = json.dumps(
            approval["tool_response"],
            sort_keys=True,
            separators=(",", ":"),
        )

        self.assertTrue(handle_post_tool(approval, self.ledger))
        self.assertIsNone(handle_pre_tool(action, self.kernel, self.ledger))
        self.assertIsNotNone(handle_pre_tool(action, self.kernel, self.ledger))

    def test_unanswered_prompt_retains_request_for_later_explicit_approval(self):
        action = self._bash("rm obsolete.txt")
        denied = handle_pre_tool(action, self.kernel, self.ledger)
        approval_input = approval_request_from_denial(denied)
        reason = denied["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("empty answers", reason)
        self.assertIn("same JSON again", reason)
        unanswered = self._approval(approval_input)
        unanswered["tool_response"] = json.dumps(
            {"answers": {}},
            sort_keys=True,
            separators=(",", ":"),
        )

        self.assertFalse(handle_post_tool(unanswered, self.ledger))
        self.assertEqual(1, len(list(self.ledger.pending.glob("*.json"))))
        self.assertTrue(handle_post_tool(self._approval(approval_input), self.ledger))
        self.assertIsNone(handle_pre_tool(action, self.kernel, self.ledger))
        self.assertIsNotNone(handle_pre_tool(action, self.kernel, self.ledger))

    def test_approval_does_not_authorize_an_altered_action(self):
        original = self._bash("rm obsolete.txt")
        denied = handle_pre_tool(original, self.kernel, self.ledger)
        approval_input = approval_request_from_denial(denied)
        self.assertTrue(handle_post_tool(self._approval(approval_input), self.ledger))

        altered = self._bash("rm different.txt")
        altered_denial = handle_pre_tool(altered, self.kernel, self.ledger)

        self.assertEqual(
            "deny",
            altered_denial["hookSpecificOutput"]["permissionDecision"],
        )

    def test_rejection_does_not_create_a_receipt(self):
        action = self._bash("rm obsolete.txt")
        denied = handle_pre_tool(action, self.kernel, self.ledger)
        approval_input = approval_request_from_denial(denied)
        rejection = self._approval(approval_input, answer="Reject")

        self.assertFalse(handle_post_tool(rejection, self.ledger))
        self.assertFalse(handle_post_tool(self._approval(approval_input), self.ledger))
        self.assertIsNotNone(handle_pre_tool(action, self.kernel, self.ledger))

    def test_near_miss_approval_input_and_another_turn_cannot_mint_receipt(self):
        action = self._bash("rm obsolete.txt")
        denied = handle_pre_tool(action, self.kernel, self.ledger)
        approval_input = approval_request_from_denial(denied)

        altered_input = json.loads(json.dumps(approval_input))
        altered_input["questions"][0]["question"] += " changed"
        self.assertFalse(handle_post_tool(self._approval(altered_input), self.ledger))

        another_turn = self._approval(approval_input)
        another_turn["turn_id"] = "turn-2"
        self.assertFalse(handle_post_tool(another_turn, self.ledger))
        self.assertIsNotNone(handle_pre_tool(action, self.kernel, self.ledger))

    def test_expired_approval_cannot_authorize_retry(self):
        action = self._bash("rm obsolete.txt")
        with patch("engine.approvals_v2.time.time", return_value=1000):
            denied = handle_pre_tool(action, self.kernel, self.ledger)
            approval_input = approval_request_from_denial(denied)
            self.assertTrue(handle_post_tool(self._approval(approval_input), self.ledger))

        with patch("engine.approvals_v2.time.time", return_value=2000):
            self.assertIsNotNone(handle_pre_tool(action, self.kernel, self.ledger))

    def test_unanswered_request_outlives_short_receipt_window(self):
        action = self._bash("rm obsolete.txt")
        with patch("engine.approvals_v2.time.time", return_value=1000):
            denied = handle_pre_tool(action, self.kernel, self.ledger)
            approval_input = approval_request_from_denial(denied)
            unanswered = self._approval(approval_input)
            unanswered["tool_response"] = {"answers": {}}
            self.assertFalse(handle_post_tool(unanswered, self.ledger))

        with patch("engine.approvals_v2.time.time", return_value=1600):
            self.assertTrue(handle_post_tool(self._approval(approval_input), self.ledger))
            self.assertIsNone(handle_pre_tool(action, self.kernel, self.ledger))

    def test_ledger_never_persists_raw_tool_input(self):
        command = "rm private-customer-filename.txt"
        denied = handle_pre_tool(self._bash(command), self.kernel, self.ledger)
        approval_input = approval_request_from_denial(denied)
        self.assertTrue(handle_post_tool(self._approval(approval_input), self.ledger))

        persisted = "\n".join(
            path.read_text(encoding="utf-8")
            for path in Path(self.temp.name).rglob("*.json")
        )
        self.assertNotIn(command, persisted)
        self.assertNotIn("private-customer-filename.txt", persisted)

    def test_one_receipt_allows_exactly_one_concurrent_retry(self):
        action = self._bash("rm obsolete.txt")
        denied = handle_pre_tool(action, self.kernel, self.ledger)
        approval_input = approval_request_from_denial(denied)
        self.assertTrue(handle_post_tool(self._approval(approval_input), self.ledger))

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.ledger.consume_approval(action), range(32)))

        self.assertEqual(1, sum(results))

    def test_ledger_removes_consumed_and_expired_records(self):
        action = self._bash("rm obsolete.txt")
        with patch("engine.approvals_v2.time.time", return_value=1000):
            denied = handle_pre_tool(action, self.kernel, self.ledger)
            approval_input = approval_request_from_denial(denied)
            self.assertTrue(handle_post_tool(self._approval(approval_input), self.ledger))
            self.assertTrue(self.ledger.consume_approval(action))
            handle_pre_tool(self._bash("rm expired.txt"), self.kernel, self.ledger)

        with patch("engine.approvals_v2.time.time", return_value=4000):
            handle_pre_tool(self._bash("rm current.txt"), self.kernel, self.ledger)

        records = list(Path(self.temp.name).rglob("*.json"))
        self.assertEqual(1, len(records))
        self.assertIn("pending-v2", records[0].parts)

    def test_operator_only_boundaries_never_offer_approval(self):
        for action in (
            self._bash("cat /home/test/.codex/auth.json"),
            {
                "hook_event_name": "PreToolUse",
                "session_id": "session-1",
                "turn_id": "turn-1",
                "cwd": "/workspace",
                "tool_name": "apply_patch",
                "tool_input": {
                    "patch": (
                        "*** Begin Patch\n"
                        "*** Update File: /home/test/.safe-yolo/policy.json\n"
                        "*** End Patch"
                    )
                },
            },
            {
                **self._bash("rm policy.json"),
                "cwd": "/home/test/.safe-yolo",
            },
        ):
            with self.subTest(action=action):
                denied = handle_pre_tool(action, self.kernel, self.ledger)
                reason = denied["hookSpecificOutput"]["permissionDecisionReason"]
                self.assertIn("operator-only", reason)
                self.assertNotIn("SAFE_YOLO_REQUEST_USER_INPUT=", reason)

    def test_missing_task_scope_and_state_failure_deny_instead_of_crashing_open(self):
        missing_scope = self._bash("rm obsolete.txt")
        missing_scope.pop("turn_id")
        denial = handle_pre_tool(missing_scope, self.kernel, self.ledger)
        self.assertIn(
            "approval unavailable",
            denial["hookSpecificOutput"]["permissionDecisionReason"],
        )

        blocked_parent = Path(self.temp.name) / "not-a-directory"
        blocked_parent.write_text("x", encoding="utf-8")
        unavailable = ApprovalLedger(blocked_parent / "state")
        denial = handle_pre_tool(self._bash("rm obsolete.txt"), self.kernel, unavailable)
        self.assertIn(
            "approval unavailable",
            denial["hookSpecificOutput"]["permissionDecisionReason"],
        )

    @staticmethod
    def _bash(command):
        return {
            "hook_event_name": "PreToolUse",
            "session_id": "session-1",
            "turn_id": "turn-1",
            "cwd": "/workspace",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }

    @staticmethod
    def _approval(tool_input, *, answer="Approve once (Recommended)"):
        return {
            "hook_event_name": "PostToolUse",
            "session_id": "session-1",
            "turn_id": "turn-1",
            "cwd": "/workspace",
            "tool_name": "request_user_input",
            "tool_input": tool_input,
            "tool_response": {
                "answers": {
                    "safe_yolo_approval": {
                        "answers": [answer],
                    }
                }
            },
        }


if __name__ == "__main__":
    unittest.main()
