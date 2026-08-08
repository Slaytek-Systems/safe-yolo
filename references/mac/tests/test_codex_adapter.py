import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from adapters.codex import evaluate_payload, hook_response, process_payload
from engine.capabilities import CapabilityStore
from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[1]


class CodexAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = CapabilityStore(Path(self.temp.name) / "capabilities")
        self.engine = SafeYoloEngine.from_file(ROOT / "policy.json", capability_store=self.store)

    def tearDown(self):
        self.temp.cleanup()

    def test_shell_payload_blocks_red_action(self):
        decision = evaluate_payload(
            {"tool_name": "Bash", "tool_input": {"command": "rm obsolete.txt"}},
            self.engine,
        )
        self.assertEqual("block_hard", decision["decision"])
        self.assertEqual("block", hook_response(decision)["decision"])

    def test_read_tool_can_inspect_protected_path(self):
        decision = evaluate_payload(
            {"tool_name": "Read", "tool_input": {"path": "~/.codex/AGENTS.md"}},
            self.engine,
        )
        self.assertEqual("allow", decision["decision"])

    def test_structured_protected_write_requires_maintenance(self):
        payload = {
            "tool_name": "apply_patch",
            "session_id": "session-1",
            "tool_input": {
                "patch": "*** Begin Patch\n*** Update File: /Users/slayga/.codex/hooks/probe.py\n*** End Patch"
            },
        }
        denied = evaluate_payload(payload, self.engine)
        self.assertEqual("require_capability", denied["decision"])

        token = self.store.issue(
            kind="maintenance",
            session_id="session-1",
            constraints={"harness": "codex", "scopes": ["hooks"]},
            ttl_seconds=300,
            user_authorized=True,
        )
        payload["safe_yolo_context"] = {"capability_token": token}
        allowed = evaluate_payload(payload, self.engine)
        self.assertEqual("allow_report", allowed["decision"])

    def test_ordinary_workspace_patch_is_allowed(self):
        decision = evaluate_payload(
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "patch": "*** Begin Patch\n*** Update File: /workspace/app.py\n*** End Patch"
                },
            },
            self.engine,
        )
        self.assertEqual("allow", decision["decision"])

    def test_relative_write_resolves_against_payload_cwd(self):
        decision = evaluate_payload(
            {
                "tool_name": "apply_patch",
                "cwd": "/Users/slayga/.codex/hooks",
                "tool_input": {
                    "patch": "*** Begin Patch\n*** Update File: probe.py\n*** End Patch"
                },
            },
            self.engine,
        )
        self.assertEqual("require_capability", decision["decision"])

    def test_relative_shell_redirect_resolves_against_payload_cwd(self):
        decision = evaluate_payload(
            {
                "tool_name": "Bash",
                "cwd": "/Users/slayga/.codex/hooks",
                "tool_input": {"command": "printf harmless > probe.py"},
            },
            self.engine,
        )
        self.assertEqual("require_capability", decision["decision"])

    def test_audit_only_logs_block_without_returning_hook_response(self):
        audit_log = Path(self.temp.name) / "state" / "audit.jsonl"
        payload = {
            "tool_name": "Bash",
            "session_id": "session-1",
            "turn_id": "turn-1",
            "tool_input": {"command": "rm obsolete.txt"},
        }
        response = process_payload(
            payload,
            self.engine,
            audit_only=True,
            audit_log=audit_log,
        )
        self.assertIsNone(response)
        record = json.loads(audit_log.read_text().strip())
        self.assertEqual("block_hard", record["decision"])
        self.assertEqual("filesystem.delete", record["policy_id"])
        self.assertNotIn("command", record)
        self.assertNotIn("tool_input", record)
        self.assertNotIn("obsolete.txt", audit_log.read_text())

    def test_audit_log_is_private_and_append_only(self):
        audit_log = Path(self.temp.name) / "state" / "audit.jsonl"
        for command in ("git status --short", "rm obsolete.txt"):
            process_payload(
                {"tool_name": "Bash", "tool_input": {"command": command}},
                self.engine,
                audit_only=True,
                audit_log=audit_log,
            )
        records = [json.loads(line) for line in audit_log.read_text().splitlines()]
        self.assertEqual(2, len(records))
        self.assertEqual(0o600, audit_log.stat().st_mode & 0o777)
        self.assertEqual(0o700, audit_log.parent.stat().st_mode & 0o777)

    def test_audit_cli_fails_open_when_policy_cannot_load(self):
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "adapters.codex",
                "--audit-only",
                "--policy",
                str(Path(self.temp.name) / "missing-policy.json"),
            ],
            cwd=ROOT,
            input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm obsolete.txt"}}),
            text=True,
            capture_output=True,
            check=False,
            env=environment,
        )
        self.assertEqual(0, process.returncode)
        self.assertEqual("", process.stdout)


if __name__ == "__main__":
    unittest.main()
