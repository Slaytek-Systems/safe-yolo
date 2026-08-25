import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from adapters.cursor import evaluate_cursor_payload, process_cursor_payload
from engine.capabilities import CapabilityStore, PendingMaintenanceStore
from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[2]


class CursorAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        self.store = CapabilityStore(Path(self.temp.name) / "capabilities")
        self.pending = PendingMaintenanceStore(Path(self.temp.name) / "pending")
        self.engine = SafeYoloEngine(
            policy,
            capability_store=self.store,
            path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            },
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_unknown_cursor_tool_fails_closed(self):
        decision = evaluate_cursor_payload(
            {"tool_name": "FutureMutationTool", "tool_input": {}},
            self.engine,
        )
        self.assertEqual("block_hard", decision["decision"])
        self.assertEqual("tool.unclassified", decision["policy_id"])

    def test_mcp_execution_fails_closed_without_an_explicit_contract(self):
        payload = {
            "hook_event_name": "beforeMCPExecution",
            "tool_name": "create_external_record",
            "tool_input": {"title": "Example"},
        }
        decision = evaluate_cursor_payload(payload, self.engine)
        response = process_cursor_payload(payload, self.engine, pending_store=self.pending)

        self.assertEqual("block_hard", decision["decision"])
        self.assertEqual("tool.unclassified", decision["policy_id"])
        self.assertEqual("deny", response["permission"])

    def test_mcp_and_network_passthrough_names_fail_closed_in_pre_tool_use(self):
        for tool_name in ("CallMcpTool", "FetchMcpResource", "GetMcpTools", "WebFetch"):
            with self.subTest(tool_name=tool_name):
                decision = evaluate_cursor_payload(
                    {"hook_event_name": "preToolUse", "tool_name": tool_name, "tool_input": {}},
                    self.engine,
                )
                self.assertEqual("block_hard", decision["decision"])
                self.assertEqual("tool.unclassified", decision["policy_id"])

    def test_only_known_collaborative_browser_tools_are_allowed(self):
        allowed = evaluate_cursor_payload(
            {"hook_event_name": "beforeMCPExecution", "tool_name": "preview_open", "tool_input": {}},
            self.engine,
        )
        blocked = evaluate_cursor_payload(
            {"hook_event_name": "beforeMCPExecution", "tool_name": "preview_run_command", "tool_input": {}},
            self.engine,
        )
        self.assertEqual("allow", allowed["decision"])
        self.assertEqual("block_hard", blocked["decision"])

    def test_search_cannot_cover_a_parent_of_protected_credentials(self):
        for payload in (
            {"tool_name": "Grep", "tool_input": {"path": "/home/test/.codex"}},
            {"tool_name": "Glob", "tool_input": {"path": "/home/test/.codex/**/*.json"}},
            {"tool_name": "SemSearch", "tool_input": {}, "cwd": "/home/test"},
        ):
            with self.subTest(payload=payload):
                decision = evaluate_cursor_payload(payload, self.engine)
                self.assertEqual("block_hard", decision["decision"])
                self.assertEqual("credentials.expose", decision["policy_id"])

        allowed = evaluate_cursor_payload(
            {"tool_name": "Grep", "tool_input": {"path": "/workspace/project"}},
            self.engine,
        )
        self.assertEqual("allow", allowed["decision"])

    def test_known_non_mutating_cursor_orchestration_remains_allowed(self):
        for tool_name in ("Task", "TodoWrite", "Await", "WebSearch"):
            with self.subTest(tool_name=tool_name):
                decision = evaluate_cursor_payload(
                    {"tool_name": tool_name, "tool_input": {}},
                    self.engine,
                )
                self.assertEqual("allow", decision["decision"])

    def test_feature_push_is_reclassified_after_branch_transition(self):
        def git_result(command, **kwargs):
            self.assertEqual("/tmp/disposable-repository", kwargs["cwd"])
            if command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout="task/cursor-proof\n")
            raise AssertionError(command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            decision = evaluate_cursor_payload(
                {
                    "hook_event_name": "beforeShellExecution",
                    "command": "git push -u origin task/cursor-proof",
                    "cwd": "/tmp/disposable-repository",
                },
                self.engine,
            )

        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual("git.push_feature", decision["policy_id"])

    def test_protected_push_remains_gated(self):
        def git_result(command, **_kwargs):
            if command[1:] == ["branch", "--show-current"]:
                return SimpleNamespace(returncode=0, stdout="main\n")
            raise AssertionError(command)

        with patch("engine.safe_yolo.subprocess.run", side_effect=git_result):
            decision = evaluate_cursor_payload(
                {
                    "hook_event_name": "beforeShellExecution",
                    "command": "git push origin main",
                    "cwd": "/tmp/disposable-repository",
                },
                self.engine,
            )

        self.assertEqual("require_capability", decision["decision"])
        self.assertEqual("git.push_protected", decision["policy_id"])

    def test_shell_working_directory_is_accepted_as_cwd(self):
        clean = SimpleNamespace(returncode=0)
        checkout = Path(self.temp.name) / "workspaces" / "client" / "repos" / "app"
        checkout.mkdir(parents=True)
        (checkout / "workspace").write_text("#!/usr/bin/env bash\n")
        engine = SafeYoloEngine(
            json.loads((ROOT / "policy" / "policy.json").read_text()),
            capability_store=self.store,
            path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            },
            host_contract={
                "version": "1",
                "workspaces_root": str(checkout.parents[2]),
                "workspace_lifecycle": ["status"],
            },
        )
        with patch("engine.safe_yolo.subprocess.run", return_value=clean):
            decision = evaluate_cursor_payload(
                {
                    "hook_event_name": "beforeShellExecution",
                    "command": "./workspace status --json",
                    "working_directory": str(checkout),
                },
                engine,
            )
        self.assertEqual("allow", decision["decision"], decision)


if __name__ == "__main__":
    unittest.main()
