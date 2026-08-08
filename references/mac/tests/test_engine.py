import json
import tempfile
import unittest
from pathlib import Path

from engine.capabilities import CapabilityStore
from engine.safe_yolo import SafeYoloEngine


ROOT = Path(__file__).resolve().parents[1]


class EnginePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.store = CapabilityStore(Path(cls.temp.name) / "capabilities")
        cls.engine = SafeYoloEngine.from_file(ROOT / "policy.json", capability_store=cls.store)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def evaluate(self, action: str, **context):
        return self.engine.evaluate({"action": action, **context})

    def test_constitutional_red_cannot_be_overridden(self):
        result = self.evaluate(
            "git.force_push",
            capability_token="forged",
        )
        self.assertEqual("block_hard", result["decision"])
        self.assertFalse(result["capability_override"])

    def test_safe_feature_push_is_blue(self):
        result = self.evaluate(
            "git.push_feature",
            repository={
                "remote": "origin",
                "branch": "feature/safe-yolo",
                "target_branch": "feature/safe-yolo",
                "protected": False,
            },
            validation={"passed": True},
        )
        self.assertEqual("allow_report", result["decision"])

    def test_mismatched_feature_push_requires_capability(self):
        result = self.evaluate(
            "git.push_feature",
            repository={
                "remote": "origin",
                "branch": "feature/a",
                "target_branch": "feature/b",
                "protected": False,
            },
            validation={"passed": True},
        )
        self.assertEqual("require_capability", result["decision"])

    def test_task_aligned_record_write_is_green(self):
        result = self.evaluate(
            "records.write",
            task_aligned=True,
            bulk=False,
            administrative=False,
        )
        self.assertEqual("allow", result["decision"])

    def test_non_task_aligned_record_write_drops_to_amber(self):
        result = self.evaluate(
            "records.write",
            task_aligned=False,
            bulk=False,
            administrative=False,
        )
        self.assertEqual("require_capability", result["decision"])

    def test_production_deploy_earns_blue_with_current_evidence(self):
        result = self.evaluate(
            "deploy.production",
            release_evidence={
                "valid": True,
                "current": True,
                "commit_match": True,
                "target_match": True,
                "rollback_verified": True,
                "browser_confirmed": True,
                "gates_passed": True,
            },
        )
        self.assertEqual("allow_report", result["decision"])

    def test_production_deploy_without_complete_evidence_is_amber(self):
        result = self.evaluate("deploy.production", release_evidence={"valid": False})
        self.assertEqual("require_capability", result["decision"])

    def test_production_deploy_can_use_exact_amber_capability(self):
        token = self.store.issue(
            kind="action",
            action="deploy.production",
            session_id="session-1",
            constraints={"repository": "/repo", "target": "production"},
            ttl_seconds=300,
            user_authorized=True,
        )
        result = self.evaluate(
            "deploy.production",
            session_id="session-1",
            repository="/repo",
            target="production",
            release_evidence={"valid": False},
            capability_token=token,
        )
        self.assertEqual("allow_report", result["decision"])

    def test_harness_change_requires_scoped_maintenance(self):
        request = {
            "action": "harness.modify",
            "session_id": "session-1",
            "harness": "codex",
            "targets": ["hooks"],
        }
        denied = self.engine.evaluate(request)
        token = self.store.issue(
            kind="maintenance",
            session_id="session-1",
            constraints={"harness": "codex", "scopes": ["hooks", "rules", "tests"]},
            ttl_seconds=300,
            user_authorized=True,
        )
        allowed = self.evaluate(
            "harness.modify",
            session_id="session-1",
            harness="codex",
            targets=["hooks"],
            capability_token=token,
        )
        self.assertEqual("require_capability", denied["decision"])
        self.assertEqual("allow_report", allowed["decision"])

    def test_capability_is_bound_to_session(self):
        token = self.store.issue(
            kind="action",
            action="github.pr_merge",
            session_id="session-1",
            constraints={"repository": "/repo", "target": "412"},
            ttl_seconds=300,
            user_authorized=True,
        )
        denied = self.evaluate(
            "github.pr_merge",
            session_id="session-2",
            repository="/repo",
            target="412",
            capability_token=token,
        )
        allowed = self.evaluate(
            "github.pr_merge",
            session_id="session-1",
            repository="/repo",
            target="412",
            capability_token=token,
        )
        self.assertEqual("require_capability", denied["decision"])
        self.assertEqual("allow_report", allowed["decision"])

    def test_capability_cannot_expand_its_target(self):
        token = self.store.issue(
            kind="action",
            action="github.pr_merge",
            session_id="session-1",
            constraints={"repository": "/repo", "target": "412"},
            ttl_seconds=300,
            user_authorized=True,
        )
        result = self.evaluate(
            "github.pr_merge",
            session_id="session-1",
            repository="/other-repo",
            target="412",
            capability_token=token,
        )
        self.assertEqual("require_capability", result["decision"])

    def test_maintenance_applies_to_shell_write_destination(self):
        token = self.store.issue(
            kind="maintenance",
            session_id="session-1",
            constraints={"harness": "codex", "scopes": ["hooks"]},
            ttl_seconds=300,
            user_authorized=True,
        )
        result = self.engine.inspect_command(
            "printf harmless > ~/.codex/hooks/probe.py",
            {"session_id": "session-1", "capability_token": token},
        )
        self.assertEqual("allow_report", result["decision"])

    def test_maintenance_does_not_allow_system_config_write(self):
        token = self.store.issue(
            kind="maintenance",
            session_id="session-1",
            constraints={"harness": "codex", "scopes": ["hooks", "config"]},
            ttl_seconds=300,
            user_authorized=True,
        )
        result = self.engine.inspect_path_write(
            "~/.ssh/config",
            {"session_id": "session-1", "capability_token": token},
        )
        self.assertEqual("block_hard", result["decision"])

    def test_policy_maintenance_requires_named_policy_ids(self):
        token = self.store.issue(
            kind="policy_maintenance",
            session_id="session-1",
            constraints={"policy_ids": ["git.force_push"]},
            ttl_seconds=300,
            user_authorized=True,
        )
        missing_scope = self.engine.inspect_path_write(
            "~/.safe-yolo/policy.json",
            {"session_id": "session-1", "capability_token": token},
        )
        named_scope = self.engine.inspect_path_write(
            "~/.safe-yolo/policy.json",
            {
                "session_id": "session-1",
                "capability_token": token,
                "policy_ids": ["git.force_push"],
            },
        )
        self.assertEqual("require_capability", missing_scope["decision"])
        self.assertEqual("allow_report", named_scope["decision"])

    def test_generic_action_capability_cannot_replace_maintenance(self):
        token = self.store.issue(
            kind="action",
            action="harness.modify",
            session_id="session-1",
            constraints={"harness": "codex", "targets": ["hooks"]},
            ttl_seconds=300,
            user_authorized=True,
        )
        result = self.evaluate(
            "harness.modify",
            session_id="session-1",
            harness="codex",
            targets=["hooks"],
            capability_token=token,
        )
        self.assertEqual("require_capability", result["decision"])


class ConformanceCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = SafeYoloEngine.from_file(ROOT / "policy.json")

    def test_jsonl_corpus(self):
        cases_path = ROOT / "tests" / "cases.jsonl"
        for line_number, line in enumerate(cases_path.read_text().splitlines(), start=1):
            if not line.strip():
                continue
            case = json.loads(line)
            with self.subTest(case=case["id"], line=line_number):
                result = self.engine.inspect_command(case["command"], case.get("context", {}))
                self.assertEqual(case["expected"], result["decision"], result)


if __name__ == "__main__":
    unittest.main()
