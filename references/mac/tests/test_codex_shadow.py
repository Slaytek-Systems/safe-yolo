from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from pathlib import Path

from adapters.codex_shadow import (
    DEFAULT_LIMIT,
    REPORT_NAME,
    append_observation,
    normalize_decision,
    run_wrapper,
)


def _process_observe(arguments: tuple[str, int]) -> None:
    state, index = arguments
    append_observation(
        Path(state),
        limit=20,
        payload={"session_id": f"s{index}", "turn_id": f"t{index}", "tool_name": "write"},
        legacy_decision="allow",
        safe_yolo_decision="block",
        policy_id="test.policy",
    )


ROOT = Path(__file__).resolve().parents[1]


class CodexShadowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.calls = self.root / "calls.jsonl"
        self.path_guard = self._guard("path", "")
        self.bash_guard = self._guard("bash", "")

    def tearDown(self):
        self.temp.cleanup()

    def _guard(self, name: str, stdout: str, returncode: int = 0) -> Path:
        path = self.root / f"{name}_{len(list(self.root.glob(name + '_*')))}.py"
        path.write_text(
            "import json, sys\n"
            "payload = json.load(sys.stdin)\n"
            f"with open({str(self.calls)!r}, 'a') as handle:\n"
            f"    handle.write(json.dumps({{'guard': {name!r}, 'tool': payload.get('tool_name')}}) + '\\n')\n"
            f"sys.stdout.write({stdout!r})\n"
            f"raise SystemExit({returncode})\n"
        )
        return path

    @staticmethod
    def _payload(tool: str = "write", **tool_input: str) -> dict[str, object]:
        return {
            "session_id": "session-secret-command",
            "turn_id": "turn-secret-path",
            "tool_name": tool,
            "tool_input": tool_input or {"path": "/private/secret.txt"},
        }

    def test_module_startup_has_no_eager_shadow_imports(self):
        process = subprocess.run(
            [
                sys.executable,
                "-c",
                "import json,sys; import adapters.codex_shadow; "
                "print(json.dumps([name for name in ('adapters.codex','engine.safe_yolo','hook_state') if name in sys.modules]))",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual([], json.loads(process.stdout))

    def test_decision_normalization(self):
        for decision in ("allow", "allow_report"):
            self.assertEqual("allow", normalize_decision(decision))
        for decision in ("require_capability", "block_method", "block_hard"):
            self.assertEqual("block", normalize_decision(decision))

    def test_wrapper_runs_path_then_bash_once_and_preserves_legacy_bytes(self):
        block = json.dumps({"decision": "block", "reason": "legacy"})
        bash_guard = self._guard("bash", block)
        result = run_wrapper(
            self._payload("Bash", command="rm secret-file"),
            state_dir=self.state,
            limit=DEFAULT_LIMIT,
            path_guard=self.path_guard,
            bash_guard=bash_guard,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(block.encode(), result.stdout)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(["path", "bash"], [call["guard"] for call in calls])

    def test_non_bash_invokes_only_path_guard(self):
        run_wrapper(
            self._payload("write"),
            state_dir=self.state,
            limit=DEFAULT_LIMIT,
            path_guard=self.path_guard,
            bash_guard=self.bash_guard,
        )
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(["path"], [call["guard"] for call in calls])

    def test_missing_shadow_policy_still_preserves_legacy_result(self):
        block = json.dumps({"decision": "block", "reason": "legacy"})
        blocking = self._guard("path", block)
        result = run_wrapper(
            self._payload("write"),
            state_dir=self.state,
            limit=DEFAULT_LIMIT,
            path_guard=blocking,
            bash_guard=self.bash_guard,
            policy=self.root / "missing-policy.json",
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(block.encode(), result.stdout)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(["path"], [call["guard"] for call in calls])

    def test_legacy_nonzero_is_preserved_and_skips_shadow(self):
        failing = self._guard("path", "legacy failure\n", returncode=7)
        result = run_wrapper(
            self._payload("write"),
            state_dir=self.state,
            limit=DEFAULT_LIMIT,
            path_guard=failing,
            bash_guard=self.bash_guard,
        )
        self.assertEqual(7, result.returncode)
        self.assertEqual(b"legacy failure\n", result.stdout)
        self.assertFalse(self.state.exists())

    def test_invalid_success_output_is_preserved_and_skips_shadow(self):
        invalid = self._guard("path", "not hook json")
        result = run_wrapper(
            self._payload("write"),
            state_dir=self.state,
            limit=DEFAULT_LIMIT,
            path_guard=invalid,
            bash_guard=self.bash_guard,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(b"not hook json", result.stdout)
        self.assertFalse(self.state.exists())

    def test_counts_only_structured_writes_and_noninformational_bash(self):
        payloads = [
            self._payload("Read", path="/tmp/a"),
            self._payload("Bash", command="git status --short"),
            self._payload("write", path="/tmp/a"),
            self._payload("Bash", command="python3 tests.py"),
        ]
        for payload in payloads:
            run_wrapper(
                payload,
                state_dir=self.state,
                limit=DEFAULT_LIMIT,
                path_guard=self.path_guard,
                bash_guard=self.bash_guard,
            )
        records = [json.loads(line) for line in (self.state / "observations.jsonl").read_text().splitlines()]
        self.assertEqual([1, 2], [record["ordinal"] for record in records])
        self.assertEqual(["write", "Bash"], [record["tool_name"] for record in records])

    def test_completed_cap_skips_all_further_evaluation(self):
        for index in range(20):
            append_observation(
                self.state,
                limit=20,
                payload={"tool_name": "write"},
                legacy_decision="allow",
                safe_yolo_decision="allow",
                policy_id=f"policy.{index}",
            )

        evaluations = 0

        def fail_if_evaluated(payload, policy):
            nonlocal evaluations
            evaluations += 1
            raise AssertionError("evaluation must not occur after completion")

        result = run_wrapper(
            self._payload("write"),
            state_dir=self.state,
            limit=20,
            path_guard=self.path_guard,
            bash_guard=self.bash_guard,
            policy=self.root / "missing-policy.json",
            evaluator=fail_if_evaluated,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(0, evaluations)
        self.assertEqual(20, len((self.state / "observations.jsonl").read_text().splitlines()))

    def test_completed_records_repair_partial_report_without_evaluation(self):
        self.state.mkdir(mode=0o700)
        records = []
        for ordinal in range(1, 21):
            records.append({
                "ordinal": ordinal,
                "timestamp": "2026-01-01T00:00:00+00:00",
                "tool_name": "write",
                "legacy_decision": "allow",
                "safe_yolo_decision": "allow",
                "safe_yolo_policy_id": "filesystem.write",
                "agreement": True,
            })
        (self.state / "observations.jsonl").write_text("".join(json.dumps(record) + "\n" for record in records))
        (self.state / REPORT_NAME).write_text("partial")

        evaluations = 0

        def fail_if_evaluated(payload, policy):
            nonlocal evaluations
            evaluations += 1
            raise AssertionError("repair must not evaluate")

        run_wrapper(
            self._payload("write"),
            state_dir=self.state,
            limit=20,
            path_guard=self.path_guard,
            bash_guard=self.bash_guard,
            evaluator=fail_if_evaluated,
        )
        self.assertEqual(0, evaluations)
        report = (self.state / REPORT_NAME).read_text()
        self.assertIn("total=20", report)
        self.assertTrue(report.endswith("NO CUTOVER: legacy Codex guards remain authoritative.\n"))
        self.assertTrue((self.state / ".completed").exists())

    def test_truncated_trailing_record_is_recovered_without_losing_prior_records(self):
        for _ in range(2):
            append_observation(
                self.state,
                limit=20,
                payload={"tool_name": "write"},
                legacy_decision="allow",
                safe_yolo_decision="allow",
                policy_id="filesystem.write",
            )
        with (self.state / "observations.jsonl").open("ab") as audit:
            audit.write(b'{"ordinal":3')
        append_observation(
            self.state,
            limit=20,
            payload={"tool_name": "write"},
            legacy_decision="allow",
            safe_yolo_decision="block",
            policy_id="test.policy",
        )
        records = [json.loads(line) for line in (self.state / "observations.jsonl").read_text().splitlines()]
        self.assertEqual([1, 2, 3], [record["ordinal"] for record in records])
        self.assertEqual("test.policy", records[-1]["safe_yolo_policy_id"])

    def test_atomic_cap_records_exactly_twenty_and_one_report(self):
        def observe(index: int) -> None:
            append_observation(
                self.state,
                limit=20,
                payload={"session_id": f"s{index}", "turn_id": f"t{index}", "tool_name": "write"},
                legacy_decision="allow",
                safe_yolo_decision="block",
                policy_id="test.policy",
            )

        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(observe, range(60)))

        records = [json.loads(line) for line in (self.state / "observations.jsonl").read_text().splitlines()]
        self.assertEqual(20, len(records))
        self.assertEqual(list(range(1, 21)), sorted(record["ordinal"] for record in records))
        report = (self.state / REPORT_NAME).read_text()
        self.assertIn("total=20", report)
        self.assertIn("NO CUTOVER", report)
        self.assertEqual(1, len(list(self.state.glob(REPORT_NAME))))

    def test_cross_process_cap_records_exactly_twenty(self):
        with ProcessPoolExecutor(max_workers=8) as pool:
            list(pool.map(_process_observe, [(str(self.state), index) for index in range(40)]))
        records = [json.loads(line) for line in (self.state / "observations.jsonl").read_text().splitlines()]
        self.assertEqual(20, len(records))
        self.assertEqual(list(range(1, 21)), [record["ordinal"] for record in records])

    def test_audit_schema_is_minimal_private_and_secret_free(self):
        append_observation(
            self.state,
            limit=20,
            payload=self._payload("write"),
            legacy_decision="allow",
            safe_yolo_decision="allow",
            policy_id="filesystem.write",
        )
        audit = self.state / "observations.jsonl"
        record = json.loads(audit.read_text())
        self.assertEqual(
            {
                "ordinal",
                "timestamp",
                "tool_name",
                "legacy_decision",
                "safe_yolo_decision",
                "safe_yolo_policy_id",
                "agreement",
            },
            set(record),
        )
        persisted = audit.read_text()
        for secret in ("secret-file", "secret.txt", "session-secret-command", "turn-secret-path", "tool_input", "reason", "command", "path"):
            self.assertNotIn(secret, persisted)
        self.assertEqual(0o700, self.state.stat().st_mode & 0o777)
        self.assertEqual(0o600, audit.stat().st_mode & 0o777)

    def test_cli_exposes_paths_and_limit_without_touching_live_state(self):
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "adapters.codex_shadow",
                "--state-dir",
                str(self.state),
                "--limit",
                "1",
                "--path-guard",
                str(self.path_guard),
                "--bash-guard",
                str(self.bash_guard),
            ],
            cwd=ROOT,
            input=json.dumps(self._payload("write")),
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )
        self.assertEqual(0, process.returncode)
        self.assertEqual("", process.stdout)
        self.assertEqual(1, len((self.state / "observations.jsonl").read_text().splitlines()))


if __name__ == "__main__":
    unittest.main()
