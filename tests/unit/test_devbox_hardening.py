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
        cls.engine = SafeYoloEngine(
            policy,
            path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            },
            host_contract={"operations_root": "/home/dev/devbox-ops"},
        )

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

    def test_opaque_interpreters_and_untrusted_scripts_fail_closed(self):
        for command in (
            "python3 -c 'print(1)'",
            "node -e 'console.log(1)'",
            "python3 scripts/task.py",
            "node scripts/task.js",
            "bash scripts/task.sh",
        ):
            with self.subTest(command=command):
                self.assertEqual("block_hard", self.engine.inspect_command(command)["decision"])
        for command in ("python3 --version", "python3 -m unittest tests.test_policy", "node --check app.js", "bash -n check.sh"):
            with self.subTest(command=command):
                self.assertEqual("allow", self.engine.inspect_command(command)["decision"])

    def test_tracked_validation_allows_only_the_exact_literal_grammar(self):
        executable = "/home/dev/devbox-ops/bin/tracked-validation"
        sha = "ddbf4b92ff7eec413722bf77440b55ae1cad3eae"
        command = f"{executable} devbox-ops {sha} validation/test-gh-prm.sh"
        decision = self.engine.inspect_command(command)
        self.assertEqual("allow_report", decision["decision"])
        self.assertEqual("tracked_validation.exact", decision["policy_id"])

        line_continuation = (
            "/home/dev/devbox-ops/bin/tracked-" + "\\" + "\n"
            + f"validation devbox-ops {sha} validation/test-gh-prm.sh"
        )

        blocked_commands = (
            f"bin/tracked-validation devbox-ops {sha} validation/test-gh-prm.sh",
            f"/tmp/tracked-validation devbox-ops {sha} validation/test-gh-prm.sh",
            f"{executable} arbitrary-repo {sha} validation/test-gh-prm.sh",
            f"{executable} devbox-ops {sha} validation/arbitrary.sh",
            f"env {command}",
            f"env -i {command}",
            f"env -- {command}",
            f"command {command}",
            f"time {command}",
            f"timeout 30 {command}",
            f"bash -c '{command}'",
            f"{command} extra",
            f"{executable} devbox-ops {sha[:12]} validation/test-gh-prm.sh",
            f"{executable} devbox-ops {sha.upper()} validation/test-gh-prm.sh",
            f"{executable} devbox-ops {sha} validation/../test-gh-prm.sh",
            f"{command} && true",
            f"{command} | tee receipt.txt",
            f"{command} > receipt.txt",
            f"{executable} $(printf devbox-ops) {sha} validation/test-gh-prm.sh",
            f"$(printf {executable}) devbox-ops {sha} validation/test-gh-prm.sh",
            f"`printf {executable}` devbox-ops {sha} validation/test-gh-prm.sh",
            f"/home/dev/devbox-ops/bin/tracked-${{UNSET:-validation}} devbox-ops {sha} validation/test-gh-prm.sh",
            f"/home/dev/devbox-ops/bin/tracked-validatio? devbox-ops {sha} validation/test-gh-prm.sh",
            line_continuation,
            f"printf '%s%s\\n' /home/dev/devbox-ops/bin/tracked- validation | xargs sh -c '\"$0\" devbox-ops {sha} validation/test-gh-prm.sh'",
            f"printf '%s\\n' '{command}' | bash",
            f"git -c 'alias.x=!p={executable}; \"$p\" devbox-ops {sha} validation/test-gh-prm.sh; touch /tmp/safe-yolo-bypass' x",
            f"git -c 'alias.x=!p=/home/dev/devbox-ops/bin/tracked-; p=${{p}}validation; \"$p\" devbox-ops {sha} validation/test-gh-prm.sh' x",
            f"git --config-env=alias.x=ALIAS_VALUE x",
            f"git --exec-path=/tmp x",
            f"GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.x GIT_CONFIG_VALUE_0='!{command}' git x",
            f"git config alias.x '!p=/home/dev/devbox-ops/bin/tracked-; p=${{p}}validation; \"$p\" devbox-ops {sha} validation/test-gh-prm.sh' && git x",
            f"printf '%s\\n' '{command}' > /tmp/safe-yolo-rg-pre.sh && rg --pre sh NOMATCH /tmp/safe-yolo-rg-pre.sh",
            f"printf '%s\\n' '{command}' > /tmp/safe-yolo-command.txt",
            f"perl -e 'exec \"/home/dev/devbox-ops/bin/tracked-\" . \"validation\", \"devbox-ops\", \"{sha}\", \"validation/test-gh-prm.sh\"'",
            f"ruby -e 'exec \"/home/dev/devbox-ops/bin/tracked-\" + \"validation\", \"devbox-ops\", \"{sha}\", \"validation/test-gh-prm.sh\"'",
            f"awk 'BEGIN {{ p=\"/home/dev/devbox-ops/bin/tracked-\" \"validation\"; system(p \" devbox-ops {sha} validation/test-gh-prm.sh\") }}'",
            f"/home/dev/devbox-ops/bin/tracked-\"validation\" devbox-ops {sha} validation/test-gh-prm.sh",
            f"/home/dev/devbox-ops/bin/tracked-\\validation devbox-ops {sha} validation/test-gh-prm.sh",
            f"dash -c '/home/dev/devbox-ops/bin/tracked-\"validation\" devbox-ops {sha} validation/test-gh-prm.sh'",
            f"busybox sh -c '/home/dev/devbox-ops/bin/tracked-\"validation\" devbox-ops {sha} validation/test-gh-prm.sh'",
        )
        for blocked_command in blocked_commands:
            with self.subTest(command=blocked_command):
                self.assertNotIn(
                    self.engine.inspect_command(blocked_command)["decision"],
                    {"allow", "allow_report"},
                )

        for harmless_mention in (
            f"grep -F {executable} engine/safe_yolo.py",
            f"printf '%s\\n' {executable}",
        ):
            with self.subTest(command=harmless_mention):
                self.assertEqual("allow", self.engine.inspect_command(harmless_mention)["decision"])

    def test_tracked_validation_fails_closed_without_the_exact_operations_root(self):
        policy = json.loads((ROOT / "policy" / "policy.json").read_text())
        engine = SafeYoloEngine(policy, path_variables={
            "SAFE_YOLO_HOME": "/opt/safe-yolo",
            "CODEX_HOME": "/home/test/.codex",
        })
        command = (
            "/home/dev/devbox-ops/bin/tracked-validation devbox-ops "
            "ddbf4b92ff7eec413722bf77440b55ae1cad3eae validation/test-gh-prm.sh"
        )
        self.assertEqual("block_method", engine.inspect_command(command)["decision"])
        alternate = SafeYoloEngine(
            policy,
            path_variables={
                "SAFE_YOLO_HOME": "/opt/safe-yolo",
                "CODEX_HOME": "/home/test/.codex",
            },
            host_contract={"operations_root": "/tmp/alternate-operations"},
        )
        self.assertEqual("block_method", alternate.inspect_command(command)["decision"])
        alternate_command = command.replace(
            "/home/dev/devbox-ops/bin/tracked-validation",
            "/tmp/alternate-operations/bin/tracked-validation",
        )
        self.assertEqual("block_method", alternate.inspect_command(alternate_command)["decision"])

    def test_configured_git_aliases_fail_closed(self):
        decision = self.engine.inspect_command("git x", {"cwd": "/tmp/repository"})
        self.assertEqual("block_method", decision["decision"])
        self.assertEqual("git.alias_execution", decision["policy_id"])

    def test_literal_command_substitution_text_remains_inspectable(self):
        decision = self.engine.inspect_command(r"rg '\$\(' engine tests")
        self.assertEqual("allow", decision["decision"])

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
