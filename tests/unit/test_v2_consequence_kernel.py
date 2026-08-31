import unittest

from adapters.codex_v2 import build_kernel
from engine.consequences_v2 import ConsequenceKernel


class V2ConsequenceKernelTests(unittest.TestCase):
    def setUp(self):
        self.kernel = ConsequenceKernel(
            enforcement_paths=(
                "/home/test/.safe-yolo",
                "/home/test/.codex/hooks.json",
                "/home/test/.codex/hooks",
            ),
            credential_paths=("/home/test/.codex/auth.json", "/home/test/.ssh"),
        )

    def test_ordinary_execution_defaults_to_allow(self):
        commands = (
            "bash scripts/task.sh",
            "python3 -c 'print(1)'",
            "curl -L https://example.com/resource",
            "curl http://127.0.0.1:3000/health",
            "bunx unknown-package --help",
            "docker ps",
            "git status && rm obsolete.txt",
            "git clean --dry-run",
            "git clean -n",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual("allow", self._shell(command).outcome)

    def test_direct_approval_eligible_consequences(self):
        expected = {
            "rm -rf build": "filesystem.delete",
            "/bin/rm obsolete.txt": "filesystem.delete",
            "unlink obsolete.txt": "filesystem.delete",
            "rmdir build": "filesystem.delete",
            "git push --force-with-lease origin feature/x": "git.history_mutation",
            "/usr/bin/git push --mirror origin": "git.history_mutation",
            "git push --prune origin": "git.history_mutation",
            "git push -d origin feature/x": "git.history_mutation",
            "git -C /repo push --force origin feature/x": "git.history_mutation",
            "git reset --hard HEAD~1": "git.history_mutation",
            "git --no-pager reset --hard HEAD~1": "git.history_mutation",
            "git restore README.md": "git.history_mutation",
            "railway up": "production.mutate",
            "fly deploy": "production.mutate",
            "vercel --prod": "production.mutate",
            "kubectl apply -f deployment.yaml": "production.mutate",
            "kubectl -n prod delete pod web": "production.mutate",
            "kubectl --context prod apply -f deployment.yaml": "production.mutate",
            "kubectl create deployment web --image example/web": "production.mutate",
            "kubectl edit deployment web": "production.mutate",
            "kubectl rollout restart deployment/web": "production.mutate",
            "gh pr merge 123": "production.mutate",
            "ssh production.example.com": "remote.execute",
            "/usr/bin/ssh production.example.com": "remote.execute",
            "sudo touch /tmp/probe": "privilege.modify",
            "/usr/bin/sudo touch /tmp/probe": "privilege.modify",
            "vite --host 0.0.0.0": "network.public_exposure",
            "vite --host": "network.public_exposure",
            "vite --host --port 3000": "network.public_exposure",
            "python3 -m http.server --bind 0.0.0.0": "network.public_exposure",
        }
        for command, consequence in expected.items():
            with self.subTest(command=command):
                decision = self._shell(command)
                self.assertEqual("approval_required", decision.outcome)
                self.assertEqual(consequence, decision.consequence)

    def test_safe_push_stops_scanning_at_heredoc_payload(self):
        decision = self._shell(
            "git push origin HEAD:feature/safe && gh pr create --body-file - <<'EOF'\n"
            "Summary\n"
            "+1 ms\n"
            "EOF"
        )

        self.assertEqual("allow", decision.outcome)

    def test_git_push_force_detection_stops_at_heredoc_tokens(self):
        for marker in ("<<EOF", "<< EOF", "<<'EOF'"):
            with self.subTest(marker=marker):
                decision = self._shell(
                    f"git push origin HEAD:topic/main {marker}\n"
                    "+topic/main:topic/main\n"
                    "EOF"
                )
                self.assertEqual("allow", decision.outcome)
                self.assertIsNone(decision.display)

    def test_git_push_force_detection_keeps_force_tokens_before_heredoc(self):
        cases = (
            ("git push origin '&&' --force-with-lease <<EOF\nsafe\nEOF", "git push to origin &&"),
            ("git push origin '&&' +topic/main:topic/main <<EOF\nsafe\nEOF", "git push to origin && +topic/main:topic/main"),
            ("git push origin HEAD:topic/main &&keep --force-with-lease <<EOF\nsafe\nEOF", "git push to origin HEAD:topic/main &&keep"),
            ("git push origin :topic/main <<EOF\nsafe\nEOF", "git push to origin :topic/main"),
        )
        for command, display in cases:
            with self.subTest(command=command):
                decision = self._shell(command)
                self.assertEqual("approval_required", decision.outcome)
                self.assertEqual("git.history_mutation", decision.consequence)
                self.assertEqual(display, decision.display)

    def test_structured_delete_is_approval_eligible(self):
        for payload in (
            {"tool_name": "delete_file", "tool_input": {"path": "/workspace/obsolete.py"}},
            {
                "tool_name": "apply_patch",
                "tool_input": {
                    "patch": "*** Begin Patch\n*** Delete File: /workspace/obsolete.py\n*** End Patch"
                },
            },
        ):
            with self.subTest(payload=payload):
                decision = self.kernel.evaluate(payload)
                self.assertEqual("approval_required", decision.outcome)
                self.assertEqual("filesystem.delete", decision.consequence)
                self.assertIn("obsolete.py", decision.display)

    def test_apply_patch_move_destination_honors_operator_only_roots(self):
        cases = (
            ("/home/test/.codex/hooks.json", "enforcement.modify"),
            ("/home/test/.codex/auth.json", "credentials.access"),
        )
        for destination, consequence in cases:
            with self.subTest(destination=destination):
                decision = self.kernel.evaluate(
                    {
                        "tool_name": "apply_patch",
                        "tool_input": {
                            "patch": (
                                "*** Begin Patch\n"
                                "*** Update File: /workspace/source.txt\n"
                                f"*** Move to: {destination}\n"
                                "@@\n"
                                "-before\n"
                                "+after\n"
                                "*** End Patch"
                            )
                        },
                    }
                )
                self.assertEqual("operator_only", decision.outcome)
                self.assertEqual(consequence, decision.consequence)

    def test_shell_workdir_resolves_relative_operator_only_paths(self):
        cases = (
            ("cat auth.json", "/home/test/.codex", "credentials.access"),
            ("tee hooks.json", "/home/test/.codex", "enforcement.modify"),
            ("cat id_ed25519", "/home/test/.ssh", "credentials.access"),
        )
        for command, workdir, consequence in cases:
            with self.subTest(command=command, workdir=workdir):
                decision = self.kernel.evaluate(
                    {
                        "tool_name": "exec_command",
                        "cwd": "/workspace",
                        "tool_input": {"cmd": command, "workdir": workdir},
                    }
                )
                self.assertEqual("operator_only", decision.outcome)
                self.assertEqual(consequence, decision.consequence)

    def test_direct_shell_write_variants_honor_enforcement_roots(self):
        commands = (
            "cp --target-directory=/home/test/.codex/hooks probe.py",
            "/bin/cp --target-directory=/home/test/.codex/hooks probe.py",
            "echo x >/home/test/.codex/hooks.json",
            "printf x>/home/test/.safe-yolo/policy.json",
            "echo x 2> /home/test/.codex/hooks/error.log",
            "echo x 2>/home/test/.codex/hooks/error.log",
            "touch /home/test/.codex/hooks.json",
            "truncate -s 0 /home/test/.safe-yolo/policy.json",
            "unlink /home/test/.codex/hooks.json",
            "rmdir /home/test/.codex/hooks",
        )
        for command in commands:
            with self.subTest(command=command):
                decision = self._shell(command)
                self.assertEqual("operator_only", decision.outcome)
                self.assertEqual("enforcement.modify", decision.consequence)

    def test_shell_input_redirection_honors_credential_roots(self):
        for command in (
            "cat </home/test/.codex/auth.json",
            "read secret 0</home/test/.ssh/id_ed25519",
        ):
            with self.subTest(command=command):
                decision = self._shell(command)
                self.assertEqual("operator_only", decision.outcome)
                self.assertEqual("credentials.access", decision.consequence)

    def test_structured_source_and_destination_aliases_honor_operator_roots(self):
        cases = (
            (
                {
                    "tool_name": "move_file",
                    "tool_input": {
                        "from": "/workspace/source.py",
                        "to": "/home/test/.codex/hooks.json",
                    },
                },
                "enforcement.modify",
            ),
            (
                {
                    "tool_name": "copy_file",
                    "tool_input": {
                        "source": "/workspace/source.py",
                        "destination": "/home/test/.codex/auth.json",
                    },
                },
                "credentials.access",
            ),
            (
                {
                    "tool_name": "write_file",
                    "tool_input": {"target_file": "/home/test/.safe-yolo/policy.json"},
                },
                "enforcement.modify",
            ),
        )
        for payload, consequence in cases:
            with self.subTest(payload=payload):
                decision = self.kernel.evaluate(payload)
                self.assertEqual("operator_only", decision.outcome)
                self.assertEqual(consequence, decision.consequence)

    def test_approval_summaries_name_the_direct_target(self):
        force_push = self._shell("git push --force-with-lease origin feature/x")
        production = self._shell("railway up")
        remote = self._shell("ssh -p 2222 production.example.com")

        self.assertIn("origin", force_push.display)
        self.assertIn("feature/x", force_push.display)
        self.assertIn("railway up", production.display)
        self.assertIn("production.example.com", remote.display)
        self.assertNotIn("to 2222", remote.display)

    def test_credential_dump_is_operator_only(self):
        for command in (
            "env",
            "env -0",
            "env --null",
            "env -u DEBUG",
            "printenv",
            "printenv -0",
            "printenv --null",
        ):
            with self.subTest(command=command):
                decision = self._shell(command)
                self.assertEqual("operator_only", decision.outcome)
                self.assertEqual("credentials.access", decision.consequence)

    def test_codex_adapter_factory_protects_only_fixed_enforcement_and_credential_roots(self):
        kernel = build_kernel(
            safe_yolo_home="/home/test/.safe-yolo",
            codex_home="/home/test/.codex",
            user_home="/home/test",
        )
        cases = (
            (
                {
                    "tool_name": "apply_patch",
                    "tool_input": {"path": "/home/test/.codex/config.toml"},
                },
                "enforcement.modify",
            ),
            (
                {
                    "tool_name": "read_file",
                    "tool_input": {"path": "/home/test/.ssh/id_ed25519"},
                },
                "credentials.access",
            ),
            (
                {
                    "tool_name": "read_file",
                    "tool_input": {"path": "/home/test/.gnupg/private-keys-v1.d/key"},
                },
                "credentials.access",
            ),
        )
        for payload, consequence in cases:
            with self.subTest(payload=payload):
                decision = kernel.evaluate(payload)
                self.assertEqual("operator_only", decision.outcome)
                self.assertEqual(consequence, decision.consequence)

    def _shell(self, command):
        return self.kernel.evaluate(
            {"tool_name": "Bash", "tool_input": {"command": command}}
        )


if __name__ == "__main__":
    unittest.main()
