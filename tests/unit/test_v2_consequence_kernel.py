import unittest

from adapters.codex_v2 import build_kernel
from engine.consequences_v2 import ConsequenceKernel


class V2ConsequenceKernelTests(unittest.TestCase):
    def setUp(self):
        self.kernel = ConsequenceKernel(
            enforcement_paths=("/home/test/.safe-yolo", "/home/test/.codex/hooks.json"),
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
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual("allow", self._shell(command).outcome)

    def test_direct_approval_eligible_consequences(self):
        expected = {
            "rm -rf build": "filesystem.delete",
            "git push --force-with-lease origin feature/x": "git.history_mutation",
            "git -C /repo push --force origin feature/x": "git.history_mutation",
            "git reset --hard HEAD~1": "git.history_mutation",
            "railway up": "production.mutate",
            "fly deploy": "production.mutate",
            "vercel --prod": "production.mutate",
            "kubectl apply -f deployment.yaml": "production.mutate",
            "gh pr merge 123": "production.mutate",
            "ssh production.example.com": "remote.execute",
            "sudo touch /tmp/probe": "privilege.modify",
            "vite --host 0.0.0.0": "network.public_exposure",
            "python3 -m http.server --bind 0.0.0.0": "network.public_exposure",
        }
        for command, consequence in expected.items():
            with self.subTest(command=command):
                decision = self._shell(command)
                self.assertEqual("approval_required", decision.outcome)
                self.assertEqual(consequence, decision.consequence)

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

    def test_approval_summaries_name_the_direct_target(self):
        force_push = self._shell("git push --force-with-lease origin feature/x")
        production = self._shell("railway up")

        self.assertIn("origin", force_push.display)
        self.assertIn("feature/x", force_push.display)
        self.assertIn("railway up", production.display)

    def test_credential_dump_is_operator_only(self):
        for command in ("env", "printenv"):
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
