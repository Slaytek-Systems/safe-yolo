"""The hook command a harness sees stays byte-identical across Safe YOLO updates."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.distribute import doctor_harness, install_harness
from scripts.harness_wiring import pinned_command, render_opencode_plugin


ROOT = Path(__file__).resolve().parents[2]
COMMIT = "c" * 40
HARNESSES = ("codex", "claude-code", "cursor", "opencode", "antigravity")


def codex_trust_hash(group: dict, hook: dict) -> str:
    """The hash Codex stores as `trusted_hash` for one PreToolUse hook entry."""
    identity = {
        "event_name": "pre_tool_use",
        "matcher": group.get("matcher"),
        "hooks": [{
            "type": "command",
            "command": hook["command"],
            "timeout": hook.get("timeout"),
            "async": False,
            "statusMessage": hook.get("statusMessage"),
        }],
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class StableHookCommandTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.home = self.root / ".safe-yolo"
        self.user = self.root / "home"
        (self.user / ".codex").mkdir(parents=True)
        (self.user / ".codex" / "config.toml").write_text(
            'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
        (self.user / ".gemini" / "config").mkdir(parents=True)
        environment = patch.dict(os.environ)
        environment.start()
        self.addCleanup(environment.stop)
        for name in ("CODEX_HOME", "CLAUDE_CONFIG_DIR", "XDG_CONFIG_HOME", "OPENCODE_CONFIG_DIR", "GEMINI_HOME"):
            os.environ.pop(name, None)
        for target in ("scripts.distribute._require_opencode_v2",):
            patcher = patch(target)
            patcher.start()
            self.addCleanup(patcher.stop)
        verify = patch("scripts.distribute.verify_source", return_value=COMMIT)
        verify.start()
        self.addCleanup(verify.stop)

    def source(self, version: str) -> Path:
        source = self.root / f"source-{version}"
        for name in ("policy", "engine", "adapters"):
            shutil.copytree(ROOT / name, source / name, ignore=shutil.ignore_patterns("__pycache__"))
        (source / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts" / "bootstrap.py", source / "scripts" / "bootstrap.py")
        (source / "VERSION").write_text(f"{version}\n")
        return source

    def install(self, harness: str, version: str) -> dict:
        source = self.root / f"source-{version}"
        if not source.exists():
            self.source(version)
        return install_harness(harness=harness, source=source, safe_yolo_home=self.home,
                               user_home=self.user, expected_commit=COMMIT)

    def receipt(self, harness: str) -> dict:
        return json.loads((self.home / "state" / "installations" / f"{harness}.json").read_text())

    def config(self, harness: str) -> Path:
        return Path(self.receipt(harness)["config_path"])

    def command(self, harness: str) -> str:
        path = self.config(harness)
        if harness == "opencode":
            text = path.read_text()
            start = text.index("const COMMAND = ") + len("const COMMAND = ")
            return shlex.join(json.loads(text[start:text.index(";", start)]))
        document = json.loads(path.read_text())
        if harness == "cursor":
            return document["hooks"]["preToolUse"][0]["command"]
        if harness == "antigravity":
            return document["safe-yolo"]["PreToolUse"][0]["hooks"][0]["command"]
        return document["hooks"]["PreToolUse"][0]["hooks"][0]["command"]

    def decision(self, harness: str, shell_command: str, hook_command: str | None = None) -> str:
        """Run the harness's hook command as the harness would and name its decision."""
        cwd = str(self.root)
        payload = {
            "codex": {"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "exec_command",
                      "tool_input": {"cmd": shell_command}},
            "claude-code": {"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
                            "tool_input": {"command": shell_command}},
            "cursor": {"hook_event_name": "preToolUse", "cwd": cwd, "tool_name": "Shell",
                       "tool_input": {"command": shell_command}},
            "opencode": {"tool": "shell", "sessionID": "s", "callID": "c", "cwd": cwd,
                         "args": {"command": shell_command}},
            "antigravity": {"stepIdx": 0, "conversationId": "c", "workspacePaths": [cwd],
                            "toolCall": {"name": "run_command", "args": {"CommandLine": shell_command}}},
        }[harness]
        completed = subprocess.run(shlex.split(hook_command or self.command(harness)), input=json.dumps(payload),
                                   capture_output=True, text=True, check=False)
        if harness != "antigravity" and completed.returncode == 2:
            return "fail-closed" if "fail-closed" in completed.stderr else "error"
        if completed.returncode != 0:
            return "error"
        if not completed.stdout.strip():
            return "allow"
        reply = json.loads(completed.stdout)
        if harness == "cursor":
            return reply.get("permission", "error")
        if harness in ("opencode", "antigravity"):
            if "fail-closed" in str(reply.get("reason", "")):
                return "fail-closed"
            return reply.get("decision", "error")
        return reply["hookSpecificOutput"]["permissionDecision"]

    def tamper(self, release: Path) -> None:
        policy = next(path for path in sorted((release / "policy").rglob("*")) if path.is_file())
        policy.chmod(0o600)
        policy.write_bytes(policy.read_bytes() + b"\n")

    def test_update_leaves_every_harness_config_byte_identical(self):
        for harness in HARNESSES:
            self.install(harness, "3.0.0-beta.50")
        before = {harness: self.config(harness).read_bytes() for harness in HARNESSES}
        commands = {harness: self.command(harness) for harness in HARNESSES}

        for harness in HARNESSES:
            receipt = self.install(harness, "3.0.0-beta.51")
            self.assertEqual("3.0.0-beta.51", receipt["version"])

        for harness in HARNESSES:
            with self.subTest(harness=harness):
                self.assertEqual(before[harness], self.config(harness).read_bytes())
                self.assertEqual(commands[harness], self.command(harness))
                self.assertNotIn("releases", commands[harness])
                self.assertNotIn(self.receipt(harness)["manifest_sha256"], commands[harness])
                report = doctor_harness(harness=harness, safe_yolo_home=self.home, user_home=self.user)
                self.assertTrue(report["healthy"], report)
                self.assertEqual("3.0.0-beta.51", report["version"])

    def test_codex_trust_hash_survives_an_update(self):
        def trust_hash() -> str:
            document = json.loads((self.user / ".codex" / "hooks.json").read_text())
            group = document["hooks"]["PreToolUse"][0]
            return codex_trust_hash(group, group["hooks"][0])

        self.install("codex", "3.0.0-beta.50")
        before = trust_hash()
        self.install("codex", "3.0.0-beta.51")
        self.assertEqual(before, trust_hash())
        self.assertNotIn("trust its hash", self.receipt("codex")["next_action"].split(".")[0])

    def test_after_an_update_the_same_command_runs_the_new_release(self):
        for harness in HARNESSES:
            self.install(harness, "3.0.0-beta.50")
            self.install(harness, "3.0.0-beta.51")
        # A broken old release no longer matters; only the new release is verified and run.
        self.tamper(self.home / "releases" / "3.0.0-beta.50")
        for harness in HARNESSES:
            with self.subTest(harness=harness):
                self.assertEqual("allow", self.decision(harness, "git status --short"))
                self.assertEqual("deny", self.decision(harness, "git push --force origin main"))

    def test_a_receipt_pointing_at_a_tampered_release_fails_closed(self):
        for harness in HARNESSES:
            self.install(harness, "3.0.0-beta.50")
            self.install(harness, "3.0.0-beta.51")
        self.tamper(self.home / "releases" / "3.0.0-beta.51")
        for harness in HARNESSES:
            with self.subTest(harness=harness):
                self.assertEqual("fail-closed", self.decision(harness, "git status --short"))
                report = doctor_harness(harness=harness, safe_yolo_home=self.home, user_home=self.user)
                self.assertFalse(report["healthy"])

    def test_an_inactive_or_unreadable_receipt_fails_closed(self):
        for harness in ("codex", "antigravity"):
            self.install(harness, "3.0.0-beta.50")
        commands = {harness: self.command(harness) for harness in ("codex", "antigravity")}
        codex = self.home / "state" / "installations" / "codex.json"
        codex.write_text(json.dumps({**json.loads(codex.read_text()), "status": "inactive"}))
        (self.home / "state" / "installations" / "antigravity.json").write_text("{not json")
        for harness, command in commands.items():
            self.assertEqual("fail-closed", self.decision(harness, "git status --short", command))

    def test_the_launcher_is_refreshed_without_touching_the_command(self):
        self.install("codex", "3.0.0-beta.50")
        launcher = Path(shlex.split(self.command("codex"))[1])
        self.assertFalse(launcher.is_relative_to(self.home / "releases"))
        launcher.chmod(0o600)
        launcher.write_text("# stale\n")
        report = doctor_harness(harness="codex", safe_yolo_home=self.home, user_home=self.user)
        self.assertFalse(report["healthy"])
        self.assertTrue(any("launcher" in problem for problem in report["problems"]), report)
        self.install("codex", "3.0.0-beta.51")
        self.assertEqual((self.home / "releases" / "3.0.0-beta.51" / "scripts" / "bootstrap.py").read_bytes(),
                         launcher.read_bytes())

    def pin_like_beta_17(self, harness: str) -> None:
        """Rewrite an install the way 3.0.0-beta.17 and earlier wired it: the command names a release and digest."""
        receipt = self.receipt(harness)
        release = Path(receipt["release"])
        pinned = pinned_command(self.home, release, receipt["manifest_sha256"], {
            "codex": "codex_v3", "claude-code": "claude_code_v3", "cursor": "cursor_v3",
            "opencode": "opencode_v3", "antigravity": "antigravity_v3"}[harness],
            user_home=self.user, harness_home=Path(receipt["harness_home"]))
        path = self.config(harness)
        if harness == "opencode":
            payload = render_opencode_plugin(release, pinned)
        else:
            stable = json.dumps(self.command(harness))
            payload = path.read_bytes().replace(stable.encode(), json.dumps(pinned).encode())
        path.write_bytes(payload)
        legacy = {key: value for key, value in receipt.items() if key not in ("command", "launcher")}
        legacy["bootstrap"] = str(release / "scripts" / "bootstrap.py")
        legacy["installed_config_sha256"] = hashlib.sha256(payload).hexdigest()
        (self.home / "state" / "installations" / f"{harness}.json").write_text(json.dumps(legacy))
        Path(receipt["launcher"]).unlink()

    def test_one_update_migrates_a_pinned_command_and_later_updates_leave_it_alone(self):
        for harness in HARNESSES:
            self.install(harness, "3.0.0-beta.50")
            self.pin_like_beta_17(harness)
            self.assertIn("--manifest-sha256", self.command(harness))
        for harness in HARNESSES:
            self.install(harness, "3.0.0-beta.51")
        migrated = {harness: self.config(harness).read_bytes() for harness in HARNESSES}
        for harness in HARNESSES:
            with self.subTest(harness=harness):
                self.assertNotIn("--manifest-sha256", self.command(harness))
                self.assertEqual("deny", self.decision(harness, "git push --force origin main"))
            self.install(harness, "3.0.0-beta.52")
        for harness in HARNESSES:
            with self.subTest(harness=harness, step="second update"):
                self.assertEqual(migrated[harness], self.config(harness).read_bytes())
                report = doctor_harness(harness=harness, safe_yolo_home=self.home, user_home=self.user)
                self.assertTrue(report["healthy"], report)


if __name__ == "__main__":
    unittest.main()
