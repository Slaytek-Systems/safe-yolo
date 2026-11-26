import json
from pathlib import Path
import tempfile
import unittest

from scripts.doctor import codex_hook_approval, codex_hook_hash


# A hooks.json entry and the `currentHash` Codex 0.172.0 reported for it (`codex app-server`, `hooks/list`).
CODEX_KNOWN_ANSWER = (
    {"matcher": "*", "hooks": [{
        "type": "command",
        "command": "/usr/bin/python3 /home/zoë/.safe-yolo/hooks/codex.py --harness codex --entry codex_v3 "
                   "--safe-yolo-home /home/zoë/.safe-yolo",
        "timeout": 10,
        "statusMessage": "Checking explicit Safe YOLO restrictions — ✓",
    }]},
    "sha256:1cf1bbc0f4a7eb543de01cd5605e95a522181817e5427c716fba7e9e9bf5db97",
)


def approve(hooks: Path, config: Path) -> None:
    """What approving the hook in Codex `/hooks` saves to config.toml, replacing an earlier approval."""
    group = json.loads(hooks.read_text())["hooks"]["PreToolUse"][0]
    header = f'\n[hooks.state."{hooks.absolute()}:pre_tool_use:0:0"]\n'
    kept = config.read_text().split(header)[0]
    config.write_text(f'{kept}{header}trusted_hash = "{codex_hook_hash(group, group["hooks"][0])}"\n')


class CodexHookApprovalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.hooks = Path(temporary.name) / "hooks.json"
        self.config = Path(temporary.name) / "config.toml"
        self.config.write_text('approval_policy = "never"\n')
        self.write_hook("python3 bootstrap.py --release /r/3.0.0-beta.1")

    def write_hook(self, command: str) -> None:
        self.hooks.write_text(json.dumps({"hooks": {"PreToolUse": [
            {"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 10}]}]}}))

    def test_the_hash_matches_one_codex_computed(self):
        group, expected = CODEX_KNOWN_ANSWER
        self.assertEqual(expected, codex_hook_hash(group, group["hooks"][0]))

    def test_an_approved_hook_is_approved(self):
        approve(self.hooks, self.config)
        self.assertEqual(("approved", None), codex_hook_approval(self.hooks, self.config))

    def test_a_hook_never_approved_is_not_approved(self):
        self.assertEqual(("not approved", "no approval is saved"), codex_hook_approval(self.hooks, self.config))

    def test_an_update_leaves_the_old_approval_stale(self):
        approve(self.hooks, self.config)
        self.write_hook("python3 bootstrap.py --release /r/3.0.0-beta.2")
        self.assertEqual(("not approved", "the saved approval is for a different hook"),
                         codex_hook_approval(self.hooks, self.config))

    def test_a_hook_turned_off_in_codex_is_not_approved(self):
        approve(self.hooks, self.config)
        with self.config.open("a") as handle:
            handle.write("enabled = false\n")
        self.assertEqual(("not approved", "the hook is turned off"), codex_hook_approval(self.hooks, self.config))

    def test_an_unreadable_or_broken_config_is_unknown(self):
        self.config.write_text("[hooks.state\n")
        self.assertEqual(("unknown", "cannot read config.toml: TOMLDecodeError"),
                         codex_hook_approval(self.hooks, self.config))
        self.config.unlink()
        self.assertEqual(("unknown", "cannot read config.toml: FileNotFoundError"),
                         codex_hook_approval(self.hooks, self.config))


if __name__ == "__main__":
    unittest.main()
