import json
from pathlib import Path
import tempfile
import unittest

from scripts.doctor import codex_hook_approval, codex_hook_hash


# hooks.json groups and the `currentHash` Codex 0.172.0 reported for each (`codex app-server`, `hooks/list`).
CODEX_KNOWN_ANSWERS = [
    ({"matcher": "*", "hooks": [{
        "type": "command",
        "command": "/usr/bin/python3 /home/zoë/.safe-yolo/hooks/codex.py --harness codex --entry codex_v3 "
                   "--safe-yolo-home /home/zoë/.safe-yolo",
        "timeout": 10,
        "statusMessage": "Checking explicit Safe YOLO restrictions — ✓",
    }]}, "sha256:1cf1bbc0f4a7eb543de01cd5605e95a522181817e5427c716fba7e9e9bf5db97"),
    ({"hooks": [{"type": "command", "command": "python3 /opt/sy/hook.py --null-timeout", "timeout": None}]},
     "sha256:4ab3b5e2913c6f7b29b2141d00e7da60ae1ac00616bd63b6c22e1104860d5a5d"),
    ({"matcher": "*", "hooks": [{"type": "command", "command": "python3 /opt/sy/hook.py --limit", "timeout": 10,
                                 "additionalContextLimit": 4000}]},
     "sha256:802c30293c1c67290e33871eba4a8914f3740c55fed652b8d2692d651d6736ee"),
    ({"matcher": "*", "hooks": [{"type": "command", "command": "python3 /opt/sy/hook.py --limit", "timeout": 10,
                                 "additionalContextLimit": 2500}]},
     "sha256:fc93c86d51b291596332caf49e1db76a5a578943b9f776a35d64d0c38c2d7b0e"),
]
GROUP, HASH = CODEX_KNOWN_ANSWERS[0]


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
        self.write_group(GROUP)

    def write_group(self, group: dict) -> None:
        self.hooks.write_text(json.dumps({"hooks": {"PreToolUse": [group]}}))

    def save_state(self, state: str, before: str = 'approval_policy = "never"\n') -> None:
        self.config.write_text(f'{before}[hooks.state."{self.hooks.absolute()}:pre_tool_use:0:0"]\n{state}')

    def approval(self):
        return codex_hook_approval(self.hooks, self.config)

    def test_the_hash_matches_the_one_codex_computed(self):
        for group, expected in CODEX_KNOWN_ANSWERS:
            with self.subTest(group=group):
                self.assertEqual(expected, codex_hook_hash(group, group["hooks"][0]))

    def test_a_hook_field_the_hash_does_not_model_is_unknown(self):
        hook = GROUP["hooks"][0]
        for change in ({"commandWindows": "x"}, {"shell": "bash"}, {"timeout": "10"}, {"timeout": -1},
                       {"async": "false"}, {"statusMessage": 1}, {"additionalContextLimit": True}):
            with self.subTest(change=change):
                self.write_group({**GROUP, "hooks": [{**hook, **change}]})
                self.save_state(f'trusted_hash = "{HASH}"\n')
                self.assertEqual("unknown", self.approval()[0])
        self.write_group({**GROUP, "description": "x"})
        self.assertEqual("unknown", self.approval()[0])

    def test_the_approval_codex_saved_is_approved(self):
        self.save_state(f'trusted_hash = "{HASH}"\n')
        self.assertEqual(("approved", None), self.approval())
        self.save_state(f'trusted_hash = "{HASH}"\nenabled = true\ntrusted_content_hash = "sha256:x"\n')
        self.assertEqual(("approved", None), self.approval())

    def test_a_hook_never_approved_is_not_approved(self):
        self.config.write_text('approval_policy = "never"\n')
        self.assertEqual(("not approved", "no approval is saved"), self.approval())

    def test_an_update_leaves_the_old_approval_stale(self):
        self.save_state(f'trusted_hash = "{HASH}"\n')
        self.write_group({**GROUP, "hooks": [{**GROUP["hooks"][0], "command": "python3 other.py"}]})
        self.assertEqual(("not approved", "the saved approval is for a different hook"), self.approval())

    def test_a_hook_turned_off_in_codex_is_not_approved(self):
        self.save_state(f'trusted_hash = "{HASH}"\nenabled = false\n')
        self.assertEqual(("not approved", "the hook is turned off"), self.approval())

    def test_a_saved_state_codex_would_reject_is_unknown(self):
        other = '[hooks.state."/elsewhere/hooks.json:pre_tool_use:0:0"]\nenabled = "true"\n'
        for state, before in ((f'trusted_hash = "{HASH}"\nenabled = "true"\n', ""),
                              (f'trusted_hash = "{HASH}"\ntrusted = true\n', ""),
                              ("trusted_hash = 1\n", ""),
                              (f'trusted_hash = "{HASH}"\n', other)):
            with self.subTest(state=state, before=before):
                self.save_state(state, before)
                self.assertEqual("unknown", self.approval()[0])
        self.config.write_text('hooks = "on"\n')
        self.assertEqual("unknown", self.approval()[0])

    def test_an_unreadable_or_broken_config_is_unknown(self):
        self.config.write_text("[hooks.state\n")
        self.assertEqual(("unknown", "cannot read config.toml: TOMLDecodeError"), self.approval())
        self.config.write_bytes(b'approval_policy = "\xff"\n')
        self.assertEqual(("unknown", "cannot read config.toml: UnicodeDecodeError"), self.approval())
        self.config.unlink()
        self.assertEqual(("unknown", "cannot read config.toml: FileNotFoundError"), self.approval())


if __name__ == "__main__":
    unittest.main()
