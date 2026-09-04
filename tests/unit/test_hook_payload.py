import unittest

from adapters.hook_payload import normalize_hook_payload


class HookPayloadTests(unittest.TestCase):
    def test_snake_case_payload_keeps_canonical_keys(self):
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "git status --short"},
            "session_id": "session-1",
            "cwd": "/home/dev/proj",
        }

        normalized = normalize_hook_payload(payload)

        self.assertEqual("PreToolUse", normalized["hook_event_name"])
        self.assertEqual("Bash", normalized["tool_name"])
        self.assertEqual({"command": "git status --short"}, normalized["tool_input"])
        self.assertEqual("session-1", normalized["session_id"])
        self.assertEqual("/home/dev/proj", normalized["cwd"])

    def test_grok_camel_case_payload_maps_to_snake_case(self):
        payload = {
            "hookEventName": "pre_tool_use",
            "sessionId": "abc",
            "cwd": "/home/dev/proj",
            "workspaceRoot": "/home/dev/proj",
            "permissionMode": "bypassPermissions",
            "toolName": "run_terminal_command",
            "toolInput": {"command": "npm test"},
            "toolUseId": "t1",
            "promptId": "p1",
        }

        normalized = normalize_hook_payload(payload)

        self.assertEqual("PreToolUse", normalized["hook_event_name"])
        self.assertEqual("abc", normalized["session_id"])
        self.assertEqual("/home/dev/proj", normalized["cwd"])
        self.assertEqual("/home/dev/proj", normalized["workspace_root"])
        self.assertEqual("bypassPermissions", normalized["permission_mode"])
        self.assertEqual("run_terminal_command", normalized["tool_name"])
        self.assertEqual({"command": "npm test"}, normalized["tool_input"])
        self.assertEqual("t1", normalized["tool_use_id"])
        self.assertEqual("p1", normalized["prompt_id"])
        self.assertNotIn("hookEventName", normalized)
        self.assertNotIn("toolName", normalized)

    def test_event_name_aliases_become_pre_tool_use(self):
        for event in ("PreToolUse", "pre_tool_use", "preToolUse"):
            with self.subTest(event=event):
                normalized = normalize_hook_payload({"hook_event_name": event})
                self.assertEqual("PreToolUse", normalized["hook_event_name"])

    def test_nested_tool_input_camel_case_keys_are_normalized(self):
        normalized = normalize_hook_payload(
            {
                "hookEventName": "preToolUse",
                "toolName": "read_file",
                "toolInput": {"filePath": "/tmp/notes.md", "targetFile": "/tmp/notes.md"},
            }
        )

        self.assertEqual("PreToolUse", normalized["hook_event_name"])
        self.assertEqual("/tmp/notes.md", normalized["tool_input"]["file_path"])
        self.assertEqual("/tmp/notes.md", normalized["tool_input"]["target_file"])

    def test_snake_case_wins_when_both_spellings_are_present(self):
        normalized = normalize_hook_payload(
            {
                "hook_event_name": "PostToolUse",
                "hookEventName": "pre_tool_use",
                "tool_name": "Bash",
                "toolName": "Write",
            }
        )

        self.assertEqual("PostToolUse", normalized["hook_event_name"])
        self.assertEqual("Bash", normalized["tool_name"])

    def test_cursor_and_opencode_identity_keys_are_normalized(self):
        normalized = normalize_hook_payload(
            {
                "hookEventName": "beforeShellExecution",
                "conversationId": "conv-1",
                "generationId": "gen-1",
                "workingDirectory": "/tmp/work",
                "sessionID": "session-open",
                "callID": "call-1",
            }
        )

        self.assertEqual("beforeShellExecution", normalized["hook_event_name"])
        self.assertEqual("conv-1", normalized["conversation_id"])
        self.assertEqual("gen-1", normalized["generation_id"])
        self.assertEqual("/tmp/work", normalized["working_directory"])
        self.assertEqual("session-open", normalized["session_id"])
        self.assertEqual("call-1", normalized["call_id"])


if __name__ == "__main__":
    unittest.main()
