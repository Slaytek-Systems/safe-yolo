import json
import os
import tempfile
import time
import unittest
from pathlib import Path


from engine.capabilities import CapabilityStore


class CapabilityStoreTests(unittest.TestCase):
    def test_issue_requires_trusted_user_event(self):
        with tempfile.TemporaryDirectory() as temp:
            store = CapabilityStore(temp)
            with self.assertRaises(PermissionError):
                store.issue(
                    kind="action",
                    action="github.pr_merge",
                    session_id="session-1",
                    constraints={},
                    ttl_seconds=60,
                    user_authorized=False,
                )

    def test_state_permissions_are_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "capabilities"
            store = CapabilityStore(root)
            token = store.issue(
                kind="action",
                action="github.pr_merge",
                session_id="session-1",
                constraints={},
                ttl_seconds=60,
                user_authorized=True,
            )
            self.assertEqual(0o700, os.stat(root).st_mode & 0o777)
            self.assertEqual(0o600, os.stat(root / f"{token}.json").st_mode & 0o777)

    def test_expired_capability_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "capabilities"
            store = CapabilityStore(root)
            token = store.issue(
                kind="action",
                action="github.pr_merge",
                session_id="session-1",
                constraints={},
                ttl_seconds=60,
                user_authorized=True,
            )
            target = root / f"{token}.json"
            record = json.loads(target.read_text())
            record["expires_at"] = time.time() - 1
            target.write_text(json.dumps(record))
            request = {"session_id": "session-1"}
            self.assertIsNone(store.resolve(token, request))

    def test_revoke_session_invalidates_without_deleting_record(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "capabilities"
            store = CapabilityStore(root)
            token = store.issue(
                kind="action",
                action="github.pr_merge",
                session_id="session-1",
                constraints={},
                ttl_seconds=60,
                user_authorized=True,
            )
            store.revoke_session("session-1")
            target = root / f"{token}.json"
            self.assertTrue(target.exists())
            self.assertIsNone(store.resolve(token, {"session_id": "session-1"}))

    def test_active_capability_can_be_resolved_by_session(self):
        with tempfile.TemporaryDirectory() as temp:
            store = CapabilityStore(Path(temp) / "capabilities")
            store.issue(
                kind="maintenance",
                session_id="session-1",
                constraints={"harness": "codex", "scopes": ["hooks"]},
                ttl_seconds=60,
                user_authorized=True,
            )
            record = store.resolve_active({"session_id": "session-1"})
            self.assertEqual("maintenance", record["kind"])


if __name__ == "__main__":
    unittest.main()
