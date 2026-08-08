# devbox authoritative baseline

Captured from the active `/home/dev/.safe-yolo` and `~/.codex` installation during the initial Safe YOLO audit.

## Observed runtime

- Codex `0.147.0`; active app-server, app-server proxy, and resumed session.
- `approval_policy = "never"` and `sandbox_mode = "danger-full-access"`.
- One authoritative `PreToolUse` adapter, plus bounded prompt-maintenance authorization and session context.
- `bubblewrap 0.9.0` installed and unprivileged user namespaces enabled, although inactive under full access.
- Sanitized audit records confirm live hook decisions.
- The full local suite had 88 passing tests and one stale configuration assertion: Codex now writes inert `approvals_reviewer = "user"` metadata despite `approval_policy = "never"`.

## Integrity manifest

These SHA-256 values identify the audited active files:

| File | SHA-256 |
| --- | --- |
| `policy.json` | `0fc148cf0046ffa027022494af5d6809a82ed194dc2bf213c0fac3f64d58cb22` |
| `adapters/codex.py` | `d84fad95e67729ff94ae2a59b31f84bfc0948482564f2290696125fa6e71a510` |
| `adapters/codex_prompt.py` | `4ef1552d1b87c6bb7c54cd138c4d427d7463f0a703bad710349c7f51266b1d34` |
| `engine/safe_yolo.py` | `1a9c3bad8e49f34a6523866c95a738f0ba82b91b9a4cb17a3d13450017244f35` |
| `tests/cases.jsonl` | `71bc624b005aac294967eeb06e487382330a74fab510a2ef1019e1d39897b23d` |

The reference excludes all runtime state and credentials. The active devbox installation is unchanged.
