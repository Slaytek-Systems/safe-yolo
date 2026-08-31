# Reversible 3.0 cutover plan

This repository produces a source candidate. It does not authorize installation or activation.

1. Validate the 3.0 allow/deny policy, release manifest, and executable hook journey from a clean source revision.
2. Obtain independent exact-revision review of the deny set, allowed adjacent actions, denial guidance, and absence of approval state.
3. Install the immutable candidate through an external operator-maintenance route on the disposable, credential-free, snapshot-backed pilot host.
4. Configure one `PreToolUse` hook for all supported local tools. Remove the Safe YOLO `request_user_input` `PostToolUse` hook. Keep the prior release and hook file available for atomic rollback.
5. Exercise fake-canary journeys: ordinary unknown tool, feature push, PR creation, protected merge without bypass, direct delete denial, repeated identical denial, force-push denial, merge-bypass denial, credential read, enforcement write, restart, and snapshot restore.
6. Re-audit host authority and recovery before any non-pilot activation. Broad provider credentials, unrecoverable persistent data, or unproved restore remain activation blockers; they are not reasons to expand the command classifier.
7. Activate one host through the operator route, read back the immutable release/hash/hook pin, and repeat the bounded journey.
8. Treat Cursor and unobserved Codex surfaces as separate parity work. Do not add permissive response parsing merely to claim cross-surface support.

After the operator installs and wires the pilot, prove both the immutable release and the single-hook lifecycle with the read-only doctor:

```sh
python3 scripts/doctor.py \
  --release /home/dev/.safe-yolo/releases/3.0.0-alpha.1 \
  --manifest-sha256 MANIFEST_SHA256 \
  --codex-config /home/dev/.codex/config.toml \
  --codex-hooks /home/dev/.codex/hooks.json \
  --bootstrap /home/dev/.safe-yolo/bootstrap.py \
  --entry codex_v3
```

The v3 doctor requires one `PreToolUse` command matched to `*`, pinned to the exact bootstrap, manifest hash, and `codex_v3` entrypoint. It rejects a stale `request_user_input` `PostToolUse` hook.

## Deferred parity debt

- Cursor has no 3.0 deny-only adapter proof.
- New semantic tools do not carry host-owned consequence metadata; unknown tools default to allow.
- Host activation remains separate from repository state; each host keeps its prior immutable release until its separately authorized review, recovery, and operator cutover complete.

All installation and hook changes are operator-maintenance actions. A governed Codex session may inspect source and health but cannot replace its own enforcement runtime.
