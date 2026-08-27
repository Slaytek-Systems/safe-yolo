# Reversible 2.0 cutover plan

This repository produces a source candidate. It does not authorize installation or activation.

1. Validate the 2.0 kernel, ledger, release manifest, and executable hook journey from a clean source revision.
2. Obtain independent exact-revision review of the consequence list, operator-only boundaries, receipt binding, stored state, and adjacent denials.
3. Install the immutable candidate through an external operator-maintenance route on the disposable, credential-free, snapshot-backed pilot host.
4. Configure both `PreToolUse` for all supported local tools and `PostToolUse` for `request_user_input`. Keep the prior release and hook file available for atomic rollback.
5. Exercise fake-canary journeys: ordinary unknown tool, direct delete rejection, direct delete approval, altered retry, repeated retry, expired receipt, credential read, enforcement write, restart, and snapshot restore.
6. Re-audit host authority and recovery before any non-pilot activation. Broad provider credentials, unrecoverable persistent data, or unproved restore remain activation blockers; they are not reasons to expand the command classifier.
7. Activate one host through the operator route, read back the immutable release/hash/hook pin, and repeat the bounded journey.
8. Treat Cursor and unobserved Codex surfaces as separate parity work. Do not add permissive response parsing merely to claim cross-surface support.

After the operator installs and wires the pilot, prove both the immutable release and the two-hook lifecycle with the read-only doctor:

```sh
python3 scripts/doctor.py \
  --release /home/dev/.safe-yolo/releases/2.0.0-alpha.1 \
  --manifest-sha256 MANIFEST_SHA256 \
  --codex-config /home/dev/.codex/config.toml \
  --codex-hooks /home/dev/.codex/hooks.json \
  --bootstrap /home/dev/.safe-yolo/bootstrap.py \
  --entry codex_v2
```

The v2 doctor requires one `PreToolUse` command matched to `*` and one `PostToolUse` command matched to `request_user_input`, both pinned to the exact bootstrap, manifest hash, and `codex_v2` entrypoint.

## Deferred parity debt

- Cursor has no 2.0 adapter or ask-user receipt proof.
- Codex CLI/TUI response shapes have not been observed; only Codex Desktop is accepted by the candidate parser.
- Hooks cannot directly request approval, so one deny → ask → retry round trip remains.
- New semantic tools do not carry host-owned consequence metadata; unknown tools default to allow.
- The installed 1.x runtime remains active until a separately authorized pilot, review, recovery, and operator cutover complete.

All installation and hook changes are operator-maintenance actions. A governed Codex session may inspect source and health but cannot replace its own enforcement runtime.
