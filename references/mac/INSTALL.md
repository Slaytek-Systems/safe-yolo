# Codex Bootstrap and Rollback Plan

This plan installs Safe YOLO without replacing the live guardian in one unreviewable jump.

## Entry capability

Bootstrap requires this exact user command in the active conversation:

```text
/maintenance codex config instructions hooks scripts rules tests
```

The staged prompt adapter cannot enforce this until it is installed, so the first bootstrap records the command in its installation manifest as the human authorization event.

## Hard prerequisites

1. Rotate the Core credential previously exposed from `~/.codex/config.toml`.
2. Remove plaintext credential storage from the Codex configuration and replace it with the established injected-secrets mechanism.
3. Confirm the staged suite still passes immediately before installation.
4. Confirm no unrelated process is actively editing the live Codex hook files.

Credential rotation and secret-provider changes are separate externally consequential actions. They require explicit handling rather than being bundled invisibly into hook installation.

## Bootstrap sequence

1. Create a timestamped, read-only backup of:
   - `~/.codex/hooks.json`
   - `~/.codex/hooks/`
   - `~/.codex/scripts/`
   - `~/.codex/rules/default.rules`
   - relevant non-secret portions of `~/.codex/config.toml`
2. Install the staged package at `~/.safe-yolo/` without capability state or bytecode caches.
3. Set `~/.safe-yolo/state/` and capability records to private user-only permissions.
4. Register the staged UserPromptSubmit adapter before relying on Maintenance capabilities.
5. Register the staged PreToolUse adapter alongside the current guardian in audit-only mode.
6. Replay the shared corpus through both guardians and compare decisions.
7. Resolve every disagreement explicitly. Do not silently prefer the new engine.
8. Switch the canonical engine from audit-only to enforcement while retaining the old guardian as a second blocking layer.
9. Restore Stop validation intentionally, with read-only and discussion turns excluded.
10. Make literal credential-free public curl reads reachable by reconciling `default.rules` with the canonical network policy.
11. Run fresh-session smoke tests for Green, Blue, Amber, Red, Method-block, Maintenance, revocation, and protected-path behavior.
12. Keep the old guardian backup until multiple real sessions complete without unsafe gaps or unacceptable friction.

## Initial smoke matrix

Must allow:

- ordinary workspace patch;
- tests, builds, and local audits;
- literal public credential-free HTTP GET;
- task-aligned Core write;
- validated feature push;
- full PR creation.

Must block:

- force push;
- permanent deletion;
- shell and structured writes into protected paths outside Maintenance;
- inline opaque protected-path mutation;
- metadata access and local-file exfiltration;
- remote-script execution;
- production deploy without evidence or exact approval.

Must allow only with the matching capability:

- named Codex maintenance scopes;
- exact repository, PR, and merge method;
- exact repository and tag;
- exact production repository and target.

## Rollback

Rollback is restoration, not destructive cleanup:

1. Disable the new hook registrations.
2. Restore the timestamped hook and rule files from backup.
3. Start a fresh Codex session.
4. Re-run the old guardian's smoke probes.
5. Preserve the failed installation and audit records for diagnosis.

Do not delete `~/.safe-yolo` or capability audit records during rollback.

## Stop conditions

Stop bootstrap immediately if:

- a backup cannot be verified;
- the credential prerequisite remains unresolved;
- existing and staged guardians disagree on a constitutional Red case;
- the Codex hook payload lacks stable session and turn identifiers;
- a protected-path write succeeds without Maintenance;
- a safe ordinary workspace action becomes blocked with no precise policy reason.
