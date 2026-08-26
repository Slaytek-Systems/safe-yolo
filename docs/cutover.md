# Reversible cutover plan

1. Import both existing host implementations as historical references; do not install either over the other.
2. Build a shared corpus from devbox’s authoritative tests and the Mac’s accumulated guard cases.
3. Resolve every disagreement in policy, not in host-specific ad hoc code.
4. Add a hash-verifying Codex bootstrap and `doctor` health check.
5. Run the new adapter on macOS in shadow mode next to legacy protection; investigate every meaningful decision difference.
6. After parity, atomically switch macOS to one authoritative adapter. Keep the previous release intact for rollback.
7. Upgrade devbox to the same released package and retain its current implementation as the immediate rollback target.
8. Enable contract-based production release only after independent evidence and adversarial tests exist.

Before activating a release that permits ordinary repository code, audit the host identity below the hook. Activation is blocked while that identity can reach unscoped production/provider authority, unrecoverable local state, or persistent data without a proved restore path. Fix those capabilities at their owning OS/provider/recovery layer; do not add script allowlists, content scanners, or another command broker to compensate.

All installer actions are explicit operator-maintenance actions. Codex sessions may inspect health, but cannot update their own policy/hook release.
