# Reversible cutover plan

1. Import both existing host implementations as historical references; do not install either over the other.
2. Build a shared corpus from devbox’s authoritative tests and the Mac’s accumulated guard cases.
3. Resolve every disagreement in policy, not in host-specific ad hoc code.
4. Add a hash-verifying Codex bootstrap and `doctor` health check. On macOS, include `--macos-asset-recovery-home ~/.safe-yolo`; do not certify full local recovery unless a destination and completed backup are both present.
5. Run the new adapter on macOS in shadow mode next to legacy protection; investigate every meaningful decision difference.
6. After parity, atomically switch macOS to one authoritative adapter. Keep the previous release intact for rollback.
7. Upgrade devbox to the same released package and retain its current implementation as the immediate rollback target.
8. Enable contract-based production release only after independent evidence and adversarial tests exist.

All installer actions are explicit operator-maintenance actions. Codex sessions may inspect health, but cannot update their own policy/hook release.
