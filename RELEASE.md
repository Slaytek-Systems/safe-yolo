# Safe YOLO 3.0.0-beta.8

Git commands are now denied or allowed by whether they can lose work.

- Denied: forced `git rm`, `git checkout -f` or `git checkout .`,
  `git switch -f` or `--discard-changes`, `git stash drop` and `clear`,
  forced `git worktree remove`, `git reflog expire` and `delete`,
  `git gc --prune=now`, and `git filter-branch` or `filter-repo`.
- Denied as unverified ref deletion: `git branch -D`, `git branch -d --force`,
  and `git update-ref -d`. Plain `git branch -d` stays allowed because Git
  refuses to delete unmerged branches.
- Allowed: `git restore --staged`, which only changes the index. Restoring the
  working tree stays denied.
- A denied file deletion now suggests `git rm <path>` without `-f` for tracked
  files. Git keeps the file recoverable and refuses when it has local changes.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
