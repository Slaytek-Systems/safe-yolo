# Safe YOLO 3.0.0-beta.8

More direct git commands that discard uncommitted work or force ref deletion
are now denied, and `git restore --staged` is allowed.

- Denied: forced `git rm`, `git checkout -f` or `git checkout .`,
  `git switch -f` or `--discard-changes`, `git stash drop` and `clear`,
  forced `git worktree remove`, `git reflog expire` and `delete`,
  `git gc --prune=now`, and `git filter-branch` or `filter-repo`.
- Denied as unverified ref deletion: `git branch -D`, `git branch -d --force`,
  and `git update-ref -d`. Plain `git branch -d` stays allowed because Git
  refuses to delete unmerged branches.
- Allowed: `git restore --staged`, which only changes the index. Restoring the
  working tree stays denied.
- Denied: forced `git push` written as a short cluster or abbreviation, such as
  `-fu` or `--forc`. Push option values, such as `-o -f`, are no longer read as
  flags.
- Denied as ref deletion or overwrite: `git push -ud` or `--del`, and
  `git branch -M`, `-C`, `-m -f`, or `-c -f`. Plain `git branch -m` and `-c`
  stay allowed because Git refuses to overwrite an existing branch.
- Denied: `gt submit --force` and its aliases. Plain `gt submit` stays allowed
  because it pushes with a lease.
- Git global options such as `-P`, `--namespace`, and attached `-C<path>` no
  longer hide the command that follows them.
- A denied file deletion now suggests `git rm <path>` without `-f` for tracked
  files. Git keeps the file recoverable and refuses when it has local changes.

Linux/Python 3.12+ is the proven platform. Codex, Claude Code, and Cursor have
installation lifecycles. Native hook trust or restart remains harness-specific.
Local customizations are preserved. The custom distribution permission remains
in effect; publication is not a change to an OSI-approved license.
