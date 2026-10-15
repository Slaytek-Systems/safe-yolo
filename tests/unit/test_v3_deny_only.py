import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from adapters.codex_v3 import build_kernel, handle_pre_tool


ROOT = Path(__file__).resolve().parents[2]


class V3DenyOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.root = root
        self.kernel = build_kernel(
            safe_yolo_home=root / "safe-yolo",
            codex_home=root / "codex",
            user_home=root / "home",
        )

    def tearDown(self):
        self.temp.cleanup()

    def payload(self, command: str) -> dict:
        return {
            "hook_event_name": "PreToolUse",
            "cwd": "/workspace",
            "tool_name": "exec_command",
            "tool_input": {"cmd": command},
        }

    def test_ordinary_work_and_guarded_shipping_default_to_allow(self):
        commands = (
            "git status --short",
            "git push -u origin fix/safe-yolo",
            "gh pr create --fill",
            "gh pr merge 232 --merge --delete-branch",
            "gh release create --help",
            "railway up --help",
            "kubectl delete --help",
            "ssh -V",
            "sudo --version",
            "python3 -m unittest discover -s tests/unit",
        )

        for command in commands:
            with self.subTest(command=command):
                self.assertIsNone(handle_pre_tool(self.payload(command), self.kernel))

        unknown = {
            "hook_event_name": "PreToolUse",
            "cwd": "/workspace",
            "tool_name": "future_tool",
            "tool_input": {"action": "ordinary"},
        }
        self.assertIsNone(handle_pre_tool(unknown, self.kernel))

    def test_explicit_restrictions_are_stable_denials_without_approval(self):
        commands = {
            "rm obsolete.txt": "filesystem.delete",
            "git push --force-with-lease": "git.history_mutation",
            "gh pr merge 232 --merge --admin": "production.mutate",
            "gh pr merge 232 --merge --admin=true": "production.mutate",
            "gh -R owner/other pr merge 232 --merge": "production.mutate",
            "gh -Rowner/other pr merge 232 --merge": "production.mutate",
            "gh -R=owner/other pr merge 232 --merge": "production.mutate",
            "gh pr merge 232 -Rowner/other --merge": "production.mutate",
            "gh pr merge 232 --repo=owner/other --merge": "production.mutate",
            "gh release create v3.0.0": "production.mutate",
            "railway up": "production.mutate",
            "ssh example.com": "remote.execute",
            "sudo apt update": "privilege.modify",
            "vite --host 0.0.0.0": "network.public_exposure",
        }

        for command, consequence in commands.items():
            with self.subTest(command=command):
                first = handle_pre_tool(self.payload(command), self.kernel)
                second = handle_pre_tool(self.payload(command), self.kernel)
                self.assertEqual(first, second)
                self.assertEqual(
                    "deny",
                    first["hookSpecificOutput"]["permissionDecision"],
                )
                reason = first["hookSpecificOutput"]["permissionDecisionReason"]
                self.assertIn(consequence, reason)
                self.assertIn("different safe method", reason)
                self.assertNotIn("request_user_input", reason)
                self.assertNotIn("approval", reason.lower())

    def test_kernel_contract_has_only_allow_or_deny_outcomes(self):
        allowed = self.kernel.evaluate(self.payload("git status --short"))
        denied = self.kernel.evaluate(self.payload("rm obsolete.txt"))

        self.assertEqual("allow", allowed.outcome)
        self.assertEqual("deny", denied.outcome)
        self.assertNotIn(denied.outcome, {"approval_required", "operator_only"})

    def test_unverified_ref_deletion_routes_to_guarded_branch_retirement(self):
        denial = handle_pre_tool(
            self.payload(
                "git push origin --delete task/one task/two release/candidate"
            ),
            self.kernel,
        )

        reason = denial["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("git.delete_ref", reason)
        self.assertIn("guarded merged-branch retirement workflow", reason)
        self.assertNotIn("additive commit", reason)

    def test_git_forms_that_discard_work_or_force_ref_deletion_are_denied(self):
        denied = {
            "git rm -f a": "git.history_mutation",
            "git rm --force a": "git.history_mutation",
            "git rm -rf src": "git.history_mutation",
            "git rm -fr src": "git.history_mutation",
            "git rm -q -f a": "git.history_mutation",
            "git -C /x rm -f a": "git.history_mutation",
            "git checkout -f main": "git.history_mutation",
            "git checkout --force main": "git.history_mutation",
            "git checkout .": "git.history_mutation",
            "git checkout HEAD -- a.py": "git.history_mutation",
            "git switch --discard-changes main": "git.history_mutation",
            "git switch -f main": "git.history_mutation",
            "git switch --force main": "git.history_mutation",
            "git stash drop": "git.history_mutation",
            "git stash clear": "git.history_mutation",
            "git worktree remove --force ../wt": "git.history_mutation",
            "git worktree remove -f ../wt": "git.history_mutation",
            "git reflog expire --expire=now --all": "git.history_mutation",
            "git reflog delete HEAD@{1}": "git.history_mutation",
            "git gc --prune=now": "git.history_mutation",
            "git gc --prune=all": "git.history_mutation",
            "git filter-branch --tree-filter true HEAD": "git.history_mutation",
            "git filter-repo --path secret.txt --invert-paths": "git.history_mutation",
            "git restore a.py": "git.history_mutation",
            "git restore --source=HEAD a": "git.history_mutation",
            "git restore --staged --worktree a.py": "git.history_mutation",
            "git restore -SW a.py": "git.history_mutation",
            "git branch -D feat": "git.delete_ref",
            "git branch --delete --force feat": "git.delete_ref",
            "git branch -d -f feat": "git.delete_ref",
            "git branch -df feat": "git.delete_ref",
            "git update-ref -d refs/heads/x": "git.delete_ref",
            "git update-ref --delete refs/heads/x": "git.delete_ref",
        }
        for command, consequence in denied.items():
            with self.subTest(command=command):
                decision = self.kernel.evaluate(self.payload(command))
                self.assertEqual(("deny", consequence), (decision.outcome, decision.consequence))

    def test_git_forms_that_keep_work_recoverable_are_allowed(self):
        commands = (
            "git restore --staged a.py",
            "git restore -S a.py",
            "git rm a",
            "git rm -r src",
            "git rm --cached x",
            "git rm -- -f",
            "git mv a b",
            "git stash",
            "git stash pop",
            "git stash apply",
            "git worktree remove ../wt",
            "git branch -d feat",
            "git reset --soft HEAD~1",
            "git reset HEAD~1",
            "git reset --keep HEAD~1",
            "git gc",
            "git reflog",
            "git clean -n",
            "git checkout main",
            "git checkout -b feat",
            "git switch -c feat",
            "git switch main",
            "git commit --amend --no-edit",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNone(handle_pre_tool(self.payload(command), self.kernel))

    def test_git_option_values_and_long_abbreviations_are_read_as_git_reads_them(self):
        denied = {
            "git restore -sSAFE a.py": "git.history_mutation",
            "git restore -s SAFE a.py": "git.history_mutation",
            "git restore --source SAFE a.py": "git.history_mutation",
            "git restore -sSAFE README.md": "git.history_mutation",
            "git restore --staged --work a.py": "git.history_mutation",
            "git restore --staged --work README.md": "git.history_mutation",
            "git restore -S --w a.py": "git.history_mutation",
            "git restore --s a.py": "git.history_mutation",
            "git checkout --forc feat": "git.history_mutation",
            "git checkout -bfeat --forc": "git.history_mutation",
            "git rm --forc a": "git.history_mutation",
            "git switch --discard main": "git.history_mutation",
            "git worktree remove --forc ../wt": "git.history_mutation",
            "git gc --prun=now": "git.history_mutation",
            "git branch --del --forc feat": "git.delete_ref",
            "git update-ref --del refs/heads/x": "git.delete_ref",
        }
        for command, consequence in denied.items():
            with self.subTest(command=command):
                decision = self.kernel.evaluate(self.payload(command))
                self.assertEqual(("deny", consequence), (decision.outcome, decision.consequence))
        allowed = (
            "git checkout -b feat",
            "git checkout -bfeat",
            "git checkout -Bfeat",
            "git checkout -q -bfeature",
            "git checkout --orphan f",
            "git switch -c fix",
            "git switch -cfix2",
            "git switch -qcfix",
            "git switch --create f main",
            "git restore --staged a.py",
            "git restore -S a.py",
            "git restore --stag a.py",
            "git restore --staged --source=HEAD a.py",
            "git restore --source HEAD -S a.py",
            "git restore -S --source W a.py",
            "git branch -uorigin/f feat",
            "git update-ref -m d refs/heads/x HEAD",
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertIsNone(handle_pre_tool(self.payload(command), self.kernel))

    def test_forced_push_branch_overwrite_and_graphite_force_submit_are_denied(self):
        denied = {
            "git push -fu origin x": "git.history_mutation",
            "git push -uf origin x": "git.history_mutation",
            "git push --forc origin x": "git.history_mutation",
            "git push --force-with-lease=x:abc origin x": "git.history_mutation",
            "git push --force-if-includes --force-with-lease origin x": "git.history_mutation",
            "git push --mirr origin": "git.history_mutation",
            "git push -o ci.skip origin +x": "git.history_mutation",
            "git push origin -- +x": "git.history_mutation",
            "git push -ud origin x": "git.delete_ref",
            "git push --del origin x": "git.delete_ref",
            "git push -o ci.skip origin :x": "git.delete_ref",
            "git -cfoo.bar=baz rm -f a": "git.history_mutation",
            "git -C/x rm -f a": "git.history_mutation",
            "git -P rm -f a": "git.history_mutation",
            "git --namespace x rm -f a": "git.history_mutation",
            "git --config-env foo.bar=HOME rm -f a": "git.history_mutation",
            "git --attr-source HEAD rm -f a": "git.history_mutation",
            "git --no-replace-objects --exec-path=/x rm -f a": "git.history_mutation",
            "git branch -M feat main": "git.delete_ref",
            "git branch -C feat main": "git.delete_ref",
            "git branch -m -f old new": "git.delete_ref",
            "git branch -mf old new": "git.delete_ref",
            "git branch --move --force old new": "git.delete_ref",
            "git branch -c -f a b": "git.delete_ref",
            "git branch --copy --force a b": "git.delete_ref",
            "gt submit --force": "git.history_mutation",
            "gt submit -f": "git.history_mutation",
            "gt submit -nf": "git.history_mutation",
            "gt submit --comment -f": "git.history_mutation",
            "gt --cwd /x submit --force": "git.history_mutation",
            "gt s --force": "git.history_mutation",
            "gt ss --force": "git.history_mutation",
            "gt stack submit --force": "git.history_mutation",
            "gt stack s -f": "git.history_mutation",
            "gt downstack submit --force": "git.history_mutation",
            "gt upstack submit -f": "git.history_mutation",
        }
        for command, consequence in denied.items():
            with self.subTest(command=command):
                decision = self.kernel.evaluate(self.payload(command))
                self.assertEqual(("deny", consequence), (decision.outcome, decision.consequence))
        allowed = (
            "git push -u origin feat/x",
            "git push origin HEAD:feat/x",
            "git -C /w push origin feat/x",
            "git push --force-if-includes origin x",
            "git push -o -f origin x",
            "git push --push-option -d origin x",
            "git push --repo -f origin x",
            "git push --receive-pack -d origin x",
            "git push --recurse-submodules check origin x",
            "git push --dry-run origin x",
            "git push --follow-tags origin x",
            "git push --no-force origin x",
            "git -P status",
            "git --namespace x push origin feat/x",
            "git branch -m old new",
            "git branch -c a b",
            "git branch --move old new",
            "gt submit",
            "gt submit --stack",
            "gt ss",
            "gt sync",
            "gt restack",
            "gt modify",
            "gt submit --comment fix",
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertIsNone(handle_pre_tool(self.payload(command), self.kernel))

    def test_file_deletion_denial_names_git_rm_for_tracked_files(self):
        denial = handle_pre_tool(
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/workspace",
                "tool_name": "apply_patch",
                "tool_input": {"patch": "*** Begin Patch\n*** Delete File: /workspace/obsolete.py\n*** End Patch"},
            },
            self.kernel,
        )

        reason = denial["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("[filesystem.delete]", reason)
        self.assertIn("`git rm <path>` (without -f) for git-tracked files", reason)

    def test_ssh_transport_and_visible_commands_share_the_consequence_kernel(self):
        allowed = (
            "ssh -N -L 8080:localhost:80 devbox",
            "ssh -n devbox hostname",
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertIsNone(handle_pre_tool(self.payload(command), self.kernel))

        denied = {
            "ssh devbox": "remote.execute",
            'ssh devbox "rm -rf build"': "filesystem.delete",
            "ssh -o 'RemoteCommand=sudo touch /tmp/probe' devbox": "privilege.modify",
            "ssh -F /tmp/alternate-config devbox hostname": "remote.execute",
        }
        for command, consequence in denied.items():
            with self.subTest(command=command):
                result = handle_pre_tool(self.payload(command), self.kernel)
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                self.assertIn(
                    consequence,
                    result["hookSpecificOutput"]["permissionDecisionReason"],
                )

    def decide(self, command: str) -> tuple[str, str | None]:
        decision = self.kernel.evaluate(
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/workspace/repo",
                "tool_name": "exec_command",
                "tool_input": {"cmd": command},
            }
        )
        return decision.outcome, decision.consequence

    def assertDecisions(self, expected: dict[str, tuple[str, str | None]]):
        for command, decision in expected.items():
            with self.subTest(command=command):
                self.assertEqual(decision, self.decide(command))

    def test_credential_path_before_attached_redirection_is_denied(self):
        key = self.root / "home" / ("." + "ssh") / "id_rsa"
        self.assertDecisions({
            f"cat {key}{redirect}": ("deny", "credentials.access")
            for redirect in (">/tmp/x", "</dev/null", ">>/tmp/x", "2>/tmp/x")
        })

    def test_credential_directory_globs_are_denied(self):
        ssh = self.root / "home" / ("." + "ssh")
        ssh.mkdir(parents=True)
        (ssh / "id_rsa").write_text("FAKE\n")
        self.assertDecisions({
            f"cat {self.root}/{directory}/{ssh.name}/id_rsa": ("deny", "credentials.access")
            for directory in ("h*", "h?me", "[h]ome")
        })

    def test_attached_short_option_credential_values_are_denied(self):
        key = self.root / "home" / ("." + "ssh") / "id_rsa"
        self.assertDecisions({
            f"{command}{key}{tail}": ("deny", "credentials.access")
            for command, tail in (("ssh-keyscan -f", ""), ("grep -f", " x"), ("cat -x", ""))
        })
        with patch.dict(os.environ, HOME=str(self.root / "home")):
            self.assertDecisions({
                "grep -f~/" + ("." + "ssh") + "/id_rsa x": ("deny", "credentials.access"),
            })

    def test_globs_reaching_protected_roots_are_denied_when_nothing_exists(self):
        ssh = "." + "ssh"
        with patch.dict(os.environ, HOME=str(self.root / "home")):
            self.assertDecisions({
                **dict.fromkeys((
                    f"cat {self.root}/*/{ssh}/id_rsa",
                    f"cat {self.root}/[a-z]*/{ssh}/id_rsa",
                    f"cat {self.root}/h**/{ssh}/id_rsa",
                    "cat ~/.s*/id_rsa",
                    "cat ~/.s?h/id_rsa",
                    "cat ~/.[^x]sh/id_rsa",
                    "ls ~/.*/",
                    "ls ~/.s*",
                    "grep -r x ~/.*",
                    f"cat {self.root}/codex/*.json",
                    f"cat x>{self.root}/*/{ssh}/id_rsa",
                ), ("deny", "credentials.access")),
                **dict.fromkeys((
                    f"touch {self.root}/codex/c*.toml",
                    f"echo x > {self.root}/codex/c*.toml",
                    f"cp a {self.root}/s*-yolo/x",
                ), ("deny", "enforcement.modify")),
            })

    def test_globs_follow_dotfile_rules_and_allow_parent_listings(self):
        home = self.root / "home"
        home.mkdir()
        for index in range(300):
            (home / f"file-{index}").touch()
        with patch.dict(os.environ, HOME=str(home)):
            self.assertDecisions(dict.fromkeys((
                "ls ~/*", "du -sh ~/*", "cp ~/* /tmp/backup/", "cat ~/*/id_rsa",
                "ls /*/*", "du -sh /*/*", f"ls {self.root}/home/*/*", f"ls {self.root}/*",
                f"cat {self.root}/codex/*.toml", "cat ~/.c*/id_rsa",
            ), ("allow", None)))

    def test_glob_decisions_do_not_walk_the_filesystem(self):
        installed = self.root / ".installed"
        self.kernel = build_kernel(
            safe_yolo_home=installed / "safe-yolo",
            codex_home=installed / "codex",
            user_home=installed / "home",
        )
        for command in (
            "ls /*/*/*/*/zzz",
            "ls /*/*/*/*/*/zzz",
            "ls /proc/*/root/*/*/zzz",
        ):
            with self.subTest(command=command):
                started = time.perf_counter()
                self.assertEqual(("allow", None), self.decide(command))
                self.assertLess(time.perf_counter() - started, 0.5)

    def test_globs_reaching_non_dot_private_paths_are_denied(self):
        home = self.root / "home"
        settings = self.root / "safe-yolo" / "customizations.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"private_paths": [str(home / "secrets")]}))
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            codex_home=self.root / "codex",
            user_home=home,
        )
        with patch.dict(os.environ, HOME=str(home)):
            self.assertDecisions({
                "cat ~/*/key": ("deny", "credentials.access"),
                "ls ~/*": ("deny", "credentials.access"),
                "cp ~/s*/key /tmp/x": ("deny", "credentials.access"),
                "ls ~/w*": ("allow", None),
            })

    def test_attached_identity_values_are_key_use(self):
        ssh = self.root / "home" / ("." + "ssh")
        self.assertDecisions({
            f"ssh -i{ssh}/id_ed25519 host true": ("allow", None),
            f"ssh -vi{ssh}/id_ed25519 host true": ("allow", None),
            f"scp -i{ssh}/id_ed25519 a host:b": ("allow", None),
            f"scp -i{ssh}/id_ed25519 {ssh}/id_rsa host:b": ("deny", "credentials.access"),
            f"ssh -i{ssh}/id_ed25519 host true >{ssh}/x": ("deny", "credentials.access"),
        })
        settings = self.root / "safe-yolo" / "customizations.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"private_paths": [str(ssh)]}))
        self.kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            codex_home=self.root / "codex",
            user_home=self.root / "home",
        )
        self.assertDecisions({
            f"ssh -i{ssh}/id_ed25519 host true": ("deny", "credentials.access"),
            f"scp -i{ssh}/id_ed25519 a host:b": ("deny", "credentials.access"),
        })

    def test_home_variable_prefix_reaches_credentials(self):
        home = self.root / "home"
        ssh = "." + "ssh"
        with patch.dict(os.environ, HOME=str(home)):
            self.assertDecisions({
                f"cat $HOME/{ssh}/id_rsa": ("deny", "credentials.access"),
                f"cat ${{HOME}}/{ssh}/id_rsa": ("deny", "credentials.access"),
                f"cat \"$HOME/{ssh}/id_rsa\"": ("deny", "credentials.access"),
                f"grep --file=$HOME/{ssh}/id_rsa x": ("deny", "credentials.access"),
                f"cat $HOME/.s*/id_rsa": ("deny", "credentials.access"),
                f"cat $HOME/{ssh}/id_rsa.pub": ("allow", None),
                "cat $HOME/notes.txt": ("allow", None),
                "cat $HOMEDIR/x": ("allow", None),
                "rm $HOME/tmp/x": ("deny", "filesystem.delete"),
            })

    def test_literal_redirection_and_glob_readings_remain_protected(self):
        ssh = self.root / "home" / ("." + "ssh")
        ssh.mkdir(parents=True)
        (ssh / "id_rsa").write_text("FAKE\n")
        (self.root / "|keys").symlink_to(ssh)
        self.assertDecisions({
            f"cat '{self.root}/h*/{ssh.name}/id_rsa'": ("deny", "credentials.access"),
            f"cat '{ssh}/id_rsa>/tmp/x'": ("deny", "credentials.access"),
            f"cat <'{self.root}/|keys/id_rsa'": ("deny", "credentials.access"),
        })

    def test_spaced_clobber_enforcement_target_is_denied(self):
        config = self.root / "codex" / "config.toml"
        self.assertDecisions({
            f"echo x {operator} {config}": ("deny", "enforcement.modify")
            for operator in (">|", "1>|", "2>|")
        })

    def test_production_global_options_before_destroy_are_denied(self):
        self.assertDecisions(dict.fromkeys((
            "fly --access-token x apps destroy app",
            "flyctl -t x apps destroy app",
            "fly --access-token=x machine destroy abc",
            "flyctl -tx destroy app",
            "vercel --token x remove proj --yes",
            "vc --scope team rm proj",
            "vercel -t x rollback",
            "vc --cwd /tmp/project --scope=team promote dpl_123",
            "fly -a app apps destroy",
            "fly --app app apps destroy",
            "flyctl -aapp apps destroy",
            "fly --app=app machine destroy abc",
            "fly -c fly.toml apps destroy app",
            "fly --config fly.toml -a app apps destroy",
        ), ("deny", "production.mutate")))
        self.assertDecisions(dict.fromkeys((
            "fly -a app status", "fly --app destroy status", "fly -c destroy logs",
        ), ("allow", None)))

    def test_residual_hardening_preserves_ordinary_work_and_denial_reasons(self):
        self.assertDecisions(dict.fromkeys((
            "ls -la", "grep -n foo src/*.py", "cat a>b", "cp -r src/* out/",
            "git log --since=2.weeks", "npm run build -- --flag=x/y",
            "fly --access-token destroy status", "vercel --token remove ls",
            "vc --scope team rollback status", "vercel --token x promote status",
        ), ("allow", None)))
        key = self.root / "home" / ("." + "ssh") / "id_rsa"
        self.assertDecisions({
            f"rm -f{key}": ("deny", "filesystem.delete"),
            f"sudo cat {key}>/tmp/x": ("deny", "privilege.modify"),
            f"A=1 rm -f{key}": ("deny", "filesystem.delete"),
            f"A=1 sudo cat {key}>/tmp/x": ("deny", "privilege.modify"),
        })

    def test_ssh_short_option_clusters_consume_their_values(self):
        allow = ("allow", None)
        self.assertDecisions(
            {
                "ssh -tp 2222 host rm -rf /srv/data": ("deny", "filesystem.delete"),
                "ssh -tl admin host sudo reboot": ("deny", "privilege.modify"),
                "ssh -vp 2222 host": ("deny", "remote.execute"),
                "ssh -vp2222 host": ("deny", "remote.execute"),
                "ssh -Ai deploy_key host": ("deny", "remote.execute"),
                "ssh -tFalternate host uptime": ("deny", "remote.execute"),
                "ssh -np 2222 host uptime": allow,
                "ssh -NL 8080:localhost:80 host": allow,
                "ssh -nl admin host hostname": allow,
            }
        )

    def test_leading_assignments_do_not_hide_the_executable(self):
        self.assertDecisions(
            {
                "FOO=1 rm -rf build": ("deny", "filesystem.delete"),
                "FOO=1 sudo ls": ("deny", "privilege.modify"),
                "KUBECONFIG=prod.yaml kubectl apply -f x.yaml": ("deny", "production.mutate"),
                "GH_TOKEN=x gh release create v1": ("deny", "production.mutate"),
                "A=1 B=2 git reset --hard": ("deny", "git.history_mutation"),
                "FOO=1 ssh -p 2222 host rm -rf /srv/data": ("deny", "filesystem.delete"),
                "ssh host FOO=1 rm -rf /srv/data": ("deny", "filesystem.delete"),
                "FOO=1 npm test": ("allow", None),
                "FOO=1 rm -rf /tmp/build": ("allow", None),
                "env FOO=1 rm -rf build": ("allow", None),
            }
        )

    def test_quoted_or_escaped_assignment_words_run_as_commands(self):
        self.assertDecisions(
            {
                "'FOO=/bin/rm' -rf build": ("deny", "filesystem.delete"),
                '"FOO=/bin/rm" -rf build': ("deny", "filesystem.delete"),
                "FOO\\=/bin/rm -rf build": ("deny", "filesystem.delete"),
                "F'OO'=/bin/rm -rf build": ("deny", "filesystem.delete"),
                "FOO='a b' rm -rf build": ("deny", "filesystem.delete"),
                'FOO="x" sudo ls': ("deny", "privilege.modify"),
                "NODE_ENV=test npm test": ("allow", None),
                "FOO=1 make": ("allow", None),
            }
        )

    def test_assignment_prefixes_never_remove_a_denial(self):
        config = self.root / "codex" / "config.toml"
        key = self.root / "home" / ".ssh" / "id_ed25519"
        modify = ("deny", "enforcement.modify")
        credentials = ("deny", "credentials.access")
        delete = ("deny", "filesystem.delete")
        self.assertDecisions(
            {
                f"FOO=1 >{config}": modify,
                f"FOO=1 > {config}": modify,
                f"FOO='a b' 2>{config}": modify,
                f"FOO=1 >>{config}": modify,
                f"FOO=1 BAR=2 >{config}": modify,
                f"FOO=1 <{key}": credentials,
                f"FOO=1 < {key}": credentials,
                "FOO=/bin/rm -rf build": delete,
                " BAR=/bin/rm -rf build": delete,
                "\vBAR=/bin/rm -rf build": delete,
                "\fBAR=/bin/rm -rf build": delete,
                " BAR=/bin/rm -rf build": delete,
                "\rBAR=/bin/rm -rf build": delete,
            }
        )

    def test_shred_and_truncate_destroy_content_like_rm(self):
        config = self.root / "codex" / "config.toml"
        key = self.root / "home" / ".ssh" / "id_ed25519"
        delete = ("deny", "filesystem.delete")
        allow = ("allow", None)
        self.assertDecisions(
            {
                "shred f": delete,
                "shred -u f": delete,
                "/usr/bin/shred -zu f": delete,
                "shred --remove f": delete,
                "shred --remove=unlink -n 3 f": delete,
                "truncate -s 0 data.db": delete,
                "truncate -s0 data.db": delete,
                "truncate --size=0 data.db": delete,
                "truncate --size 0 data.db": delete,
                "truncate -r ref.db data.db": delete,
                "truncate -s +1M data.db": delete,
                f"shred -u {config}": ("deny", "enforcement.modify"),
                f"truncate -s 0 {config}": ("deny", "enforcement.modify"),
                f"shred -u {key}": ("deny", "credentials.access"),
                "shred -u /tmp/scratch.db": allow,
                "shred -n 3 -u /tmp/scratch.db": allow,
                "truncate -s 0 /tmp/scratch.log": allow,
                "truncate --size 0 /tmp/scratch.log": allow,
                "truncate -r ref.db /tmp/scratch.log": allow,
                "truncate --reference=ref.db /tmp/scratch.log": allow,
            }
        )
        denial = self.kernel.evaluate(self.payload("truncate -s 0 data.db"))
        self.assertEqual("delete data.db", denial.display)

    def test_production_cli_verbs_are_read_at_their_command_position(self):
        mutate = ("deny", "production.mutate")
        allow = ("allow", None)
        self.assertDecisions(
            {
                "railway up": mutate,
                "railway deploy": mutate,
                "railway redeploy": mutate,
                "railway restart": mutate,
                "railway down": mutate,
                "railway delete": mutate,
                "railway rm": mutate,
                "railway deployment redeploy": mutate,
                "railway deployment up": mutate,
                "railway deployments deploy": mutate,
                "railway service redeploy": mutate,
                "railway service restart": mutate,
                "flyctl deploy": mutate,
                "/usr/local/bin/flyctl release": mutate,
                "vc --prod": mutate,
                "vc deploy --prod": mutate,
                "kubectl -v 6 apply -f x.yaml": mutate,
                "kubectl --v 6 apply -f x.yaml": mutate,
                "kubectl --vmodule pod=2 delete pod x": mutate,
                "kubectl apply -f x.yaml": mutate,
                "kubectl apply --dry-run=none -f x.yaml": mutate,
                "kubectl apply --dry-run=client --dry-run=none -f x.yaml": mutate,
                "kubectl apply --dry-run -f x.yaml": mutate,
                "kubectl delete --raw=/api/v1/namespaces/prod/pods/web --dry-run=server": mutate,
                "kubectl delete --raw=/api/v1/namespaces/prod/pods/web --dry-run=client": mutate,
                "kubectl delete --raw /api/v1/namespaces/prod/pods/web --dry-run=server": mutate,
                "kubectl create --raw=/api/v1/namespaces/prod/pods -f pod.json --dry-run=server": mutate,
                "kubectl create --dry-run=client --raw /api/v1/namespaces/prod/pods -f pod.json": mutate,
                "kubectl replace --raw=/api/v1/namespaces/prod/pods/web -f pod.json --dry-run=server": mutate,
                "kubectl replace --raw /api/v1/namespaces/prod/pods/web -f pod.json --dry-run=client": mutate,
                "railway logs --service deploy": allow,
                "railway run npm run deploy": allow,
                "railway deployment list": allow,
                "railway dev up": allow,
                "railway status": allow,
                "flyctl logs": allow,
                "vc ls": allow,
                "kubectl -v 6 get pods": allow,
                "kubectl apply --dry-run=client -f x.yaml": allow,
                "kubectl apply --dry-run=server -f x.yaml": allow,
                "kubectl delete pod x --dry-run=server": allow,
            }
        )

    def test_ssh_directory_public_files_are_readable_and_keys_stay_protected(self):
        ssh = self.root / "home" / ".ssh"
        allow = ("allow", None)
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"cat {ssh}/config": allow,
                f"cat {ssh}/known_hosts {ssh}/known_hosts.old": allow,
                f"grep github.com {ssh}/known_hosts": allow,
                f"ls {ssh}": allow,
                f"ls -la {ssh}/": allow,
                f"ssh-keygen -lf {ssh}/id_ed25519.pub": allow,
                f"ssh-keygen -F github.com -f {ssh}/known_hosts": allow,
                f"ssh-keyscan github.com >> {ssh}/known_hosts": allow,
                f"ssh-keyscan -H github.com >>{ssh}/known_hosts": allow,
                f"scp -i {ssh}/deploy_key build.tgz host:": allow,
                f"scp -Ci {ssh}/deploy_key build.tgz host:": allow,
                f"sftp -i {ssh}/deploy_key host": allow,
                f"cat {ssh}/id_ed25519": credentials,
                f"cat {ssh}/config {ssh}/id_ed25519": credentials,
                f"cat {ssh}/keys/id.pub": credentials,
                f"cp {ssh}/id_rsa /tmp/x": credentials,
                f"cp {ssh}/config /tmp/x": credentials,
                f"grep -r . {ssh}": credentials,
                f"tar czf x.tgz {ssh}": credentials,
                f"echo x >> {ssh}/authorized_keys": credentials,
                f"echo x > {ssh}/config": credentials,
                f"echo x >> {ssh}/known_hosts": credentials,
                f"cat {ssh}/config >> {ssh}/known_hosts": credentials,
                f"ssh-keyscan github.com > {ssh}/known_hosts": credentials,
                f"cp /tmp/x {ssh}/config": credentials,
                f"sed -i s/a/b/ {ssh}/config": credentials,
                f"ssh-keygen -R github.com -f {ssh}/known_hosts": credentials,
                f"ssh-keygen -f {ssh}/new.pub": credentials,
                f"scp -i {ssh}/deploy_key {ssh}/id_rsa host:": credentials,
                f"ls {self.root / 'home' / '.gnupg'}": credentials,
            }
        )

    def test_composed_commands_keep_the_whole_ssh_directory_protected(self):
        ssh = self.root / "home" / ".ssh"
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"cat {ssh}/config; cp /tmp/x {ssh}/config": credentials,
                f"cat {ssh}/config && cp /tmp/x {ssh}/config": credentials,
                f"cat {ssh}/config\ncp /tmp/x {ssh}/config": credentials,
                f"cat /tmp/x | tee -a {ssh}/known_hosts": credentials,
                f"cat /tmp/x|tee {ssh}/config": credentials,
                f"cat $(cp /tmp/x {ssh}/config)": credentials,
                f"cat `cp /tmp/x {ssh}/config`": credentials,
                f"ssh-keyscan github.com >> {ssh}/known_hosts 2>&1": ("allow", None),
            }
        )

    def test_ssh_public_names_cannot_alias_protected_files(self):
        ssh = self.root / "home" / ".ssh"
        ssh.mkdir(parents=True)
        (ssh / "id_ed25519").write_text("private\n")
        (ssh / "config").symlink_to(ssh / "id_ed25519")
        self.assertEqual(("deny", "credentials.access"), self.decide(f"cat {ssh}/config"))

        settings = self.root / "safe-yolo" / "customizations.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"private_paths": [str(ssh / "known_hosts")]}))
        kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            codex_home=self.root / "codex",
            user_home=self.root / "home",
        )
        decision = kernel.evaluate(self.payload(f"cat {ssh}/known_hosts"))
        self.assertEqual(("deny", "credentials.access"), (decision.outcome, decision.consequence))

    def test_structured_tools_read_only_public_ssh_files(self):
        ssh = self.root / "home" / ".ssh"
        allow = ("allow", None)
        credentials = ("deny", "credentials.access")
        cases = (
            ("read", ssh / "config", allow),
            ("read", ssh / "known_hosts", allow),
            ("read", ssh / "id_ed25519.pub", allow),
            ("read", ssh / "id_ed25519", credentials),
            ("read", ssh, credentials),
            ("write", ssh / "config", credentials),
            ("edit", ssh / "known_hosts", credentials),
            ("write", ssh / "id_ed25519.pub", credentials),
        )
        for tool, path, expected in cases:
            with self.subTest(tool=tool, path=path.name):
                decision = self.kernel.evaluate(
                    {
                        "hook_event_name": "PreToolUse",
                        "cwd": "/workspace/repo",
                        "tool_name": tool,
                        "tool_input": {"file_path": str(path)},
                    }
                )
                self.assertEqual(expected, (decision.outcome, decision.consequence))

    def test_identity_option_exempts_only_its_own_value(self):
        ssh = self.root / "home" / ".ssh"
        key = ssh / "id_rsa"
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"scp -i {key} build.tgz host:": ("allow", None),
                f"scp -i {key} {key} host:": credentials,
                f"scp -i {key} build.tgz host: > {key}": credentials,
                f"sftp -i {key} host < {key}": credentials,
                f"sftp -i {key} -b {key} host": credentials,
            }
        )

    def test_known_hosts_append_authorizes_no_other_write(self):
        known_hosts = self.root / "home" / ".ssh" / "known_hosts"
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"ssh-keyscan github.com >> {known_hosts} > {known_hosts}": credentials,
                f"ssh-keyscan github.com > {known_hosts} >> {known_hosts}": credentials,
                f"ssh-keyscan github.com >> {known_hosts} >> {known_hosts}.old": credentials,
                f"ssh-keyscan github.com 2>> {known_hosts}": credentials,
                f"ssh-keyscan -f{known_hosts.parent}/id_rsa >> {known_hosts}": credentials,
                f"ssh-keyscan -f {known_hosts.parent}/id_rsa >> {known_hosts}": credentials,
            }
        )

    def test_reader_option_values_cannot_name_protected_files(self):
        ssh = self.root / "home" / ".ssh"
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"file -f{ssh}/id_rsa {ssh}/config": credentials,
                f"file -f {ssh}/id_rsa {ssh}/config": credentials,
                f"grep -f{ssh}/id_rsa {ssh}/config": credentials,
                f"grep -e x -f {ssh}/id_rsa {ssh}/config": credentials,
                f"head -c 10 {ssh}/config": credentials,
                f"head --bytes=10 {ssh}/config": credentials,
                f"ls -R {ssh}": credentials,
                f"cat -- {ssh}/config": credentials,
                f"cat {ssh}/*.pub": credentials,
                f"cat {ssh}/id_rsa.p?b": credentials,
                f"cat {ssh}/config/../id_rsa.pub": credentials,
                f"head -n 5 {ssh}/config": ("allow", None),
                f"grep -in github {ssh}/known_hosts": ("allow", None),
            }
        )

    def test_public_names_linked_to_private_keys_are_denied(self):
        ssh = self.root / "home" / ".ssh"
        ssh.mkdir(parents=True)
        private = ssh / "id_rsa"
        private.write_text("FAKE PRIVATE KEY\n")
        (ssh / "id_rsa.pub").write_text("ssh-ed25519 AAAA public\n")
        (ssh / "alias.pub").symlink_to(private)
        try:
            (ssh / "linked.pub").hardlink_to(private)
        except OSError:
            linked = False
        else:
            linked = True
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"cat {ssh}/id_rsa.pub": ("allow", None),
                f"cat {ssh}/*.pub": credentials,
                f"cat {ssh}/alias.pub": credentials,
            }
        )
        if not linked:
            self.skipTest("filesystem refused a hardlink")
        self.assertEqual(credentials, self.decide(f"cat {ssh}/linked.pub"))
        self.assertEqual(credentials, self.decide(f"ssh-keygen -lf {ssh}/linked.pub"))
        decision = self.kernel.evaluate(
            {
                "hook_event_name": "PreToolUse",
                "cwd": "/workspace/repo",
                "tool_name": "read",
                "tool_input": {"file_path": str(ssh / "linked.pub")},
            }
        )
        self.assertEqual(credentials, (decision.outcome, decision.consequence))

    def test_user_private_paths_override_public_ssh_files(self):
        ssh = self.root / "home" / ".ssh"
        settings = self.root / "safe-yolo" / "customizations.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"private_paths": [str(ssh)]}))
        kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            codex_home=self.root / "codex",
            user_home=self.root / "home",
        )
        payloads = {
            "cat": self.payload(f"cat {ssh}/config"),
            "ls": self.payload(f"ls {ssh}"),
            "keyscan": self.payload(f"ssh-keyscan github.com >> {ssh}/known_hosts"),
            "read": {
                "hook_event_name": "PreToolUse",
                "cwd": "/workspace/repo",
                "tool_name": "read",
                "tool_input": {"file_path": str(ssh / "config")},
            },
        }
        for name, payload in payloads.items():
            with self.subTest(name=name):
                decision = kernel.evaluate(payload)
                self.assertEqual(
                    ("deny", "credentials.access"), (decision.outcome, decision.consequence)
                )
        self.assertEqual(("allow", None), self.decide(f"cat {ssh}/config"))

    def test_shape_option_values_cannot_hide_redirections(self):
        ssh = self.root / "home" / ".ssh"
        key, pub, known_hosts = ssh / "id_rsa", ssh / "id.pub", ssh / "known_hosts"
        outside = self.root / "hosts"
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"ssh-keygen -lf >{key} {pub}": credentials,
                f"ssh-keygen -lf > {key} {pub}": credentials,
                f"ssh-keygen -l -f >>{key} {pub}": credentials,
                f"ssh-keygen -l -f 1>{key} {pub}": credentials,
                f"ssh-keygen -l -f <{key} {pub}": credentials,
                f"ssh-keygen -l -E >{key} -f {pub}": credentials,
                f"ssh-keyscan -f >{key} {outside} host >> {known_hosts}": credentials,
                f"ssh-keyscan -f > {key} {outside} host >> {known_hosts}": credentials,
                f"ssh-keyscan -f 2>{key} {outside} host >> {known_hosts}": credentials,
                f"ssh-keyscan -p >>{key} 22 host >> {known_hosts}": credentials,
                f"ssh-keygen -lf {pub} > {self.root}/fingerprint": credentials,
                f"ssh-keygen -lf {pub} > /dev/null": ("allow", None),
                f"ssh-keyscan -f {outside} >> {known_hosts}": ("allow", None),
            }
        )

    def test_identity_values_cannot_hide_redirections(self):
        ssh = self.root / "home" / ".ssh"
        key = ssh / "id_rsa"
        outside = self.root / "outside-key"
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"scp -i >{key} {outside} build.tgz host:": credentials,
                f"scp -i > {key} {outside} build.tgz host:": credentials,
                f"scp -i >>{key} {outside} build.tgz host:": credentials,
                f"scp -i <{key} {outside} build.tgz host:": credentials,
                f"scp -Ci 2>{key} {outside} build.tgz host:": credentials,
                f"ssh -i >{key} {outside} host": credentials,
                f"ssh -i > {key} {outside} host": credentials,
                f"sftp -i >{key} {outside} host": credentials,
                f"sftp -i > {key} {outside} host": credentials,
                f"scp -o >{self.root}/log -i {key} build.tgz host:": credentials,
                f"scp -i {ssh}/* build.tgz host:": credentials,
                f"ssh -i {key} host > {self.root}/log": credentials,
                f"ssh -i {key} host 2>/dev/null": ("allow", None),
            }
        )

    def test_any_redirection_but_dev_null_and_descriptors_voids_ssh_exemptions(self):
        ssh = self.root / "home" / ".ssh"
        commands = (
            f"scp -i {ssh}/id_rsa build.tgz host:",
            f"sftp -i {ssh}/id_rsa host",
            f"ssh -i {ssh}/id_rsa host uptime",
            f"cat {ssh}/config",
            f"ssh-keygen -lf {ssh}/id.pub",
            f"ssh-keyscan github.com >> {ssh}/known_hosts",
        )
        operators = (">|", "1>|", "2>|", ">&", "&>", "&>>", "<>", "<")
        targets = (ssh / "id_rsa", ssh / "config", self.root / "outside")
        for command in commands:
            for operator in operators:
                for target in targets:
                    for space in ("", " "):
                        line = f"{command} {operator}{space}{target}"
                        with self.subTest(command=line):
                            self.assertEqual(("deny", "credentials.access"), self.decide(line))
        self.assertDecisions(
            {
                f"scp -i {ssh}/id_rsa build.tgz host: <<<{ssh}/id_rsa": ("deny", "credentials.access"),
                f"cat {ssh}/config <<EOF": ("deny", "credentials.access"),
                f"cat {ssh}/config <({ssh}/config)": ("deny", "credentials.access"),
                f"cat {ssh}/config >/tmp/x": ("deny", "credentials.access"),
                f"cat {ssh}/config 2>/tmp/x": ("deny", "credentials.access"),
                f"cat {ssh}/config 3>/dev/null": ("deny", "credentials.access"),
                f"ssh -i {ssh}/id_rsa host uptime >>/dev/null": ("deny", "credentials.access"),
            }
        )

    def test_dev_null_and_descriptor_redirections_keep_ssh_exemptions(self):
        ssh = self.root / "home" / ".ssh"
        allow = ("allow", None)
        self.assertDecisions(
            {
                f"cat {ssh}/config": allow,
                f"ls {ssh}": allow,
                f"ssh-keygen -lf {ssh}/id.pub": allow,
                f"ssh-keyscan github.com >> {ssh}/known_hosts": allow,
                f"ssh-keyscan github.com >> {ssh}/known_hosts 2>/dev/null": allow,
                f"scp -i {ssh}/deploy_key build.tgz host:": allow,
                f"ssh -i {ssh}/deploy_key host uptime 2>&1": allow,
                f"ssh -i {ssh}/deploy_key host uptime >&2": allow,
                f"ssh -i {ssh}/deploy_key host uptime 1>&2": allow,
                f"cat {ssh}/config > /dev/null": allow,
                f"cat {ssh}/config 2> /dev/null": allow,
                f"sftp -i {ssh}/deploy_key host &>/dev/null": allow,
            }
        )

    def test_clobber_and_combined_redirections_name_their_real_target(self):
        ssh = self.root / "home" / ".ssh"
        enforcement = self.root / "safe-yolo" / "customizations.json"
        credentials = ("deny", "credentials.access")
        self.assertDecisions(
            {
                f"echo x >|{ssh}/config": credentials,
                f"echo x 1>|{ssh}/config": credentials,
                f"echo x 2>|{ssh}/config": credentials,
                f"echo x >&{ssh}/config": credentials,
                f"echo x &>>{ssh}/config": credentials,
                f"echo x >|{enforcement}": ("deny", "enforcement.modify"),
                f"echo x >&{enforcement}": ("deny", "enforcement.modify"),
                f"echo x >|{self.root}/out": ("allow", None),
                f"echo x >&2": ("allow", None),
                f"echo x 2>&-": ("allow", None),
            }
        )

    def test_quoted_filenames_starting_with_a_pipe_keep_their_literal_target(self):
        ssh = self.root / "home" / ".ssh"
        ssh.mkdir(parents=True)
        (ssh / "id_rsa").write_text("fake private\n")
        work = self.root / "work"
        work.mkdir()
        (work / "|secret").symlink_to(ssh / "id_rsa")
        (work / "|keys").symlink_to(ssh, target_is_directory=True)
        for command in (
            "cat <'|secret'",
            "echo x >'|secret'",
            "cat <'|keys/id_rsa'",
            "echo x >'|keys/config'",
        ):
            with self.subTest(command=command):
                decision = self.kernel.evaluate(
                    {
                        "hook_event_name": "PreToolUse",
                        "cwd": str(work),
                        "tool_name": "exec_command",
                        "tool_input": {"cmd": command},
                    }
                )
                self.assertEqual(
                    ("deny", "credentials.access"),
                    (decision.outcome, decision.consequence),
                )

    def test_user_private_paths_override_identity_exemptions(self):
        ssh = self.root / "home" / ".ssh"
        settings = self.root / "safe-yolo" / "customizations.json"
        settings.parent.mkdir(parents=True)
        settings.write_text(json.dumps({"private_paths": [str(ssh)]}))
        kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            codex_home=self.root / "codex",
            user_home=self.root / "home",
        )
        for command in (
            f"scp -i {ssh}/id_rsa build.tgz host:",
            f"sftp -i {ssh}/id_rsa host",
            f"ssh -i {ssh}/id_rsa host uptime",
        ):
            with self.subTest(command=command):
                decision = kernel.evaluate(self.payload(command))
                self.assertEqual(
                    ("deny", "credentials.access"), (decision.outcome, decision.consequence)
                )
        self.assertEqual(("allow", None), self.decide(f"scp -i {ssh}/id_rsa build.tgz host:"))

    def test_railway_group_options_before_the_verb_are_skipped(self):
        mutate = ("deny", "production.mutate")
        allow = ("allow", None)
        self.assertDecisions(
            {
                "railway volume --project review-fixture delete --volume data --yes": mutate,
                "railway volume -p review-fixture rm --volume data": mutate,
                "railway volume --project=review-fixture delete": mutate,
                "railway bucket --bucket review-fixture delete --yes": mutate,
                "railway bucket -b assets remove": mutate,
                "railway variable --project review-fixture delete FOO": mutate,
                "railway variable -s api -e production delete FOO": mutate,
                "railway variable -k delete FOO": mutate,
                "railway functions -e staging delete": mutate,
                "railway environment --json delete staging": mutate,
                "railway volume --project review-fixture list": allow,
                "railway variable -s api list": allow,
                "railway variable -s delete list": allow,
                "railway bucket --bucket delete info": allow,
            }
        )
        denial = self.kernel.evaluate(self.payload("railway volume -p x delete --yes"))
        self.assertEqual("run railway volume delete production mutation", denial.display)

    def test_production_destroy_verbs_are_denied(self):
        mutate = ("deny", "production.mutate")
        allow = ("allow", None)
        self.assertDecisions(
            {
                "fly apps destroy myapp": mutate,
                "fly app destroy myapp": mutate,
                "fly apps rm myapp": mutate,
                "fly destroy myapp": mutate,
                "fly machine destroy abc": mutate,
                "fly machines destroy abc": mutate,
                "fly m destroy abc": mutate,
                "fly m rm abc": mutate,
                "flyctl apps destroy myapp": mutate,
                "flyctl machine destroy abc --force": mutate,
                "vercel remove myapp": mutate,
                "vercel rm dpl_123": mutate,
                "vercel rollback": mutate,
                "vercel promote dpl_123": mutate,
                "vc rm dpl_123": mutate,
                "vc rollback dpl_123": mutate,
                "railway service delete": mutate,
                "railway service rm": mutate,
                "railway volume delete": mutate,
                "railway volumes remove": mutate,
                "railway environment delete staging": mutate,
                "railway env rm staging": mutate,
                "railway bucket delete": mutate,
                "railway functions delete": mutate,
                "railway fn rm": mutate,
                "railway template delete": mutate,
                "railway templates delete": mutate,
                "railway variable delete FOO": mutate,
                "railway vars rm FOO": mutate,
                "railway project delete": mutate,
                "fly status": allow,
                "fly logs": allow,
                "fly apps list": allow,
                "fly machine list": allow,
                "vercel ls": allow,
                "vercel rollback status": allow,
                "vc promote status my-project": allow,
                "railway status": allow,
                "railway logs": allow,
                "railway service list": allow,
                "railway variable list": allow,
            }
        )
        denial = self.kernel.evaluate(self.payload("vc rm dpl_123"))
        self.assertEqual("run vercel rm production mutation", denial.display)

    def test_public_bind_spellings_are_denied_and_loopback_is_allowed(self):
        public = ("deny", "network.public_exposure")
        allow = ("allow", None)
        self.assertDecisions(
            {
                "gunicorn -b 0.0.0.0:8000 app:app": public,
                "gunicorn --bind 0.0.0.0:8000 app:app": public,
                "gunicorn --bind=0.0.0.0:8000 app:app": public,
                "gunicorn -b [::]:8000 app:app": public,
                "gunicorn -b0.0.0.0:8000 app:app": public,
                "rails s -b 0.0.0.0": public,
                "bin/rails server -b 0.0.0.0": public,
                "rails server --binding=::": public,
                "jupyter lab --ip 0.0.0.0": public,
                "jupyter notebook --ip=0.0.0.0": public,
                "jupyter lab --ip=::": public,
                "php -S 0.0.0.0:8000": public,
                "php -S [::]:8000 -t public": public,
                "uvicorn app:app --host 0.0.0.0": public,
                "gunicorn -b 127.0.0.1:8000 app:app": allow,
                "gunicorn --bind=localhost:8000 app:app": allow,
                "gunicorn -b [::1]:8000 app:app": allow,
                "rails s -b 127.0.0.1": allow,
                "jupyter lab --ip 127.0.0.1": allow,
                "php -S localhost:8000": allow,
                "php -S [::1]:8000": allow,
                "curl -H 'Host: 0.0.0.0' http://localhost:8000": allow,
                "git checkout -b 0.0.0.0": allow,
                "vite --host 127.0.0.1": allow,
            }
        )

    def test_shell_variable_listings_are_environment_dumps(self):
        dump = ("deny", "credentials.access")
        allow = ("allow", None)
        self.assertDecisions(
            {
                "export": dump,
                "export -p": dump,
                "declare -x": dump,
                "declare -p": dump,
                "declare -px": dump,
                "typeset -x": dump,
                "set": dump,
                "env --un FOO": dump,
                "env --unset FOO": dump,
                "env -u FOO": dump,
                "export FOO=bar": allow,
                "export PATH=$PATH:/x": allow,
                "export -p FOO=1": allow,
                "declare -x FOO=1": allow,
                "declare -p HOME": allow,
                "declare -f": allow,
                "set -e": allow,
                "set -euo pipefail": allow,
                "set -- a b": allow,
                "set --": allow,
                "env -i PATH=/usr/bin make": allow,
                "env --un FOO make": allow,
                "env --help": allow,
            }
        )

    def test_sed_in_place_spellings_cannot_edit_enforcement(self):
        config = self.root / "codex" / "config.toml"
        modify = ("deny", "enforcement.modify")
        allow = ("allow", None)
        self.assertDecisions(
            {
                f"sed -i s/a/b/ {config}": modify,
                f"sed -i.bak s/a/b/ {config}": modify,
                f"sed -Ei s/a/b/ {config}": modify,
                f"sed -ie s/a/b/ {config}": modify,
                f"sed -n -i s/a/b/ {config}": modify,
                f"sed --in-place s/a/b/ {config}": modify,
                f"sed --in-place=.bak s/a/b/ {config}": modify,
                f"sed --in-pl=.bak s/a/b/ {config}": modify,
                f"sed -e s/a/b/ -i {config}": modify,
                f"sed -n 1,5p {config}": allow,
                f"sed -e i {config}": allow,
                "sed -i s/a/b/ src/file.py": allow,
            }
        )

    def test_help_flags_cannot_bypass_protected_path_denials(self):
        commands = (
            f"env --help >{self.root / 'codex' / 'hooks.json'}",
            f"printenv --version >{self.root / 'codex' / 'hooks.json'}",
            f"rm --help >{self.root / 'codex' / 'hooks.json'}",
            f"env --help >{self.root / 'codex' / 'auth.json'}",
            f"ssh -V >{self.root / 'home' / '.ssh' / 'probe'}",
        )

        for command in commands:
            with self.subTest(command=command):
                denial = handle_pre_tool(self.payload(command), self.kernel)
                self.assertEqual(
                    "deny",
                    denial["hookSpecificOutput"]["permissionDecision"],
                )

    def test_help_flags_cannot_bypass_shell_composition_denials(self):
        commands = (
            "rm obsolete.txt ; env --help",
            "rm obsolete.txt && env --help",
            "git push --force-with-lease origin topic ; env --help",
            "ssh example.com ; env --help",
            "sudo touch /tmp/x ; env --help",
            "vite --host 0.0.0.0 ; env --help",
            "rm obsolete.txt\nenv --help",
            "rm obsolete.txt $(env --help )",
            "rm obsolete.txt `env --help`",
            "rm obsolete.txt # --help",
            "rm -- --help obsolete.txt",
        )

        for command in commands:
            with self.subTest(command=command):
                denial = handle_pre_tool(self.payload(command), self.kernel)
                self.assertEqual(
                    "deny",
                    denial["hookSpecificOutput"]["permissionDecision"],
                )

    def test_request_user_input_is_not_part_of_the_runtime(self):
        payload = {
            "hook_event_name": "PostToolUse",
            "cwd": "/workspace",
            "tool_name": "request_user_input",
            "tool_input": {},
            "tool_response": {},
        }

        self.assertIsNone(handle_pre_tool(payload, self.kernel))

    def test_executable_hook_has_no_stateful_retry_path(self):
        command = [
            sys.executable,
            str(ROOT / "adapters" / "codex_v3.py"),
            "--state-dir",
            str(Path(self.temp.name) / "unused-state"),
            "--safe-yolo-home",
            str(Path(self.temp.name) / "safe-yolo"),
            "--codex-home",
            str(Path(self.temp.name) / "codex"),
            "--user-home",
            str(Path(self.temp.name) / "home"),
        ]
        action = self.payload("rm obsolete.txt")

        first = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(action),
            text=True,
            capture_output=True,
            check=False,
        )
        second = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(action),
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        denial = json.loads(first.stdout)
        self.assertEqual(
            "deny",
            denial["hookSpecificOutput"]["permissionDecision"],
        )
        from engine.deletion_observation import report
        self.assertEqual(2, report(Path(self.temp.name) / "unused-state")["total_events"])
        self.assertEqual({"observations"}, {path.name for path in (Path(self.temp.name) / "unused-state").iterdir()})

    def test_default_scratch_roots_allow_tmp_deletes(self):
        self.assertIsNone(handle_pre_tool(self.payload("rm /tmp/stale.json"), self.kernel))
        home_tmp = self.root / "home" / "tmp" / "stale.json"
        self.assertIsNone(handle_pre_tool(self.payload(f"rm {home_tmp}"), self.kernel))

        denied = handle_pre_tool(self.payload("rm /var/tmp/stale.json"), self.kernel)
        self.assertIn(
            "filesystem.delete",
            denied["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_empty_scratch_paths_preserve_delete_denials(self):
        kernel = build_kernel(
            safe_yolo_home=self.root / "safe-yolo",
            codex_home=self.root / "codex",
            user_home=self.root / "home",
            scratch_paths=(),
        )
        denied = handle_pre_tool(self.payload("rm /tmp/stale.json"), kernel)
        self.assertIn(
            "filesystem.delete",
            denied["hookSpecificOutput"]["permissionDecisionReason"],
        )

    def test_scratch_cli_flag_replaces_default_roots(self):
        custom = self.root / "custom-scratch"
        extra = self.root / "extra-scratch"
        command = [
            sys.executable,
            str(ROOT / "adapters" / "codex_v3.py"),
            "--safe-yolo-home",
            str(self.root / "safe-yolo"),
            "--codex-home",
            str(self.root / "codex"),
            "--user-home",
            str(self.root / "home"),
            "--scratch",
            str(custom),
            "--scratch",
            str(extra),
        ]
        for target in (custom / "stale.json", extra / "stale.json"):
            allowed = subprocess.run(
                command,
                cwd=ROOT,
                input=json.dumps(self.payload(f"rm {target}")),
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, allowed.returncode, allowed.stderr)
            self.assertEqual("", allowed.stdout)

        denied = subprocess.run(
            command,
            cwd=ROOT,
            input=json.dumps(self.payload("rm /tmp/stale.json")),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, denied.returncode, denied.stderr)
        self.assertIn("filesystem.delete", denied.stdout)

    def test_unreadable_payload_does_not_invent_a_restriction(self):
        command = [sys.executable, str(ROOT / "adapters" / "codex_v3.py")]

        for raw_payload in ("", "not-json", "[]"):
            with self.subTest(raw_payload=raw_payload):
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    input=raw_payload,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual("", result.stdout)


if __name__ == "__main__":
    unittest.main()
