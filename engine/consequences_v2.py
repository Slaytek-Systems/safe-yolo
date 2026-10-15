from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shlex
from typing import Any, Literal

from engine.ssh_command import parse_ssh_invocation


Outcome = Literal["allow", "approval_required", "operator_only"]


# Each git form maps to alternative flag requirements. A form matches when one
# alternative has every flag group present among its options; () always matches.
_FORCE = frozenset({"-f", "--force"})
_GIT_DISCARDING_FORMS: dict[tuple[str, ...], tuple[tuple[frozenset[str], ...], ...]] = {
    ("rebase",): ((),),
    ("reset",): ((frozenset({"--hard"}),),),
    ("rm",): ((_FORCE,),),
    ("checkout",): ((_FORCE,), (frozenset({"."}),)),
    ("switch",): ((_FORCE | {"--discard-changes"},),),
    ("worktree", "remove"): ((_FORCE,),),
    ("stash", "drop"): ((),),
    ("stash", "clear"): ((),),
    ("reflog", "expire"): ((),),
    ("reflog", "delete"): ((),),
    ("gc",): ((frozenset({"--prune=now", "--prune=all"}),),),
    ("filter-branch",): ((),),
    ("filter-repo",): ((),),
}
_GIT_REF_DELETING_FORMS: dict[tuple[str, ...], tuple[tuple[frozenset[str], ...], ...]] = {
    ("branch",): (
        (frozenset({"-D", "-M", "-C"}),),
        (frozenset({"-d", "--delete", "-m", "--move", "-c", "--copy"}), _FORCE),
    ),
    ("update-ref",): ((frozenset({"-d", "--delete"}),),),
}
# Value-taking short letters and long options per subcommand, from
# `git <subcommand> -h`. Their values are never read as flags.
_GIT_VALUE_OPTIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "restore": ("s", ("--source", "--conflict", "--pathspec-from-file")),
    "checkout": ("bB", ("--orphan", "--conflict", "--pathspec-from-file")),
    "switch": ("cC", ("--create", "--force-create", "--orphan", "--conflict")),
    "rm": ("", ("--pathspec-from-file",)),
    "branch": (
        "u",
        (
            "--set-upstream-to",
            "--contains",
            "--no-contains",
            "--merged",
            "--no-merged",
            "--sort",
            "--points-at",
            "--format",
        ),
    ),
    "update-ref": ("m", ()),
    "push": ("o", ("--push-option", "--repo", "--receive-pack", "--exec", "--recurse-submodules")),
    "gc": ("", ("--max-cruft-size",)),
}
_GIT_PUSH_FORCING = ("-f", "--force", "--force-with-lease", "--mirror", "--prune", "--tags")
_GIT_PUSH_DELETING = ("-d", "--delete")
# Global options from `git -h` that take a value, spaced or attached.
_GIT_VALUE_GLOBALS = (
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--attr-source",
)
_GIT_BOOLEAN_GLOBALS = frozenset(
    {
        "--no-pager",
        "-P",
        "--paginate",
        "-p",
        "--literal-pathspecs",
        "--no-literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
        "--no-optional-locks",
        "--no-replace-objects",
        "--bare",
        "--exec-path",
    }
)
# Graphite commands from `gt --help` that force push. Plain submit uses
# --force-with-lease; only an explicit force overwrites the remote branch.
_GT_FORCE_SUBMIT_FORMS: dict[tuple[str, ...], tuple[tuple[frozenset[str], ...], ...]] = {
    (*command, verb): ((_FORCE,),)
    for command in ((), ("stack",), ("downstack",), ("upstack",))
    for verb in ("submit", "s")
} | {("ss",): ((_FORCE,),)}
# Commands that destroy file content, with their value-taking short letters
# and long options from `<command> --help`. Option values are never targets.
_CONTENT_DESTROYING_COMMANDS: dict[str, tuple[str, tuple[str, ...]]] = {
    "rm": ("", ()),
    "unlink": ("", ()),
    "rmdir": ("", ()),
    "shred": ("ns", ("--iterations", "--size", "--random-source")),
    "truncate": ("rs", ("--reference", "--size")),
}
_SED_VALUE_OPTIONS = ("efl", ("--expression", "--file", "--line-length"))
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# Production CLIs by executable alias, and the command words that mutate.
# Commands are read at the subcommand position, so arguments never match.
_PRODUCTION_ALIASES = {"flyctl": "fly", "vc": "vercel"}
_RAILWAY_MUTATING_COMMANDS = frozenset(
    {
        ("up",),
        ("deploy",),
        ("redeploy",),
        ("restart",),
        ("down",),
        ("delete",),
        ("rm",),
        ("remove",),
    }
    | {
        (group, verb)
        for group in ("deployment", "deployments")
        for verb in ("up", "deploy", "redeploy")
    }
    | {("service", "redeploy"), ("service", "restart")}
)
_KUBECTL_DRY_RUNS = frozenset({"--dry-run=client", "--dry-run=server"})
_GIT_RESTORE_LONG_OPTIONS = (
    "--source",
    "--staged",
    "--worktree",
    "--ignore-unmerged",
    "--overlay",
    "--quiet",
    "--recurse-submodules",
    "--progress",
    "--merge",
    "--conflict",
    "--ours",
    "--theirs",
    "--patch",
    "--ignore-skip-worktree-bits",
    "--pathspec-from-file",
    "--pathspec-file-nul",
)


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    consequence: str | None = None
    display: str | None = None


class ConsequenceKernel:
    """Minimal direct-tool consequence detector.

    The kernel deliberately defaults to allow. It does not infer effects inside
    scripts, interpreters, wrappers, or unknown tools.
    """

    def __init__(
        self,
        *,
        enforcement_paths: tuple[str, ...] = (),
        credential_paths: tuple[str, ...] = (),
        scratch_paths: tuple[str, ...] = (),
    ) -> None:
        self.enforcement_paths = tuple(self._path(path) for path in enforcement_paths)
        self.credential_paths = tuple(self._path(path) for path in credential_paths)
        self.scratch_paths = tuple(self._path(path) for path in scratch_paths)

    @staticmethod
    def _path(value: str) -> Path:
        return Path(value).expanduser().resolve(strict=False)

    def evaluate(self, payload: dict[str, Any]) -> Decision:
        tool_name = str(payload.get("tool_name") or "").lower()
        tool_input = payload.get("tool_input")
        cwd = self._path(str(payload.get("cwd") or "."))
        if tool_name in {"bash", "shell", "exec_command"} and isinstance(tool_input, dict):
            command = tool_input.get("command") or tool_input.get("cmd")
            if isinstance(command, str):
                workdir = tool_input.get("workdir")
                effective_cwd = (
                    self._resolve_from(workdir, cwd)
                    if isinstance(workdir, str) and workdir
                    else cwd
                )
                return self._shell(command, effective_cwd)
        paths = self._structured_paths(tool_input, cwd)
        if any(self._inside(path, self.credential_paths) for path in paths):
            return Decision(
                "operator_only",
                "credentials.access",
                "credential material is not available to the agent",
            )
        if tool_name in {
            "apply_patch",
            "write",
            "edit",
            "multiedit",
            "multi_edit",
            "create_file",
            "write_file",
            "move_file",
            "rename_file",
            "copy_file",
            "delete_file",
            "remove_file",
        } and any(self._inside(path, self.enforcement_paths) for path in paths):
            return Decision(
                "operator_only",
                "enforcement.modify",
                "Safe YOLO enforcement can only be changed through operator maintenance",
            )
        if tool_name in {"delete_file", "remove_file"}:
            if (
                self.scratch_paths
                and paths
                and all(self._inside(path, self.scratch_paths) for path in paths)
                and not any(self._inside(path, self.enforcement_paths) for path in paths)
                and not any(self._inside(path, self.credential_paths) for path in paths)
            ):
                return Decision("allow")
            display = "delete " + (", ".join(str(path) for path in paths) or "filesystem target")
            return Decision("approval_required", "filesystem.delete", display)
        if tool_name == "apply_patch" and isinstance(tool_input, dict):
            patch = tool_input.get("patch") or tool_input.get("command") or ""
            patch = self._patch_directives(patch)
            if isinstance(patch, str) and "*** Delete File:" in patch:
                targets = [
                    str(self._resolve_from(line.strip().removeprefix("*** Delete File: "), cwd))
                    for line in patch.splitlines()
                    if line.strip().startswith("*** Delete File: ")
                ]
                return Decision(
                    "approval_required",
                    "filesystem.delete",
                    "delete " + (", ".join(targets) if targets else "a file") + " through apply_patch",
                )
        return Decision("allow")

    @staticmethod
    def _patch_directives(patch: Any) -> str:
        """Keep header-like lines, including whitespace accepted by patch parsers.

        Ambiguous context lines stay in the deny scan. Added/removed content
        and quoted source strings do not become actions merely by containing
        a marker somewhere inside the line.
        """
        if not isinstance(patch, str):
            return ""
        return "\n".join(line for line in patch.splitlines() if line.lstrip().startswith("*** "))

    @classmethod
    def _structured_paths(cls, tool_input: Any, cwd: Path) -> tuple[Path, ...]:
        path_keys = {
            "path",
            "file_path",
            "filepath",
            "filename",
            "target_file",
            "target_path",
            "source",
            "source_path",
            "destination",
            "destination_path",
            "from",
            "to",
        }
        found: list[Path] = []
        if isinstance(tool_input, dict):
            for key, value in tool_input.items():
                if str(key).lower() in path_keys and isinstance(value, str):
                    found.append(cls._resolve_from(value, cwd))
                elif str(key).lower() in {"patch", "command"} and isinstance(value, str):
                    for line in value.splitlines():
                        stripped = line.strip()
                        for prefix in (
                            "*** Add File: ",
                            "*** Update File: ",
                            "*** Delete File: ",
                            "*** Move to: ",
                        ):
                            if stripped.startswith(prefix):
                                found.append(cls._resolve_from(stripped.removeprefix(prefix), cwd))
                elif isinstance(value, (dict, list)):
                    found.extend(cls._structured_paths(value, cwd))
        elif isinstance(tool_input, list):
            for value in tool_input:
                found.extend(cls._structured_paths(value, cwd))
        return tuple(found)

    @staticmethod
    def _resolve_from(value: str, cwd: Path) -> Path:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = cwd / path
        return path.resolve(strict=False)

    @staticmethod
    def _inside(path: Path, roots: tuple[Path, ...]) -> bool:
        for root in roots:
            try:
                path.relative_to(root)
            except ValueError:
                continue
            return True
        return False

    def _shell(self, command: str, cwd: Path) -> Decision:
        command = self._mask_direct_git_push_heredoc_body(command)
        lexer = shlex.shlex(command, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens: list[str] = []
        assigning = True
        start = 0
        try:
            while (token := lexer.get_token()) is not None:
                end = lexer.instream.tell()
                # Bash assigns only when NAME= is unquoted and unescaped.
                if not (assigning and _ASSIGNMENT.match(command[start:end].lstrip())):
                    assigning = False
                    tokens.append(token)
                start = end
        except ValueError:
            return Decision("allow")
        if not tokens:
            return Decision("allow")
        executable = Path(tokens[0]).name
        ssh_invocation = parse_ssh_invocation(tokens[1:]) if executable == "ssh" else None
        token_paths, positionals, redirect_targets = self._shell_paths(tokens[1:], cwd)
        credential_scan = token_paths
        if ssh_invocation is not None:
            identity_files = {
                self._resolve_from(value, cwd)
                for value in ssh_invocation.identity_files
            }
            credential_scan = tuple(path for path in token_paths if path not in identity_files)
        if any(self._inside(path, self.credential_paths) for path in credential_scan):
            return Decision(
                "operator_only",
                "credentials.access",
                "credential material is not available to the agent",
            )
        mutation_targets = self._mutation_targets(
            executable,
            tokens[1:],
            cwd,
            positionals,
            redirect_targets,
        )
        if any(self._inside(path, self.enforcement_paths) for path in mutation_targets):
            return Decision(
                "operator_only",
                "enforcement.modify",
                "Safe YOLO enforcement can only be changed through operator maintenance",
            )
        if self._environment_dump(executable, tokens[1:]):
            return Decision(
                "operator_only",
                "credentials.access",
                "dumping the complete process environment is not available to the agent",
            )
        if executable in _CONTENT_DESTROYING_COMMANDS:
            _, operands, after_separator = self._parse_options(
                tokens[1:], *_CONTENT_DESTROYING_COMMANDS[executable]
            )
            targets = operands + after_separator
            resolved = [self._resolve_from(token, cwd) for token in targets]
            if (
                self.scratch_paths
                and resolved
                and all(self._inside(path, self.scratch_paths) for path in resolved)
                and not any(self._inside(path, self.enforcement_paths) for path in resolved)
                and not any(self._inside(path, self.credential_paths) for path in resolved)
            ):
                return Decision("allow")
            display = "delete " + (", ".join(targets) if targets else "filesystem targets")
            return Decision("approval_required", "filesystem.delete", display)
        git_args = self._git_command_args(tokens[1:]) if executable == "git" else []
        if executable == "git" and self._git_history_mutation(git_args):
            return Decision(
                "approval_required",
                "git.history_mutation",
                self._git_display(git_args),
            )
        if executable == "git" and self._git_ref_deletion(git_args):
            return Decision(
                "approval_required",
                "git.delete_ref",
                self._git_display(git_args),
            )
        if executable == "gt" and self._git_form_matches(
            self._gt_command_args(tokens[1:]), _GT_FORCE_SUBMIT_FORMS
        ):
            return Decision(
                "approval_required",
                "git.history_mutation",
                "gt submit --force",
            )
        if self._production_mutation(tokens):
            return Decision(
                "approval_required",
                "production.mutate",
                f"run {self._production_display(tokens)} production mutation",
            )
        if executable == "ssh":
            assert ssh_invocation is not None
            if (
                ssh_invocation.opaque_config
                or ssh_invocation.malformed
                or ssh_invocation.subsystem
            ):
                return self._remote_execution(ssh_invocation.host)
            for local_command in ssh_invocation.local_commands:
                decision = self._remote_shell(local_command, cwd)
                if decision.outcome != "allow":
                    return decision
            for remote_command in ssh_invocation.remote_commands:
                decision = self._remote_shell(remote_command, cwd)
                if decision.outcome != "allow":
                    return decision
            if ssh_invocation.remote_commands or ssh_invocation.transport_only:
                return Decision("allow")
            return self._remote_execution(ssh_invocation.host)
        if executable in {"sudo", "doas", "su"}:
            return Decision(
                "approval_required",
                "privilege.modify",
                f"execute through {executable}",
            )
        if self._public_bind(tokens):
            return Decision(
                "approval_required",
                "network.public_exposure",
                "bind a development service to a public interface",
            )
        return Decision("allow")

    def _remote_shell(self, command: str, cwd: Path) -> Decision:
        try:
            tokens = self._line_tokens(command)
        except ValueError:
            return Decision(
                "approval_required",
                "remote.execute",
                "execute an unparseable remote command",
            )
        current: list[str] = []
        separators = {"|", "||", "|&", "&&", ";"}
        for token in [*tokens, ";"]:
            if token not in separators:
                current.append(token)
                continue
            if current:
                decision = self._remote_segment(current, cwd)
                if decision.outcome != "allow":
                    return decision
                current = []
        return Decision("allow")

    def _remote_segment(self, tokens: list[str], cwd: Path) -> Decision:
        if not tokens:
            return Decision("allow")
        executable = Path(tokens[0]).name
        if executable in {"command", "builtin", "exec"} and len(tokens) > 1:
            return self._remote_segment(tokens[1:], cwd)
        if executable in {"bash", "dash", "fish", "ksh", "sh", "zsh"}:
            for index, token in enumerate(tokens[1:], start=1):
                if token == "-c" or (token.startswith("-") and "c" in token[1:]):
                    if index + 1 >= len(tokens):
                        return self._remote_execution("remote host")
                    return self._remote_shell(" ".join(tokens[index + 1 :]), cwd)
        return self._shell(shlex.join(tokens), cwd)

    @staticmethod
    def _remote_execution(host: str | None) -> Decision:
        return Decision(
            "approval_required",
            "remote.execute",
            f"open a remote shell to {host or 'remote host'}",
        )

    @classmethod
    def _mutation_targets(
        cls,
        executable: str,
        args: list[str],
        cwd: Path,
        positionals: tuple[Path, ...],
        redirect_targets: tuple[Path, ...],
    ) -> tuple[Path, ...]:
        targets = list(redirect_targets)
        destination_flags = cls._option_values(args, "-t", "--target-directory", cwd)
        if executable in {
            "rm",
            "unlink",
            "rmdir",
            "shred",
            "chmod",
            "chown",
            "touch",
            "truncate",
            "tee",
        }:
            targets.extend(positionals)
        elif executable == "install" and any(
            token in {"-d", "--directory"} for token in args
        ):
            targets.extend(positionals)
        elif executable in {"cp", "install"}:
            if destination_flags:
                targets.extend(destination_flags)
            elif positionals:
                targets.append(positionals[-1])
        elif executable == "mv":
            targets.extend(positionals)
            targets.extend(destination_flags)
        elif executable == "sed" and cls._sed_in_place(args):
            targets.extend(positionals)
        return tuple(targets)

    @staticmethod
    def _sed_in_place(args: list[str]) -> bool:
        options, _, _ = ConsequenceKernel._parse_options(args, *_SED_VALUE_OPTIONS)
        names = {option.partition("=")[0] for option in options}
        return "-i" in options or ConsequenceKernel._git_given(("--in-place",), names)

    @classmethod
    def _option_values(
        cls,
        args: list[str],
        short_name: str,
        long_name: str,
        cwd: Path,
    ) -> list[Path]:
        found: list[Path] = []
        prefix = long_name + "="
        index = 0
        while index < len(args):
            token = args[index]
            if token in {short_name, long_name} and index + 1 < len(args):
                found.append(cls._resolve_from(args[index + 1], cwd))
                index += 2
                continue
            if token.startswith(prefix):
                value = token[len(prefix) :]
                if value:
                    found.append(cls._resolve_from(value, cwd))
            index += 1
        return found

    @classmethod
    def _shell_paths(
        cls,
        tokens: list[str],
        cwd: Path,
    ) -> tuple[tuple[Path, ...], tuple[Path, ...], tuple[Path, ...]]:
        found: list[Path] = []
        positionals: list[Path] = []
        redirect_targets: list[Path] = []
        index = 0
        while index < len(tokens):
            token = tokens[index]
            redirect = cls._output_redirection(token)
            if redirect is not None:
                target = redirect
                if not target and index + 1 < len(tokens):
                    index += 1
                    target = tokens[index]
                if target and not target.startswith("&"):
                    path = cls._resolve_from(target, cwd)
                    found.append(path)
                    redirect_targets.append(path)
                index += 1
                continue
            redirect = cls._input_redirection(token)
            if redirect is not None:
                target = redirect
                if not target and index + 1 < len(tokens):
                    index += 1
                    target = tokens[index]
                if target:
                    found.append(cls._resolve_from(target, cwd))
                index += 1
                continue
            if token.startswith("--") and "=" in token:
                value = token.split("=", 1)[1]
                if value:
                    found.append(cls._resolve_from(value, cwd))
                index += 1
                continue
            if not token.startswith("-"):
                path = cls._resolve_from(token, cwd)
                found.append(path)
                positionals.append(path)
            index += 1
        return tuple(found), tuple(positionals), tuple(redirect_targets)

    @staticmethod
    def _output_redirection(token: str) -> str | None:
        return ConsequenceKernel._redirection_target(token, ">")

    @staticmethod
    def _input_redirection(token: str) -> str | None:
        return ConsequenceKernel._redirection_target(token, "<")

    @staticmethod
    def _redirection_target(token: str, marker: str) -> str | None:
        index = token.find(marker)
        if index >= 0:
            target = token[index + 1 :]
            if target.startswith(marker):
                target = target[1:]
            return target
        return None

    @staticmethod
    def _environment_dump(executable: str, args: list[str]) -> bool:
        if executable == "printenv":
            if any(token in {"--help", "--version"} for token in args):
                return False
            return not any(token not in {"-0", "--null"} for token in args)
        if executable != "env":
            return False
        index = 0
        options_with_values = {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}
        while index < len(args):
            token = args[index]
            if token in {"--help", "--version"}:
                return False
            if token == "--":
                return index + 1 >= len(args)
            if token in options_with_values:
                index += 2
                continue
            if token.startswith(("--unset=", "--chdir=", "--split-string=")):
                index += 1
                continue
            if token.startswith("-") or "=" in token:
                index += 1
                continue
            return False
        return True

    @staticmethod
    def _git_history_mutation(args: list[str]) -> bool:
        if not args:
            return False
        if args[0] == "push":
            options, refspecs = ConsequenceKernel._git_push_parts(args[1:])
            return ConsequenceKernel._git_given(_GIT_PUSH_FORCING, options) or any(
                refspec.startswith("+") for refspec in refspecs
            )
        if args[0] == "clean":
            return not any(token in {"-n", "--dry-run"} for token in args[1:])
        if args[0] == "restore":
            options = ConsequenceKernel._git_options(args[1:], "restore")
            others = tuple(flag for flag in _GIT_RESTORE_LONG_OPTIONS if flag != "--staged")
            staged = "-S" in options or any(
                ConsequenceKernel._git_given(("--staged",), {option})
                and not ConsequenceKernel._git_given(others, {option})
                for option in options
            )
            return not staged or ConsequenceKernel._git_given(("-W", "--worktree"), options)
        if args[0] == "checkout" and "--" in args[1:]:
            return True
        return ConsequenceKernel._git_form_matches(args, _GIT_DISCARDING_FORMS)

    @staticmethod
    def _git_ref_deletion(args: list[str]) -> bool:
        if not args:
            return False
        if args[0] != "push":
            return ConsequenceKernel._git_form_matches(args, _GIT_REF_DELETING_FORMS)
        options, refspecs = ConsequenceKernel._git_push_parts(args[1:])
        return ConsequenceKernel._git_given(_GIT_PUSH_DELETING, options) or any(
            refspec.startswith(":") and len(refspec) > 1 for refspec in refspecs
        )

    @staticmethod
    def _git_push_parts(args: list[str]) -> tuple[set[str], list[str]]:
        """Split push into option names, ignoring their values, and refspecs."""
        options = ConsequenceKernel._git_options(args, "push")
        names = {
            option.partition("=")[0] for option in options if option.startswith("-")
        }
        after_separator = args[args.index("--") + 1 :] if "--" in args else []
        refspecs = [option for option in options if not option.startswith("-")]
        return names, refspecs + after_separator

    @staticmethod
    def _git_form_matches(
        args: list[str],
        forms: dict[tuple[str, ...], tuple[tuple[frozenset[str], ...], ...]],
    ) -> bool:
        for length in (2, 1):
            alternatives = forms.get(tuple(args[:length]))
            if alternatives is not None:
                options = ConsequenceKernel._git_options(args[length:], args[0])
                return any(
                    all(ConsequenceKernel._git_given(group, options) for group in alternative)
                    for alternative in alternatives
                )
        return False

    @staticmethod
    def _git_given(flags: tuple[str, ...] | frozenset[str], options: set[str]) -> bool:
        """Match short flags exactly and long flags by git's prefix abbreviation."""
        for flag in flags:
            if not flag.startswith("--"):
                if flag in options:
                    return True
                continue
            name, _, value = flag.partition("=")
            for option in options:
                given, _, given_value = option.partition("=")
                if (
                    option.startswith("--")
                    and len(given) > 2
                    and name.startswith(given)
                    and given_value == value
                ):
                    return True
        return False

    @staticmethod
    def _git_options(args: list[str], subcommand: str) -> set[str]:
        options, operands, _ = ConsequenceKernel._parse_options(
            args, *_GIT_VALUE_OPTIONS.get(subcommand, ("", ()))
        )
        return options | set(operands)

    @staticmethod
    def _parse_options(
        args: list[str],
        short_values: str,
        long_values: tuple[str, ...],
    ) -> tuple[set[str], list[str], list[str]]:
        """Read getopt-style args into options, operands, and operands after --.

        Short clusters end at a value-taking letter. Values of value-taking
        options are skipped and never read as options or operands.
        """
        options: set[str] = set()
        operands: list[str] = []
        tokens = iter(args)
        for token in tokens:
            if token == "--":
                return options, operands, list(tokens)
            if token.startswith("--"):
                options.add(token)
                if "=" not in token and ConsequenceKernel._git_given(long_values, {token}):
                    next(tokens, None)
            elif token.startswith("-") and len(token) > 1:
                for position, letter in enumerate(token[1:], start=2):
                    options.add("-" + letter)
                    if letter in short_values:
                        if position == len(token):
                            next(tokens, None)
                        break
            else:
                operands.append(token)
        return options, operands, []

    @staticmethod
    def _git_command_args(args: list[str]) -> list[str]:
        remaining = list(args)
        while remaining:
            token = remaining[0]
            if token in _GIT_VALUE_GLOBALS and len(remaining) >= 2:
                remaining = remaining[2:]
                continue
            name, equals, _ = token.partition("=")
            attached = token[:2] in {"-C", "-c"} or (
                equals and (name in _GIT_VALUE_GLOBALS or name == "--exec-path")
            )
            if attached or token in _GIT_BOOLEAN_GLOBALS:
                remaining = remaining[1:]
                continue
            break
        return remaining

    @staticmethod
    def _gt_command_args(args: list[str]) -> list[str]:
        remaining = list(args)
        while remaining and remaining[0].startswith("-"):
            remaining = remaining[2:] if remaining[0] == "--cwd" else remaining[1:]
        return remaining

    @staticmethod
    def _mask_direct_git_push_heredoc_body(command: str) -> str:
        if "<<" not in command or "\n" not in command:
            return command
        normalized = command.replace("\\\n", "") if "\\\n" in command else command
        declaration_end = normalized.find("\n")
        if declaration_end < 0:
            return command
        try:
            tokens = ConsequenceKernel._line_tokens(normalized[:declaration_end])
        except ValueError:
            return command
        if not tokens or Path(tokens[0]).name != "git":
            return command
        if ConsequenceKernel._git_command_args(tokens[1:])[:1] != ["push"]:
            return command
        delimiter = ConsequenceKernel._heredoc_delimiter(tokens)
        if delimiter is None:
            return command
        marker, strip_tabs = delimiter
        body_start = declaration_end + 1
        offset = body_start
        while True:
            newline = normalized.find("\n", offset)
            line_end = len(normalized) if newline < 0 else newline
            line = normalized[offset:line_end]
            if (line.lstrip("\t") if strip_tabs else line) == marker:
                suffix_start = line_end + 1
                return (
                    normalized[: body_start - 1]
                    if suffix_start >= len(normalized)
                    else normalized[:body_start] + normalized[suffix_start:]
                )
            if newline < 0:
                return command
            offset = newline + 1

    @staticmethod
    def _line_tokens(line: str) -> list[str]:
        lexer = shlex.shlex(line, posix=True, punctuation_chars="<>|&;")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)

    @staticmethod
    def _heredoc_delimiter(tokens: list[str]) -> tuple[str, bool] | None:
        for index, token in enumerate(tokens[:-1]):
            if token == "<<":
                delimiter = tokens[index + 1]
                strip_tabs = delimiter.startswith("-") and len(delimiter) > 1
                return (delimiter[1:] if strip_tabs else delimiter), strip_tabs
        return None

    @staticmethod
    def _git_display(args: list[str]) -> str:
        if args and args[0] == "push":
            targets = [
                token
                for token in args[1:]
                if not token.startswith("-")
            ]
            return "git push to " + (" ".join(targets) if targets else "configured remote/ref")
        return "git " + " ".join(args[:2])

    @staticmethod
    def _production_mutation(tokens: list[str]) -> bool:
        executable = Path(tokens[0]).name
        executable = _PRODUCTION_ALIASES.get(executable, executable)
        args = tokens[1:]
        if executable == "railway":
            return ConsequenceKernel._railway_command(args) is not None
        if executable == "fly":
            return bool(args and args[0] in {"deploy", "release"})
        if executable == "vercel":
            return "--prod" in args or "--production" in args
        if executable == "kubectl":
            command = ConsequenceKernel._kubectl_command_args(args)
            if not command or ConsequenceKernel._kubectl_dry_run(command):
                return False
            if command[0] == "rollout":
                return len(command) >= 2 and command[1] in {
                    "pause",
                    "restart",
                    "resume",
                    "undo",
                }
            return command[0] in {
                "annotate",
                "apply",
                "autoscale",
                "cordon",
                "create",
                "delete",
                "drain",
                "edit",
                "expose",
                "label",
                "patch",
                "replace",
                "run",
                "scale",
                "set",
                "taint",
                "uncordon",
            }
        if executable == "gh":
            return args[:2] in (
                ["pr", "merge"],
                ["release", "create"],
                ["release", "delete"],
                ["repo", "delete"],
            )
        return False

    @staticmethod
    def _railway_command(args: list[str]) -> tuple[str, ...] | None:
        return next(
            (
                tuple(args[:length])
                for length in (2, 1)
                if tuple(args[:length]) in _RAILWAY_MUTATING_COMMANDS
            ),
            None,
        )

    @staticmethod
    def _kubectl_dry_run(command: list[str]) -> bool:
        """kubectl reads the last --dry-run; client and server change nothing.

        --raw sends the request as given and ignores --dry-run.

        A dry run after a spaced option may be that option's value, so it
        does not count.
        """
        given = command[: command.index("--")] if "--" in command else command
        if any(token == "--raw" or token.startswith("--raw=") for token in given):
            return False
        dry_runs = [token for token in given if token.startswith("--dry-run")]
        spaced_values = {
            token
            for previous, token in zip(given, given[1:])
            if previous.startswith("-")
            and "=" not in previous
            and (len(previous) == 2 or previous.startswith("--"))
        }
        return (
            bool(dry_runs)
            and dry_runs[-1] in _KUBECTL_DRY_RUNS
            and not spaced_values.intersection(dry_runs)
        )

    @staticmethod
    def _kubectl_verb(args: list[str]) -> str:
        command = ConsequenceKernel._kubectl_command_args(args)
        return command[0] if command else ""

    @staticmethod
    def _kubectl_command_args(args: list[str]) -> list[str]:
        flags_with_values = {
            "--as",
            "--as-group",
            "--as-uid",
            "--cache-dir",
            "--certificate-authority",
            "--client-certificate",
            "--client-key",
            "--cluster",
            "--context",
            "--kubeconfig",
            "--namespace",
            "-n",
            "--password",
            "--profile",
            "--profile-output",
            "--request-timeout",
            "--server",
            "-s",
            "--tls-server-name",
            "--token",
            "--user",
            "--username",
            "-v",
            "--v",
            "--vmodule",
        }
        index = 0
        while index < len(args):
            token = args[index]
            if token == "--":
                return args[index + 1 :]
            if token in flags_with_values:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            return args[index:]
        return []

    @staticmethod
    def _production_display(tokens: list[str]) -> str:
        executable = Path(tokens[0]).name
        executable = _PRODUCTION_ALIASES.get(executable, executable)
        args = tokens[1:]
        if executable == "railway":
            return "railway " + " ".join(ConsequenceKernel._railway_command(args) or ("mutation",))
        if executable == "fly":
            return "fly " + (args[0] if args else "mutation")
        if executable == "vercel":
            return "vercel " + ("--prod" if "--prod" in args else "--production")
        if executable == "kubectl":
            return "kubectl " + (ConsequenceKernel._kubectl_verb(args) or "mutation")
        if executable == "gh":
            return "gh " + " ".join(args[:3])
        return executable

    @staticmethod
    def _public_bind(tokens: list[str]) -> bool:
        public_values = {"0.0.0.0", "::", "[::]"}
        executable = Path(tokens[0]).name
        if executable == "vite":
            for index, token in enumerate(tokens):
                if token == "--host" and (
                    index + 1 >= len(tokens) or tokens[index + 1].startswith("-")
                ):
                    return True
        for index, token in enumerate(tokens[:-1]):
            if token in {"--host", "--bind", "-H"} and tokens[index + 1] in public_values:
                return True
        return any(
            token.startswith(("--host=", "--bind="))
            and token.split("=", 1)[1] in public_values
            for token in tokens
        )
