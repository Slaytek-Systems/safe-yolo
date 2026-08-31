from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shlex
from typing import Any, Literal


Outcome = Literal["allow", "approval_required", "operator_only"]


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    consequence: str | None = None
    display: str | None = None


@dataclass(frozen=True)
class ShellInvocation:
    executable: str
    argv: tuple[str, ...]
    source_span: tuple[int, int]


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
    ) -> None:
        self.enforcement_paths = tuple(self._path(path) for path in enforcement_paths)
        self.credential_paths = tuple(self._path(path) for path in credential_paths)

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
            display = "delete " + (", ".join(str(path) for path in paths) or "filesystem target")
            return Decision("approval_required", "filesystem.delete", display)
        if tool_name == "apply_patch" and isinstance(tool_input, dict):
            patch = tool_input.get("patch") or tool_input.get("command") or ""
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
        invocations = self._shell_invocations(command)
        if invocations is None:
            return Decision("allow")
        best = Decision("allow")
        for invocation in invocations:
            decision = self._shell_invocation_decision(invocation, cwd)
            if self._decision_rank(decision) > self._decision_rank(best):
                best = decision
        return best

    def _shell_invocation_decision(self, invocation: ShellInvocation, cwd: Path) -> Decision:
        tokens = list(invocation.argv)
        executable = invocation.executable
        token_paths, redirects_output = self._shell_paths(tokens[1:], cwd)
        if any(self._inside(path, self.credential_paths) for path in token_paths):
            return Decision(
                "operator_only",
                "credentials.access",
                "credential material is not available to the agent",
            )
        mutating = executable in {
            "rm",
            "mv",
            "cp",
            "install",
            "tee",
            "chmod",
            "chown",
            "touch",
            "truncate",
            "unlink",
            "rmdir",
        }
        mutating = mutating or (executable == "sed" and "-i" in tokens[1:])
        mutating = mutating or redirects_output
        if mutating and any(self._inside(path, self.enforcement_paths) for path in token_paths):
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
        if executable in {"rm", "unlink", "rmdir"}:
            targets = [token for token in tokens[1:] if not token.startswith("-")]
            display = "delete " + (", ".join(targets) if targets else "filesystem targets")
            return Decision("approval_required", "filesystem.delete", display)
        git_args = self._git_command_args(tokens[1:]) if executable == "git" else []
        if executable == "git" and self._git_history_mutation(git_args):
            return Decision(
                "approval_required",
                "git.history_mutation",
                self._git_display(git_args),
            )
        if self._production_mutation(tokens):
            return Decision(
                "approval_required",
                "production.mutate",
                f"run {self._production_display(tokens)} production mutation",
            )
        if executable == "ssh":
            host = self._ssh_host(tokens[1:])
            return Decision(
                "approval_required",
                "remote.execute",
                f"open a remote shell to {host}",
            )
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

    @classmethod
    def _shell_invocations(cls, command: str) -> tuple[ShellInvocation, ...] | None:
        invocations: list[ShellInvocation] = []
        pending_heredocs: list[tuple[str, bool]] = []
        segment_start = 0
        quote: str | None = None
        index = 0
        while index < len(command):
            char = command[index]
            if quote is not None:
                if char == "\\" and quote == '"' and index + 1 < len(command):
                    index += 2
                    continue
                if char == quote:
                    quote = None
                index += 1
                continue
            if char == "\\":
                index += 2 if index + 1 < len(command) else 1
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            heredoc = cls._heredoc_delimiter(command, index)
            if heredoc is not None:
                pending_heredocs.append((heredoc[0], heredoc[1]))
                index += heredoc[2]
                continue
            separator = cls._shell_separator(command, index)
            if separator is None:
                index += 1
                continue
            invocation = cls._build_invocation(command, segment_start, index)
            if invocation is None and command[segment_start:index].strip():
                return None
            if invocation is not None:
                invocations.append(invocation)
            index += separator[1]
            if separator[0] == "newline" and pending_heredocs:
                index = cls._consume_heredoc_bodies(command, index, pending_heredocs)
                pending_heredocs.clear()
            segment_start = index
        if quote is not None:
            return None
        invocation = cls._build_invocation(command, segment_start, len(command))
        if invocation is None and command[segment_start:].strip():
            return None
        if invocation is not None:
            invocations.append(invocation)
        return tuple(invocations)

    @staticmethod
    def _decision_rank(decision: Decision) -> tuple[int, int]:
        outcome_rank = {
            "allow": 0,
            "approval_required": 1,
            "operator_only": 2,
        }
        consequence_rank = {
            None: 0,
            "filesystem.delete": 1,
            "git.history_mutation": 2,
            "network.public_exposure": 3,
            "remote.execute": 4,
            "privilege.modify": 5,
            "production.mutate": 6,
            "enforcement.modify": 7,
            "credentials.access": 8,
        }
        return (
            outcome_rank[decision.outcome],
            consequence_rank.get(decision.consequence, 0),
        )

    @staticmethod
    def _shell_separator(command: str, index: int) -> tuple[str, int] | None:
        if command.startswith("&&", index):
            return ("and", 2)
        if command.startswith("||", index):
            return ("or", 2)
        if command[index] == ";":
            return ("semicolon", 1)
        if command[index] == "|":
            return ("pipe", 1)
        if command[index] == "\n":
            return ("newline", 1)
        return None

    @classmethod
    def _build_invocation(
        cls,
        command: str,
        start: int,
        end: int,
    ) -> ShellInvocation | None:
        segment = command[start:end]
        stripped = segment.strip()
        if not stripped:
            return None
        trimmed_start = start + len(segment) - len(segment.lstrip())
        trimmed_end = end - (len(segment) - len(segment.rstrip()))
        try:
            argv = tuple(shlex.split(command[trimmed_start:trimmed_end], posix=True))
        except ValueError:
            return None
        if not argv:
            return None
        return ShellInvocation(
            executable=Path(argv[0]).name,
            argv=argv,
            source_span=(trimmed_start, trimmed_end),
        )

    @classmethod
    def _heredoc_delimiter(cls, command: str, index: int) -> tuple[str, bool, int] | None:
        if not command.startswith("<<", index):
            return None
        cursor = index + 2
        strip_tabs = cursor < len(command) and command[cursor] == "-"
        if strip_tabs:
            cursor += 1
        while cursor < len(command) and command[cursor] in {" ", "\t"}:
            cursor += 1
        start = cursor
        quote: str | None = None
        while cursor < len(command):
            char = command[cursor]
            if quote is not None:
                if char == "\\" and quote == '"' and cursor + 1 < len(command):
                    cursor += 2
                    continue
                if char == quote:
                    quote = None
                cursor += 1
                continue
            if char in {"'", '"'}:
                quote = char
                cursor += 1
                continue
            if char in {" ", "\t", "\n", ";", "|", "&", "<", ">"}:
                break
            if char == "\\" and cursor + 1 < len(command):
                cursor += 2
                continue
            cursor += 1
        if quote is not None or start == cursor:
            return None
        try:
            parsed = shlex.split(command[start:cursor], posix=True)
        except ValueError:
            return None
        if len(parsed) != 1 or not parsed[0]:
            return None
        return parsed[0], strip_tabs, cursor - index

    @staticmethod
    def _consume_heredoc_bodies(
        command: str,
        index: int,
        pending_heredocs: list[tuple[str, bool]],
    ) -> int:
        cursor = index
        for delimiter, strip_tabs in pending_heredocs:
            while cursor < len(command):
                newline = command.find("\n", cursor)
                if newline < 0:
                    line = command[cursor:]
                    cursor = len(command)
                else:
                    line = command[cursor:newline]
                    cursor = newline + 1
                if strip_tabs:
                    line = line.lstrip("\t")
                if line == delimiter:
                    break
        return cursor

    @classmethod
    def _shell_paths(
        cls,
        tokens: list[str],
        cwd: Path,
    ) -> tuple[tuple[Path, ...], bool]:
        found: list[Path] = []
        redirects_output = False
        for token in tokens:
            redirect = cls._output_redirection(token)
            if redirect is not None:
                redirects_output = True
                if redirect and not redirect.startswith("&"):
                    found.append(cls._resolve_from(redirect, cwd))
                continue
            redirect = cls._input_redirection(token)
            if redirect is not None:
                if redirect:
                    found.append(cls._resolve_from(redirect, cwd))
                continue
            if token.startswith("--") and "=" in token:
                value = token.split("=", 1)[1]
                if value:
                    found.append(cls._resolve_from(value, cwd))
                continue
            if not token.startswith("-"):
                found.append(cls._resolve_from(token, cwd))
        return tuple(found), redirects_output

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
            return any(
                token in {
                    "-f",
                    "--force",
                    "--force-with-lease",
                    "--delete",
                    "-d",
                    "--tags",
                    "--mirror",
                    "--prune",
                }
                or token.startswith("--force-with-lease=")
                or token.startswith("+")
                or (token.startswith(":") and len(token) > 1)
                for token in args[1:]
            )
        if args[0] == "rebase":
            return True
        if args[0] == "clean":
            return not any(token in {"-n", "--dry-run"} for token in args[1:])
        if args[0] == "reset" and "--hard" in args[1:]:
            return True
        if args[0] == "restore":
            return True
        if args[0] == "checkout" and "--" in args[1:]:
            return True
        return False

    @staticmethod
    def _git_command_args(args: list[str]) -> list[str]:
        remaining = list(args)
        boolean_globals = {
            "--no-pager",
            "--paginate",
            "-p",
            "--literal-pathspecs",
            "--no-literal-pathspecs",
            "--glob-pathspecs",
            "--noglob-pathspecs",
            "--icase-pathspecs",
            "--no-optional-locks",
            "--bare",
        }
        while remaining:
            if remaining[0] in {"-C", "-c", "--git-dir", "--work-tree"} and len(remaining) >= 2:
                remaining = remaining[2:]
                continue
            if remaining[0].startswith(("--git-dir=", "--work-tree=")):
                remaining = remaining[1:]
                continue
            if remaining[0] in boolean_globals:
                remaining = remaining[1:]
                continue
            break
        return remaining

    @staticmethod
    def _ssh_host(args: list[str]) -> str:
        options_with_values = {
            "-B",
            "-b",
            "-c",
            "-D",
            "-E",
            "-e",
            "-F",
            "-I",
            "-i",
            "-J",
            "-L",
            "-l",
            "-m",
            "-O",
            "-o",
            "-P",
            "-p",
            "-R",
            "-S",
            "-W",
            "-w",
        }
        index = 0
        while index < len(args):
            token = args[index]
            if token == "--":
                return args[index + 1] if index + 1 < len(args) else "remote host"
            if token in options_with_values:
                index += 2
                continue
            if token.startswith("-"):
                index += 1
                continue
            return token
        return "remote host"

    @staticmethod
    def _git_display(args: list[str]) -> str:
        if args and args[0] == "push":
            targets = [token for token in args[1:] if not token.startswith("-")]
            return "git push to " + (" ".join(targets) if targets else "configured remote/ref")
        return "git " + " ".join(args[:2])

    @staticmethod
    def _production_mutation(tokens: list[str]) -> bool:
        executable = Path(tokens[0]).name
        args = tokens[1:]
        if executable == "railway":
            return any(arg in {"up", "deploy"} for arg in args)
        if executable == "fly":
            return bool(args and args[0] in {"deploy", "release"})
        if executable == "vercel":
            return "--prod" in args or "--production" in args
        if executable == "kubectl":
            command = ConsequenceKernel._kubectl_command_args(args)
            if not command:
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
    def _kubectl_verb(args: list[str]) -> str:
        command = ConsequenceKernel._kubectl_command_args(args)
        return command[0] if command else ""

    @staticmethod
    def _kubectl_command_args(args: list[str]) -> list[str]:
        flags_with_values = {
            "--as",
            "--as-group",
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
        args = tokens[1:]
        if executable == "railway":
            subcommand = next((arg for arg in args if arg in {"up", "deploy"}), "mutation")
            return f"railway {subcommand}"
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
