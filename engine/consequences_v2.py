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
        command = self._mask_direct_git_push_heredoc_body(command)
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            return Decision("allow")
        if not tokens:
            return Decision("allow")
        executable = Path(tokens[0]).name
        token_paths, positionals, redirect_targets = self._shell_paths(tokens[1:], cwd)
        if any(self._inside(path, self.credential_paths) for path in token_paths):
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
        if executable in {"rm", "unlink", "rmdir"}:
            targets = [token for token in tokens[1:] if not token.startswith("-")]
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
        elif executable == "sed" and "-i" in args:
            targets.extend(positionals)
        return tuple(targets)

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
