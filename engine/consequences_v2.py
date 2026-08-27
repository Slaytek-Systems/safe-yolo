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
            "target_path",
            "source_path",
            "destination_path",
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
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            return Decision("allow")
        if not tokens:
            return Decision("allow")
        token_paths = tuple(
            self._resolve_from(token, cwd)
            for token in tokens[1:]
            if not token.startswith("-")
        )
        if any(self._inside(path, self.credential_paths) for path in token_paths):
            return Decision(
                "operator_only",
                "credentials.access",
                "credential material is not available to the agent",
            )
        mutating = tokens[0] in {"rm", "mv", "cp", "install", "tee", "chmod", "chown"}
        mutating = mutating or (tokens[0] == "sed" and "-i" in tokens[1:])
        mutating = mutating or any(token in {">", ">>"} for token in tokens)
        if mutating and any(self._inside(path, self.enforcement_paths) for path in token_paths):
            return Decision(
                "operator_only",
                "enforcement.modify",
                "Safe YOLO enforcement can only be changed through operator maintenance",
            )
        if tokens in (["env"], ["printenv"]):
            return Decision(
                "operator_only",
                "credentials.access",
                "dumping the complete process environment is not available to the agent",
            )
        if tokens[0] == "rm":
            targets = [token for token in tokens[1:] if not token.startswith("-")]
            display = "delete " + (", ".join(targets) if targets else "filesystem targets")
            return Decision("approval_required", "filesystem.delete", display)
        git_args = self._git_command_args(tokens[1:]) if tokens[0] == "git" else []
        if tokens[0] == "git" and self._git_history_mutation(git_args):
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
        if tokens[0] == "ssh":
            host = next((token for token in tokens[1:] if not token.startswith("-")), "remote host")
            return Decision(
                "approval_required",
                "remote.execute",
                f"open a remote shell to {host}",
            )
        if tokens[0] in {"sudo", "doas", "su"}:
            return Decision(
                "approval_required",
                "privilege.modify",
                f"execute through {tokens[0]}",
            )
        if self._public_bind(tokens):
            return Decision(
                "approval_required",
                "network.public_exposure",
                "bind a development service to a public interface",
            )
        return Decision("allow")

    @staticmethod
    def _git_history_mutation(args: list[str]) -> bool:
        if not args:
            return False
        if args[0] == "push":
            return any(
                token in {"-f", "--force", "--force-with-lease", "--delete", "--tags"}
                or token.startswith("--force-with-lease=")
                or token.startswith("+")
                or (token.startswith(":") and len(token) > 1)
                for token in args[1:]
            )
        if args[0] in {"rebase", "clean"}:
            return True
        if args[0] == "reset" and "--hard" in args[1:]:
            return True
        if args[0] in {"checkout", "restore"} and "--" in args[1:]:
            return True
        return False

    @staticmethod
    def _git_command_args(args: list[str]) -> list[str]:
        remaining = list(args)
        while remaining:
            if remaining[0] in {"-C", "-c", "--git-dir", "--work-tree"} and len(remaining) >= 2:
                remaining = remaining[2:]
                continue
            if remaining[0].startswith(("--git-dir=", "--work-tree=")):
                remaining = remaining[1:]
                continue
            break
        return remaining

    @staticmethod
    def _git_display(args: list[str]) -> str:
        if args and args[0] == "push":
            targets = [token for token in args[1:] if not token.startswith("-")]
            return "git push to " + (" ".join(targets) if targets else "configured remote/ref")
        return "git " + " ".join(args[:2])

    @staticmethod
    def _production_mutation(tokens: list[str]) -> bool:
        executable = tokens[0]
        args = tokens[1:]
        if executable == "railway":
            return any(arg in {"up", "deploy"} for arg in args)
        if executable == "fly":
            return bool(args and args[0] in {"deploy", "release"})
        if executable == "vercel":
            return "--prod" in args or "--production" in args
        if executable == "kubectl":
            return bool(args and args[0] in {"apply", "delete", "patch", "replace", "scale"})
        if executable == "gh":
            return args[:2] in (
                ["pr", "merge"],
                ["release", "create"],
                ["release", "delete"],
                ["repo", "delete"],
            )
        return False

    @staticmethod
    def _production_display(tokens: list[str]) -> str:
        executable = tokens[0]
        args = tokens[1:]
        if executable == "railway":
            subcommand = next((arg for arg in args if arg in {"up", "deploy"}), "mutation")
            return f"railway {subcommand}"
        if executable == "fly":
            return "fly " + (args[0] if args else "mutation")
        if executable == "vercel":
            return "vercel " + ("--prod" if "--prod" in args else "--production")
        if executable == "kubectl":
            return "kubectl " + (args[0] if args else "mutation")
        if executable == "gh":
            return "gh " + " ".join(args[:3])
        return executable

    @staticmethod
    def _public_bind(tokens: list[str]) -> bool:
        public_values = {"0.0.0.0", "::", "[::]"}
        for index, token in enumerate(tokens[:-1]):
            if token in {"--host", "--bind", "-H"} and tokens[index + 1] in public_values:
                return True
        return any(
            token.startswith(("--host=", "--bind="))
            and token.split("=", 1)[1] in public_values
            for token in tokens
        )
