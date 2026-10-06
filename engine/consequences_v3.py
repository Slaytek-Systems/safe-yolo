from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shlex
from typing import Any, Literal

from engine.consequences_v2 import ConsequenceKernel


Outcome = Literal["allow", "deny"]


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    consequence: str | None = None
    display: str | None = None


class DenyOnlyKernel(ConsequenceKernel):
    """Default-open direct-consequence policy with no approval outcome.

    The proven v2 recognizers remain the narrow detection seam. This kernel
    collapses every recognized consequence into a final denial; no receipt or
    human-response state exists in this release or its adapters.
    """

    def __init__(self, *, observation_dir: str | Path | None = None,
                 observation_harness: str = "unknown", customizations_path: Path | None = None,
                 **options: Any) -> None:
        super().__init__(**options)
        self.observation_dir = observation_dir
        self.observation_harness = observation_harness
        self.customization_error = False
        self.denied_tools: set[str] = set()
        if customizations_path is not None:
            try:
                with customizations_path.open('rb') as handle:
                    content = handle.read(65537)
                if len(content) > 65536:
                    raise ValueError('customizations too large')
                settings = json.loads(content)
                if not isinstance(settings, dict) or set(settings) - {'deny_tools', 'private_paths'}:
                    raise ValueError('unknown customization fields')
                for values in settings.values():
                    if not isinstance(values, list) or not all(isinstance(value, str) and value for value in values):
                        raise ValueError('customizations must be lists of nonempty strings')
                paths = settings.get('private_paths', [])
                if any(not Path(path).is_absolute() for path in paths):
                    raise ValueError('private paths must be absolute')
                self.credential_paths += tuple(self._path(path) for path in paths)
                self.denied_tools = {name.lower() for name in settings.get('deny_tools', [])}
            except FileNotFoundError:
                if customizations_path.is_symlink():
                    self.customization_error = True
            except (OSError, ValueError, TypeError):
                self.customization_error = True

    def evaluate(self, payload: dict[str, Any]) -> Decision:
        decision = self._evaluate(payload)
        if self.observation_dir is not None:
            try:
                from engine.deletion_observation import observe
                observe(payload, decision, self)
            except Exception:
                import sys
                try:
                    sys.stderr.write("Safe YOLO observation unavailable\n")
                except Exception:
                    pass
        return decision

    def _evaluate(self, payload: dict[str, Any]) -> Decision:
        tool_name = str(payload.get("tool_name") or "").lower()
        if self.customization_error:
            return Decision('deny', 'customization.invalid', 'repair customizations.json through operator maintenance')
        if tool_name in self.denied_tools:
            return Decision('deny', 'customization.tool', 'tool denied by your local customizations')
        if tool_name in {"stateful_shell", "write_to_process"}:
            return Decision(
                "deny",
                "interactive.process_write",
                "write to a process whose execution context cannot be classified",
            )
        recognized = super().evaluate(payload)
        if (
            self._direct_help_request(payload)
            and recognized.outcome == "approval_required"
        ):
            return Decision("allow")
        return Decision(
            "allow" if recognized.outcome == "allow" else "deny",
            recognized.consequence,
            recognized.display,
        )

    @staticmethod
    def _direct_help_request(payload: dict[str, Any]) -> bool:
        tool_name = str(payload.get("tool_name") or "").lower()
        tool_input = payload.get("tool_input")
        if tool_name not in {"bash", "shell", "exec_command"} or not isinstance(
            tool_input, dict
        ):
            return False
        command = tool_input.get("command") or tool_input.get("cmd")
        if not isinstance(command, str):
            return False
        if "\n" in command or any(
            marker in command for marker in ("$", "`", "(", ")", "{", "}", "#")
        ):
            return False
        try:
            lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;<>")
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError:
            return False
        if any(token and set(token) <= set("|&;<>") for token in tokens):
            return False
        for token in tokens[1:]:
            if token == "--":
                break
            if token in {"-h", "--help", "-V", "--version"}:
                return True
        return False

    @staticmethod
    def _production_mutation(tokens: list[str]) -> bool:
        executable = tokens[0].rsplit("/", 1)[-1]
        args = tokens[1:]
        if executable == "gh":
            command = DenyOnlyKernel._gh_command_args(args)
            if command[:2] == ["pr", "merge"]:
                return DenyOnlyKernel._gh_repo_override(args) or any(
                    token == "--admin" or token.startswith("--admin=")
                    for token in command[2:]
                )
            return command[:2] in (
                ["release", "create"],
                ["release", "delete"],
                ["repo", "delete"],
            )
        return ConsequenceKernel._production_mutation(tokens)

    @staticmethod
    def _gh_repo_override(args: list[str]) -> bool:
        return any(
            token == "--repo"
            or token.startswith("--repo=")
            or token.startswith("-R")
            for token in args
        )

    @staticmethod
    def _gh_command_args(args: list[str]) -> list[str]:
        remaining = list(args)
        while remaining:
            token = remaining[0]
            if token in {"-R", "--repo", "--hostname"}:
                if len(remaining) < 2:
                    return []
                remaining = remaining[2:]
                continue
            if token.startswith("-R") and token != "-R":
                remaining = remaining[1:]
                continue
            if token.startswith(("--repo=", "--hostname=")):
                remaining = remaining[1:]
                continue
            break
        return remaining
