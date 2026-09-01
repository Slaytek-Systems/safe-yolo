from __future__ import annotations

from dataclasses import dataclass
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

    def evaluate(self, payload: dict[str, Any]) -> Decision:
        recognized = super().evaluate(payload)
        return Decision(
            "allow" if recognized.outcome == "allow" else "deny",
            recognized.consequence,
            recognized.display,
        )

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
            return command[:2] in (["release", "delete"], ["repo", "delete"])
        return ConsequenceKernel._production_mutation(tokens)

    @staticmethod
    def _gh_repo_override(args: list[str]) -> bool:
        return any(
            token in {"-R", "--repo"} or token.startswith("--repo=")
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
            if token.startswith(("--repo=", "--hostname=")):
                remaining = remaining[1:]
                continue
            break
        return remaining
