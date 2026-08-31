from __future__ import annotations

from engine.consequences_v2 import ConsequenceKernel


class DenyOnlyKernel(ConsequenceKernel):
    """Default-open direct-consequence policy with no approval outcome.

    The proven v2 recognizers remain the narrow detection seam. The adapter
    turns every recognized consequence into a final denial; no receipt or
    human-response state exists in this release.
    """

    @staticmethod
    def _production_mutation(tokens: list[str]) -> bool:
        executable = tokens[0].rsplit("/", 1)[-1]
        args = tokens[1:]
        if executable == "gh":
            if args[:2] == ["pr", "merge"]:
                return "--admin" in args
            return args[:2] in (["release", "delete"], ["repo", "delete"])
        return ConsequenceKernel._production_mutation(tokens)
