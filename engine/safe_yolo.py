from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .capabilities import CapabilityStore


DECISIONS = {
    "green": "allow",
    "blue": "allow_report",
    "amber": "require_capability",
    "red": "block_hard",
}

SHELLS = {"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh"}
DESTRUCTIVE_GIT = {"reset", "rebase", "restore", "clean"}
FORCE_FLAGS = {"--force", "--force-with-lease", "-f"}
PROTECTED_BRANCHES = {"main", "master", "production", "prod"}
NETWORK_WRITE_FLAGS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "-F",
    "--form",
    "-T",
    "--upload-file",
}
AUTH_FLAGS = {
    "-u",
    "--user",
    "--oauth2-bearer",
    "--netrc",
    "--netrc-file",
    "--cookie",
    "-b",
    "--cert",
    "--key",
    "--proxy-user",
}
PRIVATE_HOSTS = {"localhost", "0.0.0.0", "127.0.0.1", "::1"}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal"}
SECRET_RE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{20,}|github_pat_[A-Za-z0-9_]{20,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})"
)
BENIGN_CREDENTIAL_LIKE_PATH_COMPONENTS = {"codex-task-session-operating-model.md"}
TAG_RE = re.compile(r"(?:refs/tags/)?v?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$")
SYSTEM_RED_EXECUTABLES = {
    "sudo",
    "su",
    "doas",
    "dd",
    "mkfs",
    "fdisk",
    "diskutil",
    "shutdown",
    "reboot",
    "halt",
    "poweroff",
    "killall",
    "pkill",
    "launchctl",
    "osascript",
}
REMOTE_EXECUTABLES = {"ssh", "scp", "rsync"}
TRACKED_VALIDATION_NAME = "tracked-validation"
TRACKED_VALIDATION_EXECUTABLE = "/home/dev/devbox-ops/bin/tracked-validation"
TRACKED_VALIDATION_OPERATIONS_ROOT = "/home/dev/devbox-ops"
TRACKED_VALIDATION_REPOSITORY = "devbox-ops"
TRACKED_VALIDATION_PATH = "validation/test-gh-prm.sh"
TRACKED_VALIDATION_COMMAND_RE = re.compile(
    rf"{re.escape(TRACKED_VALIDATION_EXECUTABLE)} "
    rf"{TRACKED_VALIDATION_REPOSITORY} [0-9a-f]{{40}} "
    rf"{re.escape(TRACKED_VALIDATION_PATH)}$"
)
TRACKED_VALIDATION_SAFE_MENTION_EXECUTABLES = {"echo", "grep", "printf"}
TRACKED_VALIDATION_WRAPPERS = {
    "bash",
    "builtin",
    "chrt",
    "command",
    "env",
    "eval",
    "exec",
    "fish",
    "ionice",
    "nice",
    "nohup",
    "parallel",
    "setsid",
    "sh",
    "stdbuf",
    "timeout",
    "xargs",
    "zsh",
}
TRACKED_VALIDATION_SHA_RE = re.compile(r"[0-9a-f]{40}$")
OPAQUE_INTERPRETERS = {
    "R",
    "Rscript",
    "awk",
    "gawk",
    "groovy",
    "lua",
    "luajit",
    "mawk",
    "nawk",
    "node",
    "perl",
    "php",
    "python",
    "python3",
    "ruby",
    "tclsh",
    "wish",
}
MULTICALL_EXECUTABLES = {"busybox", "toybox"}
DANGEROUS_GIT_ENVIRONMENT = {
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_ASKPASS",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "GIT_EDITOR",
    "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PAGER",
    "GIT_PROXY_COMMAND",
    "GIT_SEQUENCE_EDITOR",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_WORK_TREE",
}
KNOWN_GIT_SUBCOMMANDS = {
    "add",
    "archive",
    "bisect",
    "blame",
    "branch",
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "check-ref-format",
    "checkout",
    "clean",
    "clone",
    "commit",
    "config",
    "describe",
    "diff",
    "diff-index",
    "diff-tree",
    "fetch",
    "for-each-ref",
    "fsck",
    "grep",
    "hash-object",
    "help",
    "init",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "merge",
    "merge-base",
    "merge-tree",
    "mv",
    "name-rev",
    "push",
    "rebase",
    "remote",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "shortlog",
    "show",
    "show-ref",
    "status",
    "switch",
    "symbolic-ref",
    "tag",
    "update-index",
    "worktree",
}


def result(decision: str, policy_id: str, reason: str, **extra: Any) -> dict[str, Any]:
    return {"decision": decision, "policy_id": policy_id, "reason": reason, **extra}


class SafeYoloEngine:
    def __init__(
        self,
        policy: dict[str, Any],
        capability_store: CapabilityStore | None = None,
        path_variables: dict[str, str] | None = None,
        host_contract: dict[str, Any] | None = None,
    ):
        self.policy = policy
        self.actions = policy["actions"]
        self.path_variables = {
            "HOME": str(Path.home()),
            **dict(path_variables or {}),
        }
        self.host_contract = dict(host_contract or {})
        protected_paths = [*policy["protected_paths"], *(self.host_contract.get("protected_paths") or [])]
        self.protected_paths = [
            {**item, "resolved": self._resolve_policy_path(item["path"])}
            for item in protected_paths
        ]
        self.capability_store = capability_store

    def _resolve_policy_path(self, raw_path: str) -> Path:
        resolved = raw_path
        for name, value in self.path_variables.items():
            resolved = resolved.replace(f"${{{name}}}", value)
        if "${" in resolved:
            raise ValueError(f"Unresolved policy path variable: {raw_path}")
        return Path(resolved).expanduser().resolve(strict=False)

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        capability_store: CapabilityStore | None = None,
        path_variables: dict[str, str] | None = None,
        host_contract: dict[str, Any] | None = None,
    ) -> "SafeYoloEngine":
        policy_path = Path(path).resolve()
        with policy_path.open(encoding="utf-8") as handle:
            variables = {
                "SAFE_YOLO_HOME": os.environ.get("SAFE_YOLO_HOME", str(policy_path.parent.parent)),
                "CODEX_HOME": os.environ.get("CODEX_HOME", str(Path.home() / ".codex")),
                "HOME": str(Path.home()),
                **(path_variables or {}),
            }
            return cls(json.load(handle), capability_store=capability_store, path_variables=variables, host_contract=host_contract)

    def evaluate(self, request: dict[str, Any]) -> dict[str, Any]:
        action = request.get("action", "")
        rule = self.actions.get(action)
        if rule is None:
            return result("block_method", "action.unknown", f"Unknown normalized action: {action}")

        classification = rule["classification"]
        capability_override = rule.get("capability_override", classification != "red")
        if classification == "red":
            return result(
                "block_hard",
                action,
                "Constitutional Red actions cannot be authorized inside an agent session.",
                classification="red",
                capability_override=False,
            )

        condition = rule.get("condition")
        if condition and self._condition_met(condition, request):
            promoted = rule.get("promote_to", classification)
            return result(
                DECISIONS[promoted],
                action,
                f"Policy condition '{condition}' is satisfied.",
                classification=promoted,
                capability_override=capability_override,
            )

        if condition and rule.get("condition_fallback_capability") and self._generic_capability_matches(action, request):
            return result(
                "allow_report",
                action,
                "A current, action-scoped capability authorizes the Amber fallback.",
                classification="blue",
                capability_override=True,
            )

        if condition and rule.get("condition_fallback_capability") is False:
            return result(
                "block_hard",
                action,
                f"The required condition '{condition}' is not satisfied and cannot be replaced by a capability.",
                classification="amber",
                capability_override=False,
            )

        if condition:
            return result(
                "require_capability",
                action,
                f"The required condition '{condition}' is not satisfied.",
                classification="amber",
                capability_override=capability_override,
            )

        if classification == "amber" and self._generic_capability_matches(action, request):
            return result(
                "allow_report",
                action,
                "A current, action-scoped capability authorizes this operation.",
                classification="blue",
                capability_override=True,
            )

        return result(
            DECISIONS[classification],
            action,
            f"Action is classified {classification}.",
            classification=classification,
            capability_override=capability_override,
        )

    def _condition_met(self, condition: str, request: dict[str, Any]) -> bool:
        if condition == "external_release_contract":
            contract = request.get("external_release_contract") or {}
            required = {
                "valid",
                "current",
                "repository_match",
                "commit_match",
                "artifact_match",
                "target_match",
                "rollback_verified",
                "gates_passed",
            }
            return bool(contract.get("issuer")) and all(contract.get(key) is True for key in required) and bool(contract.get("expires_at"))
        if condition == "task_aligned_record_write":
            return bool(
                request.get("task_aligned") is True
                and request.get("bulk") is False
                and request.get("administrative") is False
            )
        if condition == "maintenance_capability":
            capability = self._resolved_capability(request)
            targets = set(request.get("targets") or [])
            constraints = capability.get("constraints") if capability else {}
            scopes = set(constraints.get("scopes") or [])
            return bool(
                capability
                and capability.get("kind") == "maintenance"
                and constraints.get("harness") == request.get("harness")
                and targets
                and targets <= scopes
            )
        if condition == "policy_maintenance_capability":
            capability = self._resolved_capability(request)
            constraints = capability.get("constraints") if capability else {}
            policy_ids = set(request.get("policy_ids") or [])
            return bool(
                capability
                and capability.get("kind") == "policy_maintenance"
                and policy_ids
                and policy_ids <= set(constraints.get("policy_ids") or [])
            )
        return False

    def _generic_capability_matches(self, action: str, request: dict[str, Any]) -> bool:
        capability = self._resolved_capability(request)
        if not capability or capability.get("kind") != "action" or capability.get("action") != action:
            return False
        constraints = capability.get("constraints") or {}
        return all(request.get(key) == value for key, value in constraints.items())

    def _resolved_capability(self, request: dict[str, Any]) -> dict[str, Any] | None:
        if self.capability_store is None:
            return None
        token = request.get("capability_token")
        if token:
            return self.capability_store.resolve(token, request)
        return self.capability_store.resolve_active(request)

    def inspect_command(self, command: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context or {}
        try:
            tokens = self._tokens(command)
        except ValueError as error:
            if SECRET_RE.search(command):
                return result("block_hard", "credentials.expose", "Command embeds a credential-like value.")
            return result("block_method", "shell.unparseable", f"Command could not be safely parsed: {error}")

        if any(self._token_embeds_secret(token) for token in tokens):
            return result("block_hard", "credentials.expose", "Command embeds a credential-like value.")
        contains_dynamic_shell_expansion = self._contains_dynamic_shell_expansion(command)
        if re.search(r"\bcurl\b[^|]*(?:\||\|&)\s*(?:bash|sh|zsh|fish|python|python3|node|bun)\b", command):
            return result("block_hard", "network.remote_execution", "Remote content cannot be piped into an interpreter.")
        if re.search(r"(?:\||\|&)\s*(?:bash|sh|zsh|fish|python|python3|node|bun)\b", command):
            return result("block_method", "shell.piped_interpreter", "Piped interpreter input is not inspectable enough for Safe YOLO.")

        tracked_validation = self._inspect_tracked_validation(command, tokens)
        if tracked_validation is not None:
            return tracked_validation

        for segment in self._segments(tokens):
            inspected = self._inspect_segment(segment, context)
            if inspected["decision"] != "allow":
                return inspected
        if contains_dynamic_shell_expansion:
            return result("block_method", "shell.dynamic_execution", "Dynamic shell expansion is not inspectable enough for Safe YOLO.")
        return result("allow", "shell.ordinary", "No restricted consequence detected.")

    @staticmethod
    def _contains_dynamic_shell_expansion(command: str) -> bool:
        quote: str | None = None
        escaped = False
        index = 0
        while index < len(command):
            character = command[index]
            if escaped:
                escaped = False
                index += 1
                continue
            if character == "\\" and command[index + 1:index + 2] == "\n" and quote != "'":
                return True
            if character == "\\" and quote != "'":
                escaped = True
                index += 1
                continue
            if character == "'":
                quote = None if quote == "'" else "'" if quote is None else quote
                index += 1
                continue
            if character == '"':
                quote = None if quote == '"' else '"' if quote is None else quote
                index += 1
                continue
            if quote != "'" and character == "`":
                return True
            if quote != "'" and character == "$" and command[index + 1:index + 2] == "(":
                return True
            index += 1
        return False

    def _inspect_tracked_validation(self, command: str, tokens: list[str]) -> dict[str, Any] | None:
        if not tokens:
            return None
        executable = tokens[0]
        executable_name = Path(executable).name
        operations_root = self.host_contract.get("operations_root")
        canonical_executable = (
            TRACKED_VALIDATION_EXECUTABLE
            if operations_root == TRACKED_VALIDATION_OPERATIONS_ROOT
            else None
        )
        canonical_mentioned = bool(
            canonical_executable and any(canonical_executable in token for token in tokens)
        )
        has_shell_composition = any(
            token in {"|", "||", "|&", "&&", ";", "&", "(", ")", "<", ">", "<<", ">>", "<<<", "<&", ">&"}
            for token in tokens
        )
        wrapped_name = (
            executable_name in (TRACKED_VALIDATION_WRAPPERS | SHELLS)
            and any(
                Path(token).name == TRACKED_VALIDATION_NAME
                or bool(canonical_executable and canonical_executable in token)
                for token in tokens[1:]
            )
        )
        if executable != canonical_executable:
            unsafe_mention = (
                canonical_mentioned
                and (
                    executable_name not in TRACKED_VALIDATION_SAFE_MENTION_EXECUTABLES
                    or has_shell_composition
                )
            )
            if executable_name == TRACKED_VALIDATION_NAME or wrapped_name or unsafe_mention:
                return result(
                    "block_method",
                    "tracked_validation.invocation",
                    "Tracked validation requires the exact canonical executable with no wrapper.",
                )
            return None
        if len(tokens) != 4:
            return result(
                "block_method",
                "tracked_validation.arguments",
                "Tracked validation requires exactly repository, commit, and validation-path arguments.",
            )
        repository_id, commit_sha, validation_path = tokens[1:]
        if not (
            repository_id == TRACKED_VALIDATION_REPOSITORY
            and TRACKED_VALIDATION_SHA_RE.fullmatch(commit_sha)
            and validation_path == TRACKED_VALIDATION_PATH
            and TRACKED_VALIDATION_COMMAND_RE.fullmatch(command)
        ):
            return result(
                "block_method",
                "tracked_validation.arguments",
                "Tracked validation arguments do not match the reviewed literal grammar.",
            )
        return result(
            "allow_report",
            "tracked_validation.exact",
            "Exact canonical tracked-validation invocation is permitted; the runner enforces registry authorization.",
        )

    @staticmethod
    def _token_embeds_secret(token: str) -> bool:
        return any(
            SafeYoloEngine._component_embeds_secret(component)
            for component in token.split("/")
        )

    @staticmethod
    def _component_embeds_secret(component: str) -> bool:
        if component in BENIGN_CREDENTIAL_LIKE_PATH_COMPONENTS:
            return False
        prefix, separator, value = component.rpartition("=")
        if separator and value in BENIGN_CREDENTIAL_LIKE_PATH_COMPONENTS:
            return SECRET_RE.search(prefix) is not None
        return SECRET_RE.search(component) is not None

    def inspect_path_write(self, raw_path: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        context = context or {}
        rule = self._protected_rule(raw_path, context.get("cwd"))
        if rule is None:
            return result("allow", "filesystem.write", "Write target is not protected.")
        action = rule["action"]
        request = {"action": action, **context}
        if action == "harness.modify":
            request.update({"harness": rule["harness"], "targets": [rule["scope"]]})
        elif action == "harness.modify_policy":
            request.setdefault("policy_ids", context.get("policy_ids") or [])
        decision = self.evaluate(request)
        if decision["decision"] == "require_capability" and action == "harness.modify":
            return {
                **decision,
                "maintenance_request": {"harness": rule["harness"], "scopes": [rule["scope"]]},
            }
        return decision

    @staticmethod
    def _tokens(command: str) -> list[str]:
        lexer = shlex.shlex(SafeYoloEngine._normalize_newlines(command), posix=True, punctuation_chars="|&;()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)

    @staticmethod
    def _normalize_newlines(command: str) -> str:
        output: list[str] = []
        quote: str | None = None
        escaped = False
        for character in command:
            if escaped:
                output.append(character)
                escaped = False
                continue
            if character == "\\" and quote != "'":
                output.append(character)
                escaped = True
                continue
            if character in {"'", '"'}:
                if quote is None:
                    quote = character
                elif quote == character:
                    quote = None
                output.append(character)
                continue
            if character == "\n" and quote is None:
                output.append(" ; ")
            else:
                output.append(character)
        return "".join(output)

    @staticmethod
    def _segments(tokens: list[str]) -> list[list[str]]:
        separators = {"|", "||", "|&", "&&", ";", "(", ")"}
        segments: list[list[str]] = []
        current: list[str] = []
        for token in tokens:
            if token in separators:
                if current:
                    segments.append(current)
                    current = []
                continue
            current.append(token)
        if current:
            segments.append(current)
        return segments

    def _inspect_segment(self, tokens: list[str], context: dict[str, Any]) -> dict[str, Any]:
        if not tokens:
            return result("allow", "shell.empty", "Empty segment.")

        original_tokens = tokens
        original_index = 0
        while original_index < len(original_tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*", original_tokens[original_index]
        ):
            original_index += 1
        if (
            original_index < len(original_tokens)
            and Path(original_tokens[original_index]).name == "env"
        ):
            return self.evaluate({"action": "credentials.expose", **context})
        tokens = self._strip_env(tokens)
        if not tokens:
            if original_tokens and Path(original_tokens[0]).name == "env":
                return self.evaluate({"action": "credentials.expose", **context})
            return result("allow", "shell.environment", "Environment assignment only.")

        raw_executable = tokens[0]
        if any(character in raw_executable for character in "$*?[]{}"):
            return result(
                "block_method",
                "shell.dynamic_executable",
                "Dynamic executable names are not inspectable enough for Safe YOLO.",
            )
        executable = Path(raw_executable).name
        args = tokens[1:]

        if executable == "git":
            assigned_names = {
                token.split("=", 1)[0]
                for token in original_tokens
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token)
            }
            if assigned_names & DANGEROUS_GIT_ENVIRONMENT or any(
                name.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))
                for name in assigned_names
            ):
                return result(
                    "block_method",
                    "git.dynamic_configuration",
                    "Git execution-affecting environment configuration is not permitted.",
                )

        if executable == TRACKED_VALIDATION_NAME:
            return result(
                "block_method",
                "tracked_validation.invocation",
                "Tracked validation requires direct canonical invocation with no wrapper.",
            )

        redirect = self._protected_redirect(tokens, context)
        if redirect:
            return redirect

        if executable in SHELLS:
            wrapped = self._wrapped_command(args)
            if wrapped is not None:
                wrapped_result = self.inspect_command(wrapped, context)
                if wrapped_result.get("policy_id") == "tracked_validation.exact":
                    return result(
                        "block_method",
                        "tracked_validation.invocation",
                        "Tracked validation requires the exact canonical executable with no wrapper.",
                    )
                return wrapped_result
            if args and not (args[0] in {"-n", "--version", "--help", "-h"}):
                return result("block_hard", "shell.unclassified", "Untrusted shell script execution is not permitted.")

        if executable in {"command", "builtin", "exec"} and args:
            return self._inspect_segment(args, context)

        if executable in SYSTEM_RED_EXECUTABLES:
            return self.evaluate({"action": "system.modify", **context})

        if executable == "printenv":
            return self.evaluate({"action": "credentials.expose", **context})

        restricted = self.host_contract.get("restricted_executables") or {}
        if executable in restricted:
            return self.evaluate({"action": str(restricted[executable]), **context})

        if executable in REMOTE_EXECUTABLES:
            return self._inspect_remote(executable, args, context)

        if executable in {"rm", "rmdir", "unlink", "shred", "truncate"}:
            return result("block_hard", "filesystem.delete", "Permanent deletion is a constitutional Red action; use quarantine.")

        if executable == "xargs":
            if any(Path(arg).name in {"rm", "rmdir", "unlink", "shred"} for arg in args):
                return result("block_hard", "filesystem.delete", "xargs cannot invoke permanent deletion; use quarantine.")
            return result("block_method", "shell.dynamic_execution", "xargs command construction is not inspectable enough for Safe YOLO.")

        if executable in {"eval", "source", "."}:
            return result("block_method", "shell.dynamic_execution", "Dynamic shell evaluation is not inspectable enough for Safe YOLO.")

        if executable == "rg" and any(arg == "--pre" or arg.startswith("--pre=") for arg in args):
            return result("block_method", "shell.secondary_execution", "rg --pre command execution is not permitted.")

        if executable == "find" and any(arg in {"-delete", "-exec", "-execdir", "-ok", "-okdir"} for arg in args):
            return result("block_hard", "filesystem.delete", "Destructive find actions are Red; use a bounded reviewable method.")

        if executable in {"cp", "mv", "install", "tee"}:
            path_arguments = [arg for arg in args if not arg.startswith("-")]
            for index, arg in enumerate(args[:-1]):
                if arg in {"--target-directory", "-t"}:
                    path_arguments.append(args[index + 1])
                elif arg.startswith("--target-directory="):
                    path_arguments.append(arg.split("=", 1)[1])
            for path in path_arguments:
                path_result = self.inspect_path_write(path, context)
                if path_result["decision"] != "allow":
                    return path_result

        if executable in MULTICALL_EXECUTABLES:
            return result(
                "block_hard",
                "shell.unclassified_interpreter",
                "Multi-call executables can launch unreviewed secondary commands and are not permitted.",
            )

        if executable in OPAQUE_INTERPRETERS:
            read_only = (
                args[:1] in (["--version"], ["--help"], ["-h"])
                or executable in {"python", "python3"} and args[:2] == ["-m", "unittest"]
                or executable == "node" and args[:1] == ["--check"]
            )
            if not read_only:
                return result("block_hard", "shell.unclassified_interpreter", "Inline or script-backed interpreter execution is not permitted.")
        if executable == "bun":
            inline = self._inline_program(executable, args)
            if inline is not None and self._looks_mutating(inline):
                if self._mentions_protected_path(inline):
                    return result("block_method", "filesystem.opaque_protected_write", "Inline programs cannot mutate protected paths, even in Maintenance Mode.")
                return result("block_method", "filesystem.opaque_write", "Use a structured, reviewable editing method instead of inline mutation.")

        if executable in {"docker", "docker-compose"}:
            return self._inspect_docker(context)
        if self._is_workspace_launcher(tokens, args, context):
            return self._inspect_workspace_launcher(tokens[0], args, context)
        if tokens[0].startswith("./"):
            return result("block_method", "workspace.lifecycle", "Project launchers require a tracked repository contract.")
        if executable == "git":
            return self._inspect_git(args, context)
        if executable == "gh":
            return self._inspect_gh(args, context)
        if executable == "core-edge":
            if any(arg in {"delete", "remove", "purge"} for arg in args):
                return self.evaluate({"action": "records.delete", **context})
            return result("allow", "records.write", "Task-aligned Core operations are Green.")
        if executable in {"curl", "wget"}:
            return self._inspect_fetch(executable, args)
        if executable == "railway":
            return self._inspect_railway(args, context)
        if executable == "vercel":
            action = "deploy.production" if "--prod" in args or "--production" in args else "deploy.preview"
            return self.evaluate({"action": action, **context})
        if executable == "netlify" and args[:1] == ["deploy"]:
            action = "deploy.production" if "--prod" in args or "--production" in args else "deploy.preview"
            return self.evaluate({"action": action, **context})
        if executable in {"bunx", "npx"} or (executable == "bun" and args[:1] == ["x"]):
            package_args = args[1:] if executable == "bun" else args
            package = next((arg for arg in package_args if not arg.startswith("-")), "")
            if package and package not in set(context.get("local_bins") or []):
                return result("block_method", "package.remote_execution", f"Package binary is not installed locally: {package}")

        return result("allow", "shell.segment", "Segment is permitted.")

    @staticmethod
    def _inline_program(executable: str, args: list[str]) -> str | None:
        flags = {"-c"} if executable in {"python", "python3"} else {"-e", "--eval"}
        for index, arg in enumerate(args[:-1]):
            if arg in flags:
                return args[index + 1]
        return None

    @staticmethod
    def _looks_mutating(program: str) -> bool:
        patterns = (
            r"\bopen\s*\(",
            r"write_text\s*\(",
            r"write_bytes\s*\(",
            r"writeFile(?:Sync)?\s*\(",
            r"unlink(?:Sync)?\s*\(",
            r"rmtree\s*\(",
            r"remove\s*\(",
        )
        return any(re.search(pattern, program) for pattern in patterns)

    def _mentions_protected_path(self, program: str) -> bool:
        expanded = str(Path.home())
        normalized = program.replace("~", expanded)
        return any(str(item["resolved"]) in normalized for item in self.protected_paths)

    @staticmethod
    def _strip_env(tokens: list[str]) -> list[str]:
        index = 0
        if tokens and tokens[0] == "env":
            index = 1
        while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
            index += 1
        return tokens[index:]

    @staticmethod
    def _wrapped_command(args: list[str]) -> str | None:
        for index, arg in enumerate(args):
            if arg == "-c" or (arg.startswith("-") and "c" in arg[1:]):
                if index + 1 < len(args):
                    return args[index + 1]
        return None

    def _protected_redirect(self, tokens: list[str], context: dict[str, Any]) -> dict[str, Any] | None:
        for index, token in enumerate(tokens[:-1]):
            if token and set(token) <= {">"}:
                destination = tokens[index + 1]
                path_result = self.inspect_path_write(destination, context)
                if path_result["decision"] != "allow":
                    return path_result
        return None

    def _protected_rule(self, raw_path: str, cwd: str | None = None) -> dict[str, Any] | None:
        if raw_path.startswith("/dev/"):
            return None
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = (Path(cwd).expanduser() if cwd else Path.cwd()) / candidate
        candidate = candidate.resolve(strict=False)
        matches = [
            item
            for item in self.protected_paths
            if candidate == item["resolved"] or item["resolved"] in candidate.parents
        ]
        if not matches:
            return None
        return max(matches, key=lambda item: len(item["resolved"].parts))

    def _inspect_docker(self, context: dict[str, Any]) -> dict[str, Any]:
        operations_root = self.host_contract.get("operations_root")
        cwd = context.get("cwd")
        if not operations_root or not cwd:
            return result("block_method", "docker.workspace_contract", "Raw Docker requires an approved operations-workspace contract.")
        try:
            operations = Path(str(operations_root)).expanduser().resolve(strict=False)
            working = Path(str(cwd)).expanduser().resolve(strict=False)
        except OSError:
            return result("block_method", "docker.workspace_contract", "Docker workspace could not be resolved.")
        if working != operations and operations not in working.parents:
            return result("block_method", "docker.workspace_contract", "Raw Docker is reserved for the approved operations workspace.")
        return result("allow", "docker.operations_workspace", "Docker operation is within the approved operations workspace.")

    @staticmethod
    def _workspace_command_args(args: list[str]) -> tuple[str | None, list[str]]:
        repo = None
        remaining: list[str] = []
        index = 0
        while index < len(args):
            arg = args[index]
            if arg == "--repo" and index + 1 < len(args):
                repo = args[index + 1]
                index += 2
                continue
            if arg.startswith("--repo="):
                repo = arg.split("=", 1)[1]
                index += 1
                continue
            remaining.append(arg)
            index += 1
        return repo, remaining

    def _workspace_root(self) -> Path | None:
        workspaces_root = self.host_contract.get("workspaces_root")
        if not workspaces_root:
            return None
        try:
            return Path(str(workspaces_root)).expanduser().resolve(strict=False)
        except OSError:
            return None

    def _resolve_workspace_checkout(self, raw: str | None, cwd: str | None) -> Path | None:
        if not isinstance(raw, str) or not raw:
            return None
        try:
            candidate = Path(raw).expanduser()
            if not candidate.is_absolute():
                base = Path(cwd).expanduser() if isinstance(cwd, str) and cwd else Path.cwd()
                candidate = base / candidate
            return candidate.resolve(strict=False)
        except OSError:
            return None

    def _workspace_relative(self, checkout: Path) -> str | None:
        root = self._workspace_root()
        if root is None:
            return None
        try:
            return str(checkout.relative_to(root))
        except ValueError:
            return None

    def _is_workspace_launcher(self, tokens: list[str], args: list[str], context: dict[str, Any]) -> bool:
        if tokens[0] == "./workspace":
            return True
        if Path(tokens[0]).name != "workspace":
            return False
        repo_flag, command_args = self._workspace_command_args(args)
        checkout = self._resolve_workspace_checkout(repo_flag, context.get("cwd") if isinstance(context.get("cwd"), str) else None)
        if checkout is None:
            checkout = self._resolve_workspace_checkout(context.get("cwd") if isinstance(context.get("cwd"), str) else None, None)
        if checkout is None or self._workspace_relative(checkout) is None:
            return False
        return True

    def _inspect_workspace_launcher(self, executable: str, args: list[str], context: dict[str, Any]) -> dict[str, Any]:
        if self._workspace_root() is None:
            return result("block_method", "workspace.lifecycle", "Workspace launcher requires an approved host contract.")
        repo_flag, command_args = self._workspace_command_args(args)
        cwd_value = context.get("cwd") if isinstance(context.get("cwd"), str) else None
        cwd_checkout = self._resolve_workspace_checkout(cwd_value, None)
        repo_checkout = self._resolve_workspace_checkout(repo_flag, cwd_value)
        if executable.startswith("./"):
            if cwd_checkout is None or (repo_checkout is not None and repo_checkout != cwd_checkout):
                return result(
                    "block_method",
                    "workspace.untrusted_launcher",
                    "Relative workspace launcher must be verified in its actual working directory.",
                )
            checkout = cwd_checkout
        else:
            checkout = repo_checkout or cwd_checkout
        if checkout is None:
            return result(
                "block_method",
                "workspace.lifecycle",
                "Workspace launcher requires cwd or --repo under the approved workspace root.",
            )
        relative = self._workspace_relative(checkout)
        if relative is None:
            return result("block_method", "workspace.lifecycle", "Workspace launcher is outside the approved workspace root.")
        launcher = checkout / "workspace"
        if not launcher.is_file() or launcher.is_symlink():
            return result("block_method", "workspace.untrusted_launcher", "Workspace launcher must be a real tracked file.")
        lifecycle = command_args[0] if command_args else ""
        allowed_lifecycle = set(self.host_contract.get("workspace_lifecycle") or [])
        command_contracts = self.host_contract.get("workspace_commands") or []
        contract = next(
            (
                item
                for item in command_contracts
                if item.get("workspace") == relative and item.get("command") == command_args
            ),
            None,
        )
        if lifecycle not in allowed_lifecycle and contract is None:
            return result("block_method", "workspace.lifecycle", "Unknown workspace lifecycle command requires direct review.")
        checks = (
            ["git", "-C", str(checkout), "ls-files", "--error-unmatch", "workspace"],
            ["git", "-C", str(checkout), "diff", "--quiet", "--", "workspace"],
            ["git", "-C", str(checkout), "diff", "--cached", "--quiet", "--", "workspace"],
        )
        try:
            if any(subprocess.run(check, capture_output=True, check=False, timeout=2).returncode != 0 for check in checks):
                return result("block_method", "workspace.untrusted_launcher", "Workspace launcher must be tracked and unmodified.")
        except (OSError, subprocess.TimeoutExpired):
            return result("block_method", "workspace.unproven_launcher", "Workspace launcher could not be verified.")
        if contract is not None:
            return result("allow_report", str(contract["policy_id"]), str(contract["reason"]))
        return result("allow", "workspace.lifecycle", "Tracked workspace lifecycle command is permitted.")

    def _inspect_railway(self, args: list[str], context: dict[str, Any]) -> dict[str, Any]:
        flags_with_values = {"--project", "-p", "--environment", "-e", "--service", "-s", "--team", "--workspace"}
        index = 0
        while index < len(args):
            arg = args[index]
            if arg in flags_with_values:
                index += 2
                continue
            if any(arg.startswith(f"{flag}=") for flag in flags_with_values if flag.startswith("--")):
                index += 1
                continue
            if arg.startswith("-"):
                index += 1
                continue
            break
        command_args = args[index:]
        if command_args[:1] in (["up"], ["deploy"]):
            return self.evaluate({"action": "deploy.production", **context})
        if command_args[:1] in (["variable"], ["variables"]) or command_args[:2] == ["environment", "config"]:
            return self.evaluate({"action": "credentials.expose", **context})
        return result("allow", "railway.inspect", "Railway status/list inspection is permitted.")

    def _inspect_remote(self, executable: str, args: list[str], context: dict[str, Any]) -> dict[str, Any]:
        contract = self.host_contract.get("remote_maintenance") or {}
        if executable != "ssh" or not contract:
            return self.evaluate({"action": "remote.execute", **context})
        remaining = list(args)
        if remaining[:1] == ["-n"]:
            remaining = remaining[1:]
        if not remaining or remaining[0] != contract.get("host"):
            return self.evaluate({"action": "remote.execute", **context})
        remote_command = remaining[1:]
        allowed_commands = contract.get("commands") or []
        if remote_command in allowed_commands:
            return result("allow_report", "remote.safe_yolo_maintenance", "Exact verified Safe YOLO maintenance command for devbox is permitted.")
        return self.evaluate({"action": "remote.execute", **context})

    @staticmethod
    def _git_value(args: list[str], cwd: str) -> str | None:
        try:
            completed = subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True, check=False, timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return completed.stdout.strip() if completed.returncode == 0 else None

    def _push_branch(self, context: dict[str, Any]) -> str | None:
        cwd = context.get("cwd")
        if not isinstance(cwd, str) or not cwd:
            return None
        return self._git_value(["branch", "--show-current"], cwd)

    @staticmethod
    def _protected_push_target(positional: list[str]) -> str | None:
        # The first positional is the remote. Remaining values are refspecs.
        # A refspec without ':' updates a remote ref of the same name.
        for refspec in positional[1:]:
            destination = refspec.split(":", 1)[1] if ":" in refspec else refspec
            destination = destination.removeprefix("refs/heads/")
            if destination in PROTECTED_BRANCHES or destination.startswith("release/"):
                return destination
        return None

    def _inspect_git(self, args: list[str], context: dict[str, Any]) -> dict[str, Any]:
        filtered = list(args)
        git_context = dict(context)
        while filtered:
            option = filtered[0]
            if option == "-C" or option.startswith("-C"):
                if option == "-C":
                    if len(filtered) < 2:
                        return result("block_method", "git.context_missing", "Git -C requires an explicit working directory.")
                    raw_cwd = filtered[1]
                    filtered = filtered[2:]
                else:
                    raw_cwd = option[2:]
                    filtered = filtered[1:]
                    if not raw_cwd:
                        return result("block_method", "git.context_missing", "Git -C requires an explicit working directory.")
                effective_cwd = Path(raw_cwd).expanduser()
                if not effective_cwd.is_absolute():
                    base_cwd = git_context.get("cwd")
                    if not isinstance(base_cwd, str) or not base_cwd:
                        return result("block_method", "git.context_missing", "Relative Git -C requires a known working directory.")
                    effective_cwd = Path(base_cwd) / effective_cwd
                git_context["cwd"] = str(effective_cwd.resolve(strict=False))
                continue
            if option in {"--no-pager", "--paginate", "-P", "-p", "--literal-pathspecs", "--no-literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs"}:
                filtered = filtered[1:]
                continue
            if (
                option == "-c"
                or option.startswith("-c")
                or option.startswith("--config-env")
                or option.startswith("--exec-path")
                or option.startswith("--git-dir")
                or option.startswith("--work-tree")
                or option.startswith("--namespace")
                or option.startswith("--super-prefix")
            ):
                return result(
                    "block_method",
                    "git.dynamic_configuration",
                    "Git command or executable configuration is not permitted.",
                )
            break
        if not filtered:
            return result("allow", "git.inspect", "Git inspection is permitted.")
        subcommand = filtered[0]
        rest = filtered[1:]
        if subcommand in DESTRUCTIVE_GIT:
            return result("block_hard", f"git.{subcommand}", "Git work loss or history rewrite is Red.")
        if subcommand not in KNOWN_GIT_SUBCOMMANDS:
            return result(
                "block_method",
                "git.alias_execution",
                "Unknown Git subcommands and configured aliases are not permitted.",
            )
        if subcommand == "config":
            return self._inspect_git_config(rest)
        if subcommand == "checkout" and any(arg in {"--", "."} for arg in rest):
            return result("block_hard", "git.discard_work", "Checkout cannot discard working-tree changes.")
        if subcommand != "push":
            return result("allow", "git.ordinary", "Git operation is permitted.")
        if any(arg in FORCE_FLAGS or arg.startswith("--force=") for arg in rest):
            return result("block_hard", "git.force_push", "Force push is always Red.")
        if any(arg.startswith("+") for arg in rest):
            return result("block_hard", "git.force_push", "Forced refspecs are always Red.")
        if any(arg in {"--delete", "--mirror", "--all", "--tags", "--prune"} for arg in rest):
            return result("block_hard", "git.unsafe_push", "Broad or destructive push shape is blocked.")
        positional = [arg for arg in rest if not arg.startswith("-")]
        if any(arg.startswith(":") or arg.endswith(":") for arg in positional):
            return result("block_hard", "git.delete_ref", "Ref deletion is Red.")
        tag = next((arg for arg in positional if TAG_RE.fullmatch(arg) or "refs/tags/" in arg), None)
        if tag:
            return self.evaluate({"action": "git.push_tag", "target": tag.removeprefix("refs/tags/"), **git_context})
        protected_target = self._protected_push_target(positional)
        if protected_target:
            return self.evaluate({"action": "git.push_protected", "target": protected_target, **git_context})
        branch = self._push_branch(git_context)
        cwd = git_context.get("cwd")
        if isinstance(cwd, str) and cwd and branch is None:
            return result(
                "require_capability",
                "git.push_protected",
                "Current branch could not be determined for push classification.",
            )
        if branch and (branch in PROTECTED_BRANCHES or branch.startswith("release/")):
            return self.evaluate({"action": "git.push_protected", "target": branch, **git_context})
        return self.evaluate({"action": "git.push_feature", **git_context})

    @staticmethod
    def _inspect_git_config(args: list[str]) -> dict[str, Any]:
        write_flags = {
            "--add",
            "--edit",
            "-e",
            "--remove-section",
            "--rename-section",
            "--replace-all",
            "--unset",
            "--unset-all",
        }
        if any(arg in write_flags for arg in args):
            return result("block_method", "git.config_write", "Git configuration writes are not permitted.")
        positional = [arg for arg in args if not arg.startswith("-")]
        read_operations = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l"}
        if any(arg in read_operations for arg in args):
            return result("allow", "git.config_read", "Git configuration inspection is permitted.")
        if len(positional) <= 1:
            return result("allow", "git.config_read", "Git configuration inspection is permitted.")
        return result("block_method", "git.config_write", "Git configuration writes are not permitted.")

    def _inspect_gh(self, args: list[str], context: dict[str, Any]) -> dict[str, Any]:
        if args[:2] == ["pr", "create"]:
            return self.evaluate({"action": "github.pr_create"})
        if args[:2] == ["pr", "merge"]:
            target = args[2] if len(args) >= 3 and args[2].isdigit() else ""
            repository = self._flag_value(args, "--repo")
            method = next((flag.removeprefix("--") for flag in ("--squash", "--merge", "--rebase") if flag in args), "")
            return self.evaluate(
                {
                    "action": "github.pr_merge",
                    "repository": repository,
                    "target": target,
                    "method": method,
                    **context,
                }
            )
        if args[:2] in (["repo", "delete"], ["release", "delete"]):
            return result("block_hard", "github.destructive_admin", "Destructive GitHub administration is Red.")
        if args[:1] == ["api"]:
            method = "GET"
            for index, arg in enumerate(args[:-1]):
                if arg in {"-X", "--method"}:
                    method = args[index + 1].upper()
            if method not in {"GET", "HEAD", "OPTIONS"} or any(arg in {"-f", "-F", "--field", "--raw-field"} for arg in args):
                return result("require_capability", "github.api_write", "GitHub API mutation requires an exact capability.")
        return result("allow", "github.ordinary", "GitHub operation is permitted by this slice.")

    @staticmethod
    def _flag_value(args: list[str], flag: str) -> str:
        try:
            index = args.index(flag)
        except ValueError:
            return ""
        return args[index + 1] if index + 1 < len(args) else ""

    def _inspect_fetch(self, executable: str, args: list[str]) -> dict[str, Any]:
        if any("$" in arg or "`" in arg for arg in args):
            return result("block_method", "network.dynamic_url", "Dynamic shell-built network targets are not Green.")
        if any(arg in {"-L", "--location", "--location-trusted"} for arg in args):
            return result("block_method", "network.redirect", "Use the safe fetch wrapper for validated redirects.")
        file_backed_prefixes = ("--data=@", "--data-binary=@", "--data-raw=@", "--data-urlencode=@", "--post-file=", "--body-file=", "--upload-file=")
        if any(arg.startswith(file_backed_prefixes) for arg in args):
            return result("block_hard", "network.exfiltration", "Transmitting local file contents is Red.")
        for index, arg in enumerate(args):
            if arg in {"-F", "--form"} and index + 1 < len(args) and "@" in args[index + 1]:
                return result("block_hard", "network.exfiltration", "Transmitting local file contents is Red.")
            if arg in {"-T", "--upload-file"} and index + 1 < len(args):
                return result("block_hard", "network.exfiltration", "Uploading local file contents is Red.")
            if arg in NETWORK_WRITE_FLAGS and index + 1 < len(args) and args[index + 1].startswith("@"):
                return result("block_hard", "network.exfiltration", "Transmitting local file contents is Red.")
        if any(arg in NETWORK_WRITE_FLAGS for arg in args):
            return result("require_capability", "network.write", "Request bodies and uploads require a scoped capability.")
        if any(arg in AUTH_FLAGS for arg in args):
            return result("require_capability", "network.authenticated_read", "Authenticated network reads require a scoped capability.")
        if any(arg in {"--config", "-K", "--unix-socket"} for arg in args):
            return result("block_method", "network.indirect_configuration", "Indirect network configuration is not inspectable enough for Green.")
        if "-H" in args or "--header" in args:
            joined = " ".join(args).lower()
            if any(name in joined for name in ("authorization:", "cookie:", "x-api-key", "api-key", "token:")):
                return result("require_capability", "network.authenticated_read", "Credential-bearing headers require a scoped capability.")
        method = "GET"
        for index, arg in enumerate(args[:-1]):
            if arg in {"-X", "--request"}:
                method = args[index + 1].upper()
        if method not in {"GET", "HEAD", "OPTIONS"}:
            return result("require_capability", "network.write", f"HTTP {method} requires a scoped capability.")
        urls = [arg for arg in args if arg.startswith(("http://", "https://"))]
        if not urls:
            return result("block_method", "network.target_missing", f"{executable} target is not a literal public HTTP(S) URL.")
        for url in urls:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if host in METADATA_HOSTS:
                return result("block_hard", "network.metadata", "Cloud metadata endpoints are Red.")
            if host in LOOPBACK_HOSTS:
                registered = {int(port) for port in (self.host_contract.get("workspace_loopback_ports") or [])}
                port = parsed.port
                if port is None:
                    port = 443 if parsed.scheme == "https" else 80
                if port in registered:
                    return result("allow", "network.workspace_loopback", "Loopback read of a registered workspace port is permitted.")
            if host in PRIVATE_HOSTS or host.startswith("10.") or host.startswith("192.168.") or host.startswith("172.16."):
                return result("require_capability", "network.private_read", "Private or local network access requires a scoped capability.")
        return result("allow", "network.public_read", "Literal credential-free public read is Green.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate a normalized Safe YOLO request.")
    parser.add_argument("--policy", type=Path, default=Path(__file__).resolve().parents[1] / "policy.json")
    parser.add_argument("--command", help="Inspect a shell command instead of a normalized request.")
    args = parser.parse_args()
    engine = SafeYoloEngine.from_file(args.policy)
    if args.command is not None:
        response = engine.inspect_command(args.command)
    else:
        response = engine.evaluate(json.load(sys.stdin))
    json.dump(response, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
