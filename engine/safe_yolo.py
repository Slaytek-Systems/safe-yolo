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

SHELLS = {"bash", "sh", "zsh", "fish"}
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
        if self._has_remote_response_pipeline(tokens):
            return result(
                "block_hard",
                "network.remote_pipeline",
                "Fetch remote content to a file and inspect it before passing it to another command.",
            )

        for segment in self._segments(tokens):
            inspected = self._inspect_segment(segment, context)
            if inspected["decision"] != "allow":
                return inspected
        return result("allow", "shell.ordinary", "No restricted consequence detected.")

    @staticmethod
    def _has_remote_response_pipeline(tokens: list[str]) -> bool:
        current: list[str] = []
        for token in tokens:
            if token in {"|", "|&"}:
                segment = SafeYoloEngine._strip_env(current)
                while segment and Path(segment[0]).name in {"command", "builtin", "exec", "time"}:
                    segment = SafeYoloEngine._strip_env(segment[1:])
                if segment and Path(segment[0]).name in {"curl", "wget"}:
                    return True
                current = []
            elif token in {"||", "&&", ";", "(", ")", "<(", ">("}:
                current = []
            else:
                current.append(token)
        return False

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
        separators = {"|", "||", "|&", "&&", ";", "(", ")", "<(", ">("}
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
        tokens = self._strip_env(tokens)
        if not tokens:
            if original_tokens and Path(original_tokens[0]).name == "env":
                return self.evaluate({"action": "credentials.expose", **context})
            return result("allow", "shell.environment", "Environment assignment only.")

        executable = Path(tokens[0]).name
        args = tokens[1:]

        redirect = self._protected_redirect(tokens, context)
        if redirect:
            return redirect

        if executable in SHELLS:
            wrapped = self._wrapped_command(args)
            if wrapped is not None:
                return self.inspect_command(wrapped, context)

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

        if executable == "xargs" and any(Path(arg).name in {"rm", "rmdir", "unlink", "shred"} for arg in args):
            return result("block_hard", "filesystem.delete", "xargs cannot invoke permanent deletion; use quarantine.")

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

        if executable in {"docker", "docker-compose"}:
            return self._inspect_docker(context)
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
        while filtered and (filtered[0] == "-C" or filtered[0].startswith("-C")):
            if filtered[0] == "-C":
                if len(filtered) < 2:
                    return result("block_method", "git.context_missing", "Git -C requires an explicit working directory.")
                raw_cwd = filtered[1]
                filtered = filtered[2:]
            else:
                raw_cwd = filtered[0][2:]
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
        if not filtered:
            return result("allow", "git.inspect", "Git inspection is permitted.")
        subcommand = filtered[0]
        rest = filtered[1:]
        if subcommand in DESTRUCTIVE_GIT:
            return result("block_hard", f"git.{subcommand}", "Git work loss or history rewrite is Red.")
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
