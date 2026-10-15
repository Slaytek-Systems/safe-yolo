from __future__ import annotations

from dataclasses import dataclass


# Value-taking letters from `ssh` usage. ssh reads options with getopt, so a
# cluster such as -tp2222 or -tp 2222 ends at the first value-taking letter.
_VALUE_LETTERS = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
_ROUTE_FLAGS = {"-F", "-J", "-S", "-l", "-p"}
_LOCAL_COMMAND_OPTIONS = {"localcommand", "proxycommand", "knownhostscommand"}
_ROUTE_OPTIONS = {
    "canonicaldomains",
    "canonicalizehostname",
    "controlpath",
    "hostname",
    "include",
    "port",
    "proxycommand",
    "proxyjump",
    "user",
}


@dataclass(frozen=True)
class SshInvocation:
    host: str | None
    remote_tokens: tuple[str, ...]
    remote_commands: tuple[str, ...]
    local_commands: tuple[str, ...]
    identity_files: tuple[str, ...]
    transport_only: bool
    opaque_config: bool
    route_overridden: bool
    subsystem: bool
    malformed: bool

    @property
    def interactive(self) -> bool:
        return bool(
            self.host
            and not self.remote_commands
            and not self.transport_only
            and not self.subsystem
        )


def parse_ssh_invocation(args: list[str]) -> SshInvocation:
    host: str | None = None
    remote_tokens: tuple[str, ...] = ()
    remote_commands: list[str] = []
    local_commands: list[str] = []
    identity_files: list[str] = []
    transport_only = False
    opaque_config = False
    route_overridden = False
    subsystem = False
    malformed = False

    index = 0
    while index < len(args):
        token = args[index]
        if token == "--":
            rest = args[index + 1 :]
            if rest:
                host = rest[0]
                remote_tokens = tuple(rest[1:])
            else:
                malformed = True
            break
        if not token.startswith("-") or token == "-":
            host = token
            remote_tokens = tuple(args[index + 1 :])
            break

        index += 1
        for position, letter in enumerate(token[1:], start=2):
            if letter not in _VALUE_LETTERS:
                if letter in "NGV":
                    transport_only = True
                elif letter == "s":
                    subsystem = True
                continue
            flag = "-" + letter
            if position < len(token):
                value = token[position:].removeprefix("=")
            elif index < len(args):
                value = args[index]
                index += 1
            else:
                value = None
                malformed = True
                break
            if flag == "-i":
                identity_files.append(value)
            elif flag == "-F":
                opaque_config = True
            elif flag in {"-W", "-O", "-Q"}:
                transport_only = True
            elif flag == "-o":
                name, option_value = _config_option(value)
                if name == "identityfile" and option_value:
                    identity_files.append(option_value)
                command_value = option_value if option_value.lower() != "none" else ""
                if name in _LOCAL_COMMAND_OPTIONS and command_value:
                    local_commands.append(command_value)
                if name == "remotecommand" and command_value:
                    remote_commands.append(command_value)
                if name == "sessiontype" and option_value.lower() == "none":
                    transport_only = True
                if name == "include":
                    opaque_config = True
                if name in _ROUTE_OPTIONS:
                    route_overridden = True
            if flag in _ROUTE_FLAGS:
                route_overridden = True
            break
        if malformed:
            break

    if remote_tokens and remote_tokens[0] in {"|", "||", "|&", "&&", ";"}:
        remote_tokens = ()
    if remote_tokens:
        remote_commands.append(" ".join(remote_tokens))

    return SshInvocation(
        host=host,
        remote_tokens=remote_tokens,
        remote_commands=tuple(remote_commands),
        local_commands=tuple(local_commands),
        identity_files=tuple(identity_files),
        transport_only=transport_only,
        opaque_config=opaque_config,
        route_overridden=route_overridden,
        subsystem=subsystem,
        malformed=malformed or host is None,
    )


def _config_option(option: str) -> tuple[str, str]:
    normalized = option.strip()
    if "=" in normalized:
        name, value = normalized.split("=", 1)
    elif " " in normalized:
        name, value = normalized.split(None, 1)
    else:
        name, value = normalized, ""
    return name.lower(), value
