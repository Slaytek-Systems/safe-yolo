from __future__ import annotations

from dataclasses import dataclass


_OPTIONS_WITH_VALUES = {
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
    "-Q",
    "-R",
    "-S",
    "-W",
    "-w",
}
_ATTACHED_VALUE_OPTIONS = tuple(sorted(_OPTIONS_WITH_VALUES, key=len, reverse=True))
_ROUTE_FLAGS = {"-F", "-J", "-l", "-p"}
_LOCAL_COMMAND_OPTIONS = {"localcommand", "proxycommand", "knownhostscommand"}
_ROUTE_OPTIONS = {"hostname", "proxyjump", "proxycommand"}


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

        flag, value, consumed = _option_value(args, index)
        if flag is not None:
            if value is None:
                malformed = True
                break
            if flag == "-i":
                identity_files.append(value)
            elif flag == "-F":
                opaque_config = True
            elif flag == "-W":
                transport_only = True
            elif flag == "-O":
                transport_only = True
            elif flag == "-Q":
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
                if name in _ROUTE_OPTIONS:
                    route_overridden = True
            if flag in _ROUTE_FLAGS:
                route_overridden = True
            index += consumed
            continue

        short_flags = token[1:]
        if "N" in short_flags or "G" in short_flags or "V" in short_flags:
            transport_only = True
        if "s" in short_flags:
            subsystem = True
        index += 1

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


def _option_value(args: list[str], index: int) -> tuple[str | None, str | None, int]:
    token = args[index]
    if token in _OPTIONS_WITH_VALUES:
        if index + 1 >= len(args):
            return token, None, 1
        return token, args[index + 1], 2
    for flag in _ATTACHED_VALUE_OPTIONS:
        if token.startswith(flag) and len(token) > len(flag):
            return flag, token[len(flag) :].removeprefix("="), 1
    return None, None, 1


def _config_option(option: str) -> tuple[str, str]:
    normalized = option.strip()
    if "=" in normalized:
        name, value = normalized.split("=", 1)
    elif " " in normalized:
        name, value = normalized.split(None, 1)
    else:
        name, value = normalized, ""
    return name.lower(), value
