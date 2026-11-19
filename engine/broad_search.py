"""Recognize a recursive search that names a whole storage root.

Only what the command text settles on its own is recognized: `grep -r`, `rg`
or `find` at the head of a simple command, with one of its own path words an
absolute, `~` or `$HOME` path that is exactly a listed root. The reader does
not know the working folder, follow `cd`, unwrap `sudo` or `bash -c`, or read
any other variable. Where it is not certain it reports nothing, because this
runs before every shell call and a wrong refusal costs more than a miss.
"""
from __future__ import annotations

import os
import re
from typing import Any, NamedTuple

# Exact folders only: `~/.cache` is a root, `~/.cache/pip` is not.
SYSTEM_ROOTS = ("/", "/home", "/Users", "/tmp", "/var", "/var/tmp")
HOME_ROOTS = (
    ".local", ".local/state", ".local/share", ".cache",
    # The harness folders of scripts/harness_specs.py.
    ".codex", ".claude", ".cursor", ".grok", ".config/opencode", ".gemini", ".devin",
)
# `find` reads names, not contents, so only the trees that hold everything count.
WALK_ROOTS = ("/", "/home", "/Users")
MAX_FIND_DEPTH = 3
MAX_SCRIPT = 65536  # a longer command is allowed unread


def _options(plain: str, valued: str) -> dict[str, bool]:
    """Option name -> whether its value is a separate word. A missing option is unknown."""
    return {**dict.fromkeys(plain.split(), False), **dict.fromkeys(valued.split(), True)}


# From `grep --help` (GNU grep 3.11) and `rg -h` (ripgrep 14.1). An option that
# is not here makes the command unread, so it is allowed. Left out on purpose:
# --help, --version and -V, rg --files and --type-list, which do not search;
# rg -d and --max-depth, which may stop the descent; -NUM; and shortened long
# options. --color takes a value only after `=`, so it is plain.
_GREP = _options(
    "E F G P i w x s v b n H h o q a I r R L l c T U extended-regexp fixed-strings basic-regexp perl-regexp "
    "ignore-case no-ignore-case word-regexp line-regexp no-messages invert-match byte-offset line-number "
    "line-buffered with-filename no-filename only-matching quiet silent text recursive dereference-recursive "
    "files-without-match files-with-matches count initial-tab binary no-group-separator color colour",
    "e f m d D A B C regexp file max-count label binary-files directories devices include exclude exclude-from "
    "exclude-dir before-context after-context context group-separator")
_RG = _options(
    "z s F i v x U P S a w L . u b n N 0 o p q H I c l search-zip case-sensitive fixed-strings ignore-case "
    "invert-match line-regexp multiline pcre2 smart-case text word-regexp follow hidden no-ignore no-ignore-vcs "
    "unrestricted byte-offset column heading no-heading line-number no-line-number null only-matching pretty quiet "
    "trim vimgrep with-filename no-filename count count-matches files-with-matches files-without-match json "
    "no-messages stats no-config",
    "e f E m j g t T A B C M r regexp file encoding max-count threads glob iglob type type-not after-context "
    "before-context context max-columns replace sort sortr color colors")
# From `find --help` (GNU findutils 4.9). Left out on purpose: --help and
# --version, which do not search, and -exec, -ok and their kin, -newerXY and
# -fprintf, whose following words this table cannot count.
_FIND = _options(
    "-a -o -and -or -not -daystart -depth -mount -xdev -noleaf -ignore_readdir_race -noignore_readdir_race -empty "
    "-false -true -nouser -nogroup -readable -writable -executable -print -print0 -ls -prune -quit -follow",
    "-maxdepth -mindepth -amin -anewer -atime -cmin -cnewer -ctime -mmin -mtime -newer -fstype -gid -group "
    "-ilname -iname -inum -ipath -iregex -iwholename -links -lname -name -path -perm -regex -regextype -samefile "
    "-size -type -uid -used -user -wholename -xtype -printf -fprint -fprint0 -fls")
_TOOL_FOLDERS = ("", "/bin", "/usr/bin", "/usr/local/bin")
_PATTERN_OPTIONS = {"e", "f", "regexp", "file"}
_GREP_RECURSIVE = {"r", "R", "recursive", "dereference-recursive"}
_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "time", "{"}
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_HOME_VARIABLE = re.compile(r"\$(?:HOME(?![A-Za-z0-9_])|\{HOME\})")
# The name HOME other than as $HOME or ${HOME}: an assignment, export, unset or read may give it another value.
_HOME_NAMED = re.compile(r"(?<![$A-Za-z0-9_{])HOME(?![A-Za-z0-9_])")
# A home holding one of these is split or globbed by the shell when $HOME is not quoted.
_SPLITS_OR_GLOBS = re.compile(r"[\s*?\[]")


class Hit(NamedTuple):
    tool: str
    root: str


def _simple_commands(script: str, home: str) -> list[list[str]]:
    """The word lists of the simple commands that can be read with certainty.

    Each word is the literal text the shell would pass. A command that holds a
    variable other than $HOME or a substitution is dropped, because one of its
    words is unknown. Where the script names HOME itself, $HOME is unknown too
    and `~` stays as written. An unquoted $HOME is also unknown when the home
    holds whitespace or a glob character. Reading stops at the first heredoc, backtick,
    unclosed quote, substitution inside double quotes or bracket that is not
    plainly a subshell, so nothing after it is judged.
    """
    commands: list[list[str]] = []
    words: list[str] = []
    word: list[str] | None = None
    unknown = redirect = False  # the command has an unreadable word; the next word is a redirect target
    home_known = not _HOME_NAMED.search(script)
    bare_home_known = home_known and not _SPLITS_OR_GLOBS.search(home)
    i, size = 0, len(script)

    def add(text: str) -> None:
        nonlocal word
        if word is None:
            word = []
        word.append(text)

    def end_word() -> None:
        nonlocal word, redirect
        if word is not None:
            if not redirect:
                words.append("".join(word))
            redirect = False
        word = None

    def end_command(keep: bool = True) -> None:
        nonlocal words, unknown, redirect
        end_word()
        if keep and words and not unknown:
            commands.append(words)
        words, unknown, redirect = [], False, False

    while i < size:
        ch = script[i]
        if ch == "\\":
            if script[i + 1:i + 2] != "\n":
                add(script[i + 1:i + 2])
            i += 2
        elif ch == "'":
            end = script.find("'", i + 1)
            if end < 0:
                return commands
            add(script[i + 1:end])
            i = end + 1
        elif ch == '"':
            add("")
            i += 1
            while script[i:i + 1] != '"':
                if i >= size or script[i] == "`" or script.startswith("$(", i):
                    return commands
                variable = home_known and _HOME_VARIABLE.match(script, i)
                if variable:
                    add(home)
                    i = variable.end()
                elif script[i] == "\\" and script[i + 1:i + 2] in ("$", "`", '"', "\\", "\n"):
                    add(script[i + 1:i + 2].strip("\n"))
                    i += 2
                else:
                    unknown = unknown or script[i] == "$"
                    add(script[i])
                    i += 1
            i += 1
        elif ch == "`":
            return commands
        elif script.startswith(("$(", "<(", ">("), i):
            end_command(keep=False)  # the command around the brackets has a word of unknown value
            i += 2
        elif ch == "(":
            if word is not None or words:
                return commands  # an array, a function or a test pattern, not a subshell
            i += 1
        elif ch == ")":
            end_command()
            unknown = True  # what follows belongs to the command around the brackets
            i += 1
        elif ch in ";\n|" or (ch == "&" and script[i + 1:i + 2] != ">"):
            end_command()
            i += 1
        elif ch in "<>&":
            if word is not None and "".join(word).isdigit():
                word = None  # the descriptor number in `2>file`
            end_word()
            start = i
            while script[i:i + 1] in ("<", ">", "&", "|") or script.startswith("\\\n", i):
                i += 2 if script[i] == "\\" else 1
            operator = script[start:i].replace("\\\n", "")  # a line continuation can split `<<`
            if "<<" in operator and "<<<" not in operator:
                return commands  # a heredoc: its body is data
            redirect = True
        elif ch in " \t":
            end_word()
            i += 1
        elif ch == "#" and word is None:
            newline = script.find("\n", i)
            i = size if newline < 0 else newline
        elif ch == "$":
            variable = bare_home_known and _HOME_VARIABLE.match(script, i)
            unknown = unknown or not variable
            add(home if variable else ch)
            i = variable.end() if variable else i + 1
        elif (ch == "~" and home_known and word is None
              and script[i + 1:i + 2] in ("", "/", " ", "\t", "\n", ";", "|", "&", ")")):
            add(home)
            i += 1
        else:
            add(ch)
            i += 1
    end_command()
    return commands


def _parse(args: list[str], table: dict[str, bool]) -> tuple[dict[str, list[str]], list[str]] | None:
    """(option values by name, the other words), or None when an option is not in the table."""
    found: dict[str, list[str]] = {}
    rest: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--":
            rest += args[i:]
            break
        if arg.startswith("--"):
            name, equals, value = arg[2:].partition("=")
            names = [name]
        elif arg.startswith("-") and len(arg) > 1:
            cut = next((n for n, flag in enumerate(arg[1:], 1) if table.get(flag)), len(arg) - 1)
            names, equals, value = list(arg[1:cut + 1]), arg[cut + 1:], arg[cut + 1:]
        else:
            rest.append(arg)
            continue
        if any(name not in table for name in names):
            return None
        if table[names[-1]] and not equals:
            if i == len(args):
                return None
            value = args[i]
            i += 1
        for name in names:
            found.setdefault(name, []).append(value if name == names[-1] else "")
    return found, rest


def _search_paths(tool: str, args: list[str]) -> list[str]:
    """The words a recursive grep or rg would search, or none when that is not certain."""
    parsed = _parse(args, _RG if tool == "rg" else _GREP)
    if not parsed:
        return []
    found, rest = parsed
    if tool != "rg":
        directories = found.get("d", []) + found.get("directories", [])
        if any(action != "recurse" for action in directories) or not (directories or found.keys() & _GREP_RECURSIVE):
            return []
    return rest if found.keys() & _PATTERN_OPTIONS else rest[1:]


def _find_paths(args: list[str]) -> list[str]:
    """The words a deep find would walk: the ones before its first option or operator.

    None of them when a later `-word` is not in the table, a depth is not a
    short ASCII number, a shallow -maxdepth is given, or the expression opens
    with `-prune`, alone or after one shallow -mindepth. That -prune is tested
    on every file from -mindepth down, so the walk stops there, unless -depth
    turns -prune off.
    """
    start = next((n for n, arg in enumerate(args) if arg.startswith(("-", "(", "!", ","))), len(args))
    expression = args[start:]
    pruned = expression[2 if expression[:1] == ["-mindepth"] else 0:][:1] == ["-prune"]
    rest = iter(expression)
    for arg in rest:
        if arg.startswith("-"):
            if arg not in _FIND:
                return []
            value = next(rest, "") if _FIND[arg] else ""
            if arg in ("-maxdepth", "-mindepth"):
                if not (value.isascii() and value.isdigit() and len(value) <= 9):
                    return []
                shallow = int(value) <= MAX_FIND_DEPTH
                if arg == "-maxdepth" and shallow:
                    return []
                pruned = pruned and (arg == "-maxdepth" or shallow)
            pruned = pruned and arg != "-depth"
    return [] if pruned else args[:start]


def _normal(path: str) -> str | None:
    """The one spelling of an absolute path that roots and path words are compared in."""
    return "/" + os.path.normpath(path).lstrip("/") if path.startswith("/") else None


def _root_named(words: list[str], roots: set[str | None]) -> str | None:
    for word in words:
        path = _normal(word)
        if path and path in roots:
            return path
    return None


def _roots(home: str) -> set[str | None]:
    return {*SYSTEM_ROOTS, *(_normal(f"{home}/{name}") for name in ("", *HOME_ROOTS))}


def _classify(script: str, home: str) -> Hit | None:
    """The first command in a shell script that names a whole root to search."""
    if len(script) > MAX_SCRIPT or "POSIXLY_CORRECT" in script:  # POSIXLY_CORRECT changes how options are read
        return None
    walk_roots = {*WALK_ROOTS, _normal(home)}
    for words in _simple_commands(script, home):
        start = next((n for n, word in enumerate(words) if word not in _KEYWORDS and not _ASSIGNMENT.match(word)),
                     len(words))
        if start == len(words):
            continue
        head, args = words[start], words[start + 1:]
        folder, tool = os.path.split(head)
        if folder not in _TOOL_FOLDERS:
            continue  # some other program that shares the name
        if tool in ("grep", "egrep", "fgrep", "rg"):
            root = _root_named(_search_paths(tool, args), _roots(home))
        elif tool == "find":
            root = _root_named(_find_paths(args), walk_roots)
        else:
            continue
        if root:
            return Hit(tool, root)
    return None


def inspect(payload: dict[str, Any], home: str) -> Hit | None:
    """The whole-root search one tool call names: a shell command, or a native grep tool's `path`."""
    tool_name = str(payload.get("tool_name") or "").lower()
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    if tool_name in {"bash", "shell", "exec_command"}:
        command = tool_input.get("command") or tool_input.get("cmd")
        return _classify(command, home) if isinstance(command, str) else None
    if tool_name == "grep" and isinstance(tool_input.get("path"), str):
        root = _root_named([tool_input["path"]], _roots(home))
        return Hit("grep tool", root) if root else None
    return None
