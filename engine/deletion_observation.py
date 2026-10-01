"""Bounded, private deletion observations; never an enforcement input."""

from __future__ import annotations

from contextlib import closing
from datetime import UTC, datetime
from functools import lru_cache
import hashlib
import hmac
import os
from pathlib import Path
import re
import shlex
import sqlite3
import stat
import sys
from typing import Any


SCHEMA_VERSION = 1
MAX_EVENTS = 10_000
MAX_BYTES = 16 * 1024 * 1024
LOCK_TIMEOUT = 0.05
DIAGNOSTIC = "Safe YOLO observation unavailable\n"
HARNESS_NAMES = {"codex", "claude-code", "cursor", "devin", "grok", "opencode", "antigravity"}
DELETE_COMMANDS = {"rm", "rmdir", "unlink", "shred", "truncate"}
POLICIES = {
    "filesystem.delete", "git.delete_ref", "git.history_mutation", "production.mutate",
    "remote.execute", "privilege.modify", "network.public_exposure", "credentials.access",
    "enforcement.modify", "interactive.process_write",
}
PATH_NAMES = ("path", "file_path", "target_file")
ROOT = Path(__file__).resolve().parents[1]


def _path_shape(value: str) -> str:
    if any(marker in value for marker in ("$", "`")):
        return "<dynamic>"
    if any(marker in value for marker in ("*", "?", "[")):
        return "<glob>"
    if value.startswith("/"):
        return "<absolute>"
    if value.startswith("~"):
        return "<home>"
    return "<relative>"


def _targets(values: list[str]) -> str:
    shapes = [_path_shape(value) for value in values[:2]]
    if len(values) > 2:
        shapes.append("<many>")
    return " ".join(shapes) or "<no-target>"


def _direct_shape(executable: str, args: list[str]) -> str:
    flags: set[str] = set()
    targets: list[str] = []
    positional = False
    skip_value = False
    long_flags = {"--force": "f", "--recursive": "r", "--dir": "d", "--verbose": "v"}
    value_flags = {"-s", "--size", "--reference", "-n", "--iterations", "-o", "--output"}
    for token in args:
        if skip_value:
            skip_value = False
            continue
        if token == "--" and not positional:
            positional = True
        elif not positional and token.startswith("-"):
            name = token.split("=", 1)[0]
            if executable in {"shred", "truncate"} and name in value_flags:
                flags.add("<value-option>")
                skip_value = "=" not in token
            elif token in long_flags:
                flags.add("-" + long_flags[token])
            elif token.startswith("--"):
                flags.add("<option>")
            elif len(token) > 1 and set(token[1:]) <= set("frdiIv"):
                flags.update("-" + char for char in token[1:])
            else:
                flags.add("<option>")
        else:
            targets.append(token)
    return " ".join([executable, *sorted(flags), _targets(targets)])


def candidate(payload: dict[str, Any], decision: Any) -> tuple[str, str] | None:
    """Return a fixed-vocabulary shape and parsing coverage, not a new policy."""
    tool = str(payload.get("tool_name") or "").lower()
    values = payload.get("tool_input")
    if not isinstance(values, dict):
        values = {}
    if tool in {"delete_file", "remove_file"}:
        targets = [values[name] for name in PATH_NAMES if isinstance(values.get(name), str)]
        return ("delete_file " + _targets(targets), "complete")
    if tool == "apply_patch":
        patch = values.get("patch") or values.get("command") or ""
        if isinstance(patch, str):
            targets = [line.lstrip().removeprefix("*** Delete File:").strip()
                       for line in patch.splitlines()
                       if line.lstrip().startswith("*** Delete File:")]
            if targets:
                return ("apply_patch <delete-file> " + _targets(targets), "complete")
    if tool in {"bash", "shell", "exec_command", "stateful_shell"}:
        command = values.get("command") or values.get("cmd")
        if isinstance(command, str):
            try:
                lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;<>")
                lexer.whitespace_split = True
                lexer.commenters = ""
                tokens = list(lexer)
            except ValueError:
                if re.search(r"(?<![\w])(?:rm|rmdir|unlink|shred|truncate|-delete)(?![\w])", command):
                    return ("shell <deletion-candidate>", "unparsed")
                tokens = []
            if tokens:
                executable = tokens[0].rsplit("/", 1)[-1]
                complex_shell = "\n" in command or any(marker in command for marker in ("$", "`")) or any(
                    token and set(token) <= set("|&;<>") for token in tokens
                )
                if executable in DELETE_COMMANDS:
                    if complex_shell:
                        return (executable + " <compound-or-dynamic>", "partial")
                    return (_direct_shape(executable, tokens[1:]), "complete")
                if executable == "find" and ("-delete" in tokens or any(token in DELETE_COMMANDS for token in tokens)):
                    return ("find <deletion-candidate>", "partial")
                if executable == "xargs" and any(token in DELETE_COMMANDS for token in tokens[1:]):
                    return ("xargs <deletion-candidate>", "partial")
                if executable == "git" and "clean" in tokens[1:]:
                    return ("git clean <deletion-candidate>", "partial")
                if executable == "git" and decision.consequence == "git.delete_ref":
                    return ("git push <ref-delete>", "complete")
                for index, token in enumerate(tokens[:-1]):
                    if token in {";", "&&", "||", "|", "&", "|&"} and tokens[index + 1].rsplit("/", 1)[-1] in DELETE_COMMANDS:
                        return ("shell <compound-deletion-candidate>", "partial")
    if decision.consequence in {"filesystem.delete", "git.delete_ref"}:
        return ("tool <deletion-consequence>", "partial")
    return None


@lru_cache(maxsize=1)
def _source_identity() -> tuple[str, str]:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z]+\.[0-9]+)?", version):
        version = "unknown"
    digest = hashlib.sha256()
    for folder in ("engine", "adapters"):
        for path in sorted((ROOT / folder).glob("*.py")):
            digest.update(str(path.relative_to(ROOT)).encode())
            digest.update(b"\x00")
            digest.update(path.read_bytes())
    digest.update(version.encode())
    return version, digest.hexdigest()


def _database_path(state_dir: str | Path, *, create: bool) -> Path:
    state = Path(os.path.abspath(Path(state_dir).expanduser()))
    directory = state / "observations"
    for path in [*reversed(directory.parents), directory]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            if not create:
                continue
            try:
                path.mkdir(mode=0o700)
            except FileExistsError:
                pass
            info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("unsafe observation directory")
    if directory.exists():
        info = directory.lstat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("observation directory must be private")
    database = directory / "deletions.sqlite3"
    if create:
        descriptor = os.open(database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
    for path in [database, *(Path(str(database) + suffix) for suffix in ("-journal", "-wal", "-shm"))]:
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("unsafe observation database")
        if info.st_size > MAX_BYTES:
            raise RuntimeError("observation capacity reached")
    return database


def _schema(connection: sqlite3.Connection) -> bytes:
    connection.execute("CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL, fingerprint_key BLOB NOT NULL)")
    connection.execute("INSERT OR IGNORE INTO metadata VALUES (1, ?, ?)", (SCHEMA_VERSION, os.urandom(32)))
    row = connection.execute("SELECT schema_version, fingerprint_key FROM metadata WHERE id=1").fetchone()
    if row is None or row[0] != SCHEMA_VERSION or not isinstance(row[1], bytes) or len(row[1]) != 32:
        raise RuntimeError("unsupported observation schema")
    connection.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, harness TEXT NOT NULL,
        shape TEXT NOT NULL, coverage TEXT NOT NULL, recognized INTEGER NOT NULL,
        outcome TEXT NOT NULL, policy_id TEXT NOT NULL, version TEXT NOT NULL,
        source_fingerprint TEXT NOT NULL, session_fingerprint TEXT,
        cwd_fingerprint TEXT, context_fingerprint TEXT NOT NULL
    )""")
    return row[1]


def _fingerprint(key: bytes, category: str, value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return hmac.new(key, (category + "\x00" + value).encode(), hashlib.sha256).hexdigest()


def observe(payload: dict[str, Any], decision: Any, kernel: Any) -> None:
    """Observation failures preserve the decision and emit only a fixed message."""
    if kernel.observation_dir is None:
        return
    try:
        item = candidate(payload, decision)
        if item is None:
            return
        shape, coverage = item
        version, source = _source_identity()
        database = _database_path(kernel.observation_dir, create=True)
        with closing(sqlite3.connect(database.as_uri() + "?mode=rw", uri=True,
                                    timeout=LOCK_TIMEOUT, isolation_level=None)) as connection:
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA page_size=4096")
            connection.execute(f"PRAGMA max_page_count={MAX_BYTES // 4096}")
            connection.execute("BEGIN IMMEDIATE")
            try:
                key = _schema(connection)
                if connection.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= MAX_EVENTS:
                    raise RuntimeError("observation capacity reached")
                session = payload.get("session_id")
                values = payload.get("tool_input")
                cwd = values.get("workdir") if isinstance(values, dict) else None
                cwd = cwd if isinstance(cwd, str) and cwd else payload.get("cwd")
                context = repr((tuple(map(str, kernel.enforcement_paths)),
                                tuple(map(str, kernel.credential_paths)),
                                tuple(map(str, kernel.scratch_paths))))
                policy = decision.consequence
                connection.execute("INSERT INTO events (timestamp,harness,shape,coverage,recognized,outcome,policy_id,version,source_fingerprint,session_fingerprint,cwd_fingerprint,context_fingerprint) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                    datetime.now(UTC).isoformat(timespec="milliseconds"),
                    kernel.observation_harness if kernel.observation_harness in HARNESS_NAMES else "unknown",
                    shape, coverage, int(policy in {"filesystem.delete", "git.delete_ref"}),
                    decision.outcome, policy if policy in POLICIES else "none",
                    version, source, _fingerprint(key, "session", session),
                    _fingerprint(key, "cwd", cwd), _fingerprint(key, "context", context),
                ))
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
    except Exception:
        try:
            sys.stderr.write(DIAGNOSTIC)
        except Exception:
            pass


def report(state_dir: str | Path) -> dict[str, Any]:
    """Read-only grouped evidence; missing session identities are never invented."""
    result: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "total_events": 0,
                              "groups": [], "max_events": MAX_EVENTS, "max_bytes": MAX_BYTES,
                              "at_capacity": False, "status": "empty"}
    try:
        database = _database_path(state_dir, create=False)
        if not database.exists():
            return result
        with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=LOCK_TIMEOUT)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            version = connection.execute("SELECT schema_version FROM metadata WHERE id=1").fetchone()
            if version != (SCHEMA_VERSION,):
                raise RuntimeError("unsupported observation schema")
            connection.row_factory = sqlite3.Row
            rows = connection.execute("""SELECT harness,shape,coverage,recognized,outcome,policy_id,
                version,source_fingerprint,context_fingerprint,COUNT(*) AS attempts,
                COUNT(DISTINCT session_fingerprint) AS sessions,
                SUM(session_fingerprint IS NULL) AS missing_session_attempts,
                COUNT(DISTINCT cwd_fingerprint) AS workspaces,
                SUM(cwd_fingerprint IS NULL) AS missing_cwd_attempts,
                MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen
                FROM events GROUP BY harness,shape,coverage,recognized,outcome,policy_id,
                version,source_fingerprint,context_fingerprint
                ORDER BY attempts DESC,harness,shape,coverage,recognized,outcome,policy_id,
                version,source_fingerprint,context_fingerprint""")
            result["groups"] = [dict(row) for row in rows]
            result["total_events"] = sum(group["attempts"] for group in result["groups"])
            result["at_capacity"] = result["total_events"] >= MAX_EVENTS or database.stat().st_size >= MAX_BYTES
            result["status"] = "available"
        return result
    except Exception as error:
        raise RuntimeError("observation unavailable") from error
