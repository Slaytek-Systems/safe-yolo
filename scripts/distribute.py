"""User-facing, reversible Safe YOLO private-beta distribution workflow."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.activate_v3 import _ensure_release, verify_source
from scripts.doctor import (
    _command_hooks,
    _owns_command,
    inspect_antigravity_wiring,
    inspect_claude_code_wiring,
    inspect_codex_wiring,
    inspect_release,
    owns_antigravity_group,
    own_hook_slots,
)
from scripts.harness_specs import ANTIGRAVITY_IDS, HARNESS_BY_ID, HARNESS_HOME_ENV, HARNESSES, HarnessSpec
from scripts.package import MANIFEST as DISTRIBUTION_MANIFEST, verify_bundle
from scripts.harness_wiring import (
    ANTIGRAVITY_GROUP as _ANTIGRAVITY_GROUP,
    config_path_problem as _config_path_problem,
    inspect_cursor_wiring as _inspect_cursor_wiring,
    inspect_opencode_wiring as _inspect_opencode_wiring,
    is_hand_wired_antigravity_group as _is_hand_wired_antigravity_group,
    is_stable_command as _is_stable_command,
    launcher_path as _launcher_path,
    pinned_command as _pinned_command,
    prepare_antigravity_hooks as _prepare_antigravity_hooks,
    prepare_command_hooks as _prepare_hooks,
    prepare_cursor_hooks as _prepare_cursor_hooks,
    prepare_opencode_plugin as _prepare_opencode_plugin,
    read_antigravity_hooks as _read_antigravity_hooks,
    read_json_object as _read_json_object,
    render_opencode_plugin as _render_opencode_plugin,
    stable_command as _stable_command,
)


RECEIPT_NAME = "codex-install.json"


def harness_catalog(user_home: str | Path | None = None) -> list[dict[str, Any]]:
    home = Path.home() if user_home is None else Path(user_home).expanduser()
    return [
        {
            "id": spec.id,
            "name": spec.name,
            "status": spec.status,
            "entry": spec.entry,
            "lifecycle_supported": spec.lifecycle_supported,
            "detected": bool(_t3_antigravity_profiles(home)) if spec.id == "antigravity-t3" else (
                shutil.which(spec.binary) is not None or _harness_root(spec, home, None).exists()),
        }
        for spec in HARNESSES
    ]


def _spec(harness: str) -> HarnessSpec:
    try:
        spec = HARNESS_BY_ID[harness]
    except KeyError as error:
        raise RuntimeError(
            f"Unknown harness {harness!r}. Choose one of: {', '.join(HARNESS_BY_ID)}."
        ) from error
    if not spec.lifecycle_supported:
        raise RuntimeError(
            f"{spec.name} is adapter-only in this release; install, doctor, and deactivate are not yet supported."
        )
    return spec


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _atomic_write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _exclusive_write(path: Path, payload: bytes, mode: int) -> None:
    """Like _atomic_write, but raises FileExistsError rather than replace an existing entry."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.link(temporary, path)
    finally:
        temporary.unlink()


Step = tuple[Callable[[], None], Callable[[], None]]


def _restore_file(path: Path, previous: bytes | None, mode: int) -> Callable[[], None]:
    """An undo that puts `path` back as it was: `previous`, or absent."""
    def undo() -> None:
        try:
            if previous is not None:
                _atomic_write(path, previous, mode)
            elif path.exists():
                path.unlink()
        except OSError as error:
            raise RuntimeError(f"{path} ({error})") from error
    return undo


def _apply_steps(steps: list[Step], check: Callable[[], None]) -> None:
    """Run each (write, undo) step in order, then `check`.

    On any failure, undo the steps whose write completed, newest first. Every undo runs even
    when another fails, so a write that never happened is never undone and one stuck file
    does not strand the rest. The error says what was restored and names any file that was not.
    """
    undos: list[Callable[[], None]] = []
    try:
        for write, undo in steps:
            write()
            undos.append(undo)
        check()
    except Exception as error:
        stuck = []
        for undo in reversed(undos):
            try:
                undo()
            except Exception as undo_error:
                stuck.append(str(undo_error))
        if stuck:
            raise RuntimeError(f"{error}; could not restore {', '.join(stuck)}") from error
        raise RuntimeError(f"previous hooks restored: {error}") from error


def _run_canaries(command_text: str, harness: str, timeout: int | None = None) -> dict[str, bool]:
    """Allow and deny replies of one hook command, run as the harness would run it."""
    command = shlex.split(command_text)
    if not command or shutil.which(command[0]) is None:
        raise RuntimeError(f"Hook command cannot start: {command_text}")
    base = {"hook_event_name": "PreToolUse", "cwd": str(Path.cwd())}
    if harness == "codex":
        allowed_payload = {**base, "tool_name": "exec_command", "tool_input": {"cmd": "git status --short"}}
        denied_payload = {**base, "tool_name": "exec_command", "tool_input": {"cmd": "git push --force-with-lease"}}
    elif harness == "claude-code":
        allowed_payload = {**base, "tool_name": "Bash", "tool_input": {"command": "git status --short"}}
        denied_payload = {**base, "tool_name": "Bash", "tool_input": {"command": "git push --force-with-lease"}}
    elif harness == "opencode":
        opencode_base = {"tool": "shell", "sessionID": "canary", "callID": "canary", "cwd": str(Path.cwd())}
        allowed_payload = {**opencode_base, "args": {"command": "git status --short"}}
        denied_payload = {**opencode_base, "args": {"command": "git push --force-with-lease"}}
    elif harness in ANTIGRAVITY_IDS:
        antigravity_base = {"stepIdx": 0, "conversationId": "canary", "workspacePaths": [str(Path.cwd())]}
        allowed_payload = {**antigravity_base, "toolCall": {"name": "run_command",
                                                            "args": {"CommandLine": "git status --short"}}}
        denied_payload = {**antigravity_base, "toolCall": {"name": "run_command",
                                                           "args": {"CommandLine": "git push --force-with-lease"}}}
    else:
        cursor_base = {"hook_event_name": "preToolUse", "cwd": str(Path.cwd()), "tool_name": "Shell"}
        allowed_payload = {**cursor_base, "tool_input": {"command": "git status --short"}}
        denied_payload = {**cursor_base, "tool_input": {"command": "git push --force-with-lease"}}
    if harness in ANTIGRAVITY_IDS:
        def reply(payload: dict[str, Any]) -> str | None:
            try:
                completed = subprocess.run(command, input=json.dumps(payload), text=True, capture_output=True,
                                           check=False, timeout=timeout)
            except OSError as error:
                raise RuntimeError(f"Antigravity hook command cannot start: {command_text} ({error})") from error
            except subprocess.TimeoutExpired:
                return None
            return _reply_decision(completed.stdout) if completed.returncode == 0 else None

        return {"allow": reply(allowed_payload) == "allow", "deny": reply(denied_payload) == "deny"}
    allowed = subprocess.run(
        command,
        input=json.dumps(allowed_payload),
        text=True,
        capture_output=True,
        check=False,
    )
    denied = subprocess.run(
        command,
        input=json.dumps(denied_payload),
        text=True,
        capture_output=True,
        check=False,
    )
    if harness == "opencode":
        return {
            outcome: completed.returncode == 0 and _reply_decision(completed.stdout) == outcome
            for outcome, completed in (("allow", allowed), ("deny", denied))
        }
    allow_ok = allowed.returncode == 0 and not allowed.stdout.strip()
    try:
        denial = json.loads(denied.stdout)
        deny_ok = denied.returncode == 0 and (
            denial.get("permission") == "deny"
            if harness == "cursor"
            else denial["hookSpecificOutput"]["permissionDecision"] == "deny"
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        deny_ok = False
    if harness == "cursor":
        try:
            allow_ok = (
                allowed.returncode == 0
                and json.loads(allowed.stdout).get("permission") == "allow"
            )
        except (json.JSONDecodeError, AttributeError):
            allow_ok = False
    return {"allow": allow_ok, "deny": deny_ok}


def _antigravity_hook(config_path: Path) -> tuple[str, int]:
    """The command and timeout Antigravity runs; the hooks file must already have passed the wiring check."""
    hook = _read_antigravity_hooks(config_path)[_ANTIGRAVITY_GROUP]["PreToolUse"][0]["hooks"][0]
    return hook["command"], hook["timeout"]


def _installed_canaries(spec: HarnessSpec, command: str, config_path: Path) -> dict[str, bool]:
    """Canaries through the command the harness runs: for Antigravity, the one its hooks file holds."""
    if spec.id in ANTIGRAVITY_IDS:
        hook_command, timeout = _antigravity_hook(config_path)
        return _run_canaries(hook_command, spec.id, timeout)
    return _run_canaries(command, spec.id)


def _reply_decision(stdout: str) -> str | None:
    try:
        decision = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    return decision.get("decision") if isinstance(decision, dict) else None


def _receipt_path(home: Path) -> Path:
    return home / "state" / RECEIPT_NAME


def _write_receipt(home: Path, receipt: dict[str, Any]) -> None:
    _atomic_write(
        _receipt_path(home),
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )


def _harness_receipt_path(home: Path, harness: str) -> Path:
    return home / "state" / "installations" / f"{harness}.json"


def _read_harness_receipt(home: Path, spec: HarnessSpec) -> tuple[dict[str, Any], Path]:
    receipt_path = _harness_receipt_path(home, spec.id)
    if receipt_path.is_file() or spec.id != "codex":
        return _read_json_object(receipt_path), receipt_path

    legacy_path = _receipt_path(home)
    legacy = _read_json_object(legacy_path)
    normalized = {
        **legacy,
        "harness": "codex",
        "config_path": legacy.get("hooks_path"),
        "installed_config_sha256": legacy.get("installed_hooks_sha256"),
        "previous_config_existed": legacy.get("previous_hooks_existed"),
        "previous_config_backup": legacy.get("previous_hooks_backup"),
        "previous_config_mode": legacy.get("previous_hooks_mode"),
    }
    return normalized, legacy_path


def _settled_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    """The installation whose hook the harness file holds.

    Update writes the receipt before the harness file, and rollback writes the harness file
    before the receipt. Stopped between the two, the receipt names one installation while the
    file still holds, or already holds, the hook of `previous_install`, so every command that
    rewrites the file continues from that one. Doctor reads the receipt as written: it names
    the release the launcher runs.
    """
    previous = receipt.get("previous_install")
    path = Path(str(receipt.get("config_path", "")))
    if receipt.get("status") != "active" or not previous or path.is_symlink() or not path.is_file():
        return receipt
    digest = _sha256(path)
    if digest != receipt.get("installed_config_sha256") and digest == previous.get("installed_config_sha256"):
        return previous
    return receipt


def _never_published(receipt: dict[str, Any]) -> bool:
    """A first install stopped after its receipt and before the harness file: the file is as it found it."""
    path = Path(str(receipt.get("config_path", "")))
    if receipt.get("previous_install") or path.is_symlink():
        return False
    if not receipt.get("previous_config_existed"):
        return not path.exists()
    backup = Path(str(receipt.get("previous_config_backup")))
    return (path.is_file() and backup.is_file() and path.read_bytes() == backup.read_bytes()
            and _sha256(path) != receipt.get("installed_config_sha256"))


def _has_harness_receipt(home: Path, spec: HarnessSpec) -> bool:
    return _harness_receipt_path(home, spec.id).is_file() or (
        spec.id == "codex" and _receipt_path(home).is_file()
    )


def _t3_antigravity_profiles(user_home: Path) -> list[Path]:
    """The profile folders T3 Code has created for Antigravity; it passes one as `--gemini-dir`."""
    parent = user_home / HARNESS_BY_ID["antigravity-t3"].config_dir
    try:
        return sorted(path for path in parent.iterdir() if path.is_dir())
    except OSError:
        return []


def _harness_root(spec: HarnessSpec, user_home: Path, config_home: str | Path | None) -> Path:
    """The configuration folder the harness itself reads, for discovery and install alike."""
    if config_home is not None:
        chosen = Path(config_home)
    elif spec.id == "antigravity-t3":
        profiles = _t3_antigravity_profiles(user_home)
        if len(profiles) != 1:
            found = ", ".join(map(str, profiles)) or "none"
            raise RuntimeError(
                f"Expected one T3 Code Antigravity profile under {user_home / spec.config_dir}, found {found}. "
                "Start an Antigravity thread in T3 Code once to create it, or pass --config-home <profile>."
            )
        chosen = profiles[0]
    elif spec.id == "opencode":
        # OpenCode 2.3.2's CLI order (packages/cli/src/index.ts): a non-empty OPENCODE_CONFIG_DIR,
        # then a non-empty XDG_CONFIG_HOME, then ~/.config.
        if os.environ.get("OPENCODE_CONFIG_DIR"):
            chosen = Path(os.environ["OPENCODE_CONFIG_DIR"])
        elif os.environ.get("XDG_CONFIG_HOME"):
            chosen = Path(os.environ["XDG_CONFIG_HOME"]) / "opencode"
        else:
            chosen = user_home / spec.config_dir
    else:
        environment_name = HARNESS_HOME_ENV.get(spec.id)
        environment_home = os.environ.get(environment_name) if environment_name else None
        chosen = Path(environment_home) if environment_home else user_home / spec.config_dir
    return chosen.expanduser().resolve(strict=False)


def _config_path(spec: HarnessSpec, user_home: Path, config_home: str | Path | None) -> Path:
    return _harness_root(spec, user_home, config_home) / spec.config_file


class OpenCodeV1Error(RuntimeError):
    """The OpenCode on PATH is V1, which cannot run the V2 plugin."""


# `opencode --version` prints `opencode v2.3.2` on V2 and a bare `1.19.6` on V1 (yargs).
_OPENCODE_VERSION_LINE = re.compile(r"(?:opencode v)?(?P<major>\d+)\.\d+\.\d+(?:-[0-9A-Za-z.]+)?\n?")


def _require_opencode_v2() -> None:
    """Refuse to replace a working V1 plugin when the OpenCode on PATH is V1.

    A sanity check on the version text, not proof of which program printed it.
    """
    binary = shutil.which("opencode")
    if binary is None:
        return
    try:
        completed = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f"Could not read the OpenCode version from {binary}: {error}") from error
    match = _OPENCODE_VERSION_LINE.fullmatch(completed.stdout)
    if completed.returncode != 0 or match is None:
        raise RuntimeError(
            f"{binary} --version did not print one OpenCode version line; nothing was changed."
        )
    if int(match.group("major")) < 2:
        raise OpenCodeV1Error(
            f"OpenCode {completed.stdout.strip()} on PATH ({binary}) is V1. This Safe YOLO plugin runs only on "
            "OpenCode V2, so the existing plugin was left unchanged. Upgrade OpenCode, then install again."
        )


def _retire(
    harness: str, path: Path, expected_sha256: str, home: Path, *, destination: Path | None = None
) -> Path:
    """Take an owned file out of the harness folder, keeping a verified copy in Safe YOLO's backups.

    Copy, re-check, unlink: no rename, so the backups may sit on another filesystem. The copy's
    name comes from the harness and digest, so a run interrupted after the unlink can be finished
    by a retry that finds the file gone and that copy in place. A failed install passes its own
    attempt folder as `destination`, so an earlier retained copy can never keep the file in place.
    """
    problem = _config_path_problem(harness, path)
    if problem:
        raise RuntimeError(problem)
    destination = destination or home / "backups" / f"retired-{harness}-{expected_sha256}-{path.name}"

    def holds_expected(candidate: Path) -> bool:
        return (
            not candidate.is_symlink()
            and candidate.is_file()
            and hashlib.sha256(candidate.read_bytes()).hexdigest() == expected_sha256
        )

    if not path.exists() and not path.is_symlink():
        if holds_expected(destination):
            return destination
        raise RuntimeError(f"{path} is missing and no verified copy exists at {destination}; needs operator review.")
    if not holds_expected(path):
        raise RuntimeError(f"{path} changed since installation; refusing to remove newer work.")
    if destination.exists() or destination.is_symlink():
        if not holds_expected(destination):
            raise RuntimeError(f"{destination} already exists with other contents; {path} was left in place.")
    else:
        _exclusive_write(destination, path.read_bytes(), path.stat().st_mode & 0o777)
    if not holds_expected(destination):
        raise RuntimeError(f"Could not keep a verified copy of {path}; it was left in place.")
    if not holds_expected(path):
        raise RuntimeError(f"{path} changed since installation; refusing to remove newer work.")
    path.unlink()
    return destination


def _direct_command(command: str, home: Path, spec: HarnessSpec, receipt: dict[str, Any]) -> str:
    """`command` made to run `receipt`'s release directly, with the same interpreter.

    A stable command reads the release from the active receipt, so it cannot check a release
    before the receipt names it. A release-pinned command already runs its own release.
    """
    if not _is_stable_command(command, home, spec.id, spec.entry):
        return command
    pinned = _pinned_command(home, Path(receipt["release"]), receipt["manifest_sha256"], spec.entry,
                             user_home=Path(receipt["user_home"]), harness_home=Path(receipt["harness_home"]))
    return shlex.join([shlex.split(command)[0], *shlex.split(pinned)[1:]])


def _config_root(spec: HarnessSpec, config_path: Path) -> Path:
    """The harness configuration folder that holds this config file."""
    return config_path.parents[len(Path(spec.config_file).parts) - 1]


def _receipt_pin(receipt: dict[str, Any], home: Path, spec: HarnessSpec) -> dict[str, Any]:
    """How to recognise the hook command that the installation behind this receipt wrote."""
    pin: dict[str, Any] = {"release_path": receipt.get("release", ""), "entry": spec.entry}
    if receipt.get("command"):
        return {**pin, "command": receipt["command"]}
    # Written by 3.0.0-beta.17 or earlier, whose command pinned the release. Kept so one update can migrate it.
    user = receipt.get("user_home")
    return {
        **pin,
        "bootstrap_path": receipt.get("bootstrap") or home / "bootstrap.py",
        "manifest_sha256": receipt.get("manifest_sha256", ""),
        "safe_yolo_home": home if user else None,
        "user_home": user,
        "harness_home": receipt.get("harness_home") if user else None,
        "state_dir": home / "state",
    }


def _inspect_wiring(spec: HarnessSpec, config_path: Path, home: Path, pin: dict[str, Any]) -> dict[str, Any]:
    """Whether the harness configuration holds the hook command `pin` describes."""
    if spec.id == "codex":
        return inspect_codex_wiring(
            config_path.parent / "config.toml",
            config_path,
            pin.get("bootstrap_path"),
            pin.get("manifest_sha256"),
            release_path=pin["release_path"],
            entry=spec.entry,
            safe_yolo_home=pin.get("safe_yolo_home"),
            user_home=pin.get("user_home"),
            harness_home=pin.get("harness_home"),
            command=pin.get("command"),
        )
    if spec.id in ANTIGRAVITY_IDS:
        return inspect_antigravity_wiring(config_path, **pin)
    if spec.id == "claude-code":
        return inspect_claude_code_wiring(
            config_path,
            pin.get("bootstrap_path"),
            pin.get("manifest_sha256"),
            release_path=pin["release_path"],
            entry=spec.entry,
            safe_yolo_home=pin.get("safe_yolo_home"),
            user_home=pin.get("user_home"),
            harness_home=pin.get("harness_home"),
            state_dir=pin.get("state_dir"),
            command=pin.get("command"),
        )
    if spec.id == "opencode":
        return _inspect_opencode_wiring(config_path, Path(pin["release_path"]), [_opencode_command(home, spec, pin)])
    return _inspect_cursor_wiring(config_path, lambda command: _owns_command(command, pin))


def _opencode_command(home: Path, spec: HarnessSpec, pin: dict[str, Any]) -> str:
    """The command the OpenCode plugin of this pin calls. The plugin text cannot be parsed back, only rendered."""
    return pin.get("command") or _pinned_command(
        home, Path(pin["release_path"]), pin["manifest_sha256"], spec.entry,
        user_home=Path(pin["user_home"]) if pin.get("user_home") else None,
        harness_home=Path(pin["harness_home"]) if pin.get("harness_home") else None,
    )


def _saved_hook(spec: HarnessSpec, path: Path, home: Path, receipt: dict[str, Any]) -> tuple[str, int | None]:
    """The Safe YOLO hook command `path` holds for the installation behind `receipt`, with its Antigravity timeout.

    Read from the file, not the receipt: receipts written before the stable command name no command,
    and the file is what the harness runs.
    """
    pin = _receipt_pin(receipt, home, spec)
    if spec.id in ANTIGRAVITY_IDS:
        group = _read_antigravity_hooks(path).get(_ANTIGRAVITY_GROUP)
        if owns_antigravity_group(group, **pin):
            hook = group["PreToolUse"][0]["hooks"][0]
            return hook["command"], hook["timeout"]
    elif spec.id == "opencode":
        if _inspect_wiring(spec, path, home, pin)["healthy"]:
            return _opencode_command(home, spec, pin), None
    else:
        hooks = _read_json_object(path).get("hooks")
        if spec.id == "cursor":
            entries = hooks.get("preToolUse") if isinstance(hooks, dict) else None
            commands = [entry.get("command") for entry in entries or [] if isinstance(entry, dict)]
        else:
            commands = [command for _, command in _command_hooks(hooks, "PreToolUse")]
        owned = [command for command in commands if isinstance(command, str) and _owns_command(command, pin)]
        if len(owned) == 1:
            return owned[0], None
    raise RuntimeError(f"{path} does not hold the Safe YOLO hook of release {receipt.get('version')}")


def _without_own_hook(groups: Any, pin: dict[str, Any]) -> list[Any]:
    """Claude Code's PreToolUse groups minus the hook this installation wrote, and any group that empties."""
    slots = set(own_hook_slots(groups, **pin))
    kept = []
    for group_index, group in enumerate(groups if isinstance(groups, list) else []):
        if not any(index == group_index for index, _ in slots):
            kept.append(group)
            continue
        hooks = [hook for hook_index, hook in enumerate(group['hooks']) if (group_index, hook_index) not in slots]
        if hooks:
            kept.append({**group, 'hooks': hooks})
    return kept


def _remove_own_hook(spec: HarnessSpec, receipt: dict[str, Any], home: Path) -> Path | None:
    """Take this installation's hook out of the harness file and leave everything else in it.

    Other owners' hooks and settings stay, including any added after install. Keys only Safe YOLO
    writes go back to their values from before the first install. A file Safe YOLO created that
    is left holding nothing is retired; the retained copy is returned.
    """
    harness = spec.id
    config = Path(str(receipt.get('config_path', '')))
    baseline = receipt.get('original_install', receipt)
    if not baseline['previous_config_existed'] and not config.exists() and not config.is_symlink():
        # An earlier run retired the file and stopped; finish from its verified copy.
        return _retire(harness, config, receipt['installed_config_sha256'], home)
    if (config.is_symlink() or not config.is_file() or _config_path_problem(harness, config)
            or _sha256(config) != receipt.get('installed_config_sha256')):
        raise RuntimeError(f'{spec.name} configuration changed since installation; refusing to overwrite newer work.')
    original_bytes = None
    original: dict[str, Any] = {}
    if baseline['previous_config_existed']:
        original_bytes = Path(baseline['previous_config_backup']).read_bytes()
        original = (_read_antigravity_hooks(Path(baseline['previous_config_backup'])) if harness in ANTIGRAVITY_IDS
                    else json.loads(original_bytes))
    document = _read_antigravity_hooks(config) if harness in ANTIGRAVITY_IDS else json.loads(config.read_text())
    if harness in ANTIGRAVITY_IDS:
        document.pop(_ANTIGRAVITY_GROUP)
    else:
        event = 'preToolUse' if harness == 'cursor' else 'PreToolUse'
        original_hooks = original.get('hooks', {})
        if original_hooks.get(event):
            raise RuntimeError('The legacy baseline already contains an enforcement hook; a complete uninstall needs operator review.')
        # Install and update keep Codex and Cursor's event to Safe YOLO's hook alone; Claude Code shares it.
        others = (_without_own_hook(document['hooks'].get(event), _receipt_pin(receipt, home, spec))
                  if harness == 'claude-code' else [])
        if others:
            document['hooks'][event] = others
        elif event in original_hooks:
            document['hooks'][event] = original_hooks[event]
        else:
            document['hooks'].pop(event, None)
        if not document['hooks'] and 'hooks' not in original:
            document.pop('hooks')
    owned_key = 'version' if harness == 'cursor' else 'description' if harness == 'codex' else None
    if owned_key:
        if owned_key in original:
            document[owned_key] = original[owned_key]
        else:
            document.pop(owned_key, None)
    if not document and original_bytes is None:
        return _retire(harness, config, receipt['installed_config_sha256'], home)
    payload = original_bytes if document == original and original_bytes is not None else (
        json.dumps(document, indent=2, allow_nan=harness not in ANTIGRAVITY_IDS) + '\n').encode()
    _atomic_write(config, payload, baseline['previous_config_mode'])
    return None


def _same_config(spec: HarnessSpec, original: bytes, payload: bytes) -> bool:
    """Whether writing `payload` would change nothing the harness reads."""
    if spec.id == "opencode":
        return original == payload
    try:
        return json.loads(original) == json.loads(payload)
    except ValueError:
        return False


def install_harness(
    *,
    harness: str,
    source: str | Path,
    safe_yolo_home: str | Path,
    user_home: str | Path,
    expected_commit: str,
    config_home: str | Path | None = None,
) -> dict[str, Any]:
    spec = _spec(harness)
    source_path = Path(source).resolve()
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    user = Path(user_home).expanduser().resolve(strict=False)
    target = _config_path(spec, user, config_home)
    harness_home = _config_root(spec, target)
    previous_receipt = None
    if _has_harness_receipt(home, spec):
        existing = _settled_receipt(_read_harness_receipt(home, spec)[0])
        if existing.get('status') == 'active' and not _never_published(existing):
            previous_receipt = existing
    if previous_receipt and Path(str(previous_receipt.get('config_path'))) != target:
        raise RuntimeError(
            f"The active {spec.name} installation is wired to {previous_receipt.get('config_path')}, "
            f"not {target}. Run `safe-yolo uninstall --harness {spec.id}` first, or select that folder again."
        )
    for other in HARNESSES:
        # Only another id that writes the same kind of file can own this one.
        if (other.id != spec.id and other.lifecycle_supported and other.config_file == spec.config_file
                and other.entry == spec.entry and _has_harness_receipt(home, other)):
            claimed, _ = _read_harness_receipt(home, other)
            if claimed.get('status') == 'active' and Path(str(claimed.get('config_path'))) == target:
                raise RuntimeError(
                    f"{target} is already managed as {other.id}. Run `safe-yolo uninstall --harness {other.id}` "
                    f"first, then install {spec.id}."
                )
    if spec.id == "opencode":
        _require_opencode_v2()
    source_commit = (
        verify_bundle(source_path)
        if (source_path / DISTRIBUTION_MANIFEST).is_file()
        else verify_source(source_path, expected_commit)
    )
    if source_commit != expected_commit:
        raise RuntimeError('Download source revision does not match the requested revision.')
    release, digest, version = _ensure_release(source_path, home)
    if previous_receipt and previous_receipt['version'] == version:
        report = doctor_harness(harness=harness, safe_yolo_home=home, user_home=user)
        if not report['healthy']:
            raise RuntimeError('Existing installation needs attention: ' + '; '.join(report['problems']))
        return previous_receipt
    previous_pin = _receipt_pin(previous_receipt, home, spec) if previous_receipt else None
    if previous_receipt:
        current_wiring = _inspect_wiring(spec, target, home, previous_pin)
        if not current_wiring['healthy']:
            raise RuntimeError('Existing Safe YOLO hook changed; refusing to overwrite it.')
        verified_current = target.read_bytes()
        previous_receipt = {**previous_receipt, 'installed_config_sha256': hashlib.sha256(verified_current).hexdigest()}
    # The new release must answer correctly on its own before anything a harness reads changes.
    canaries = _run_canaries(
        _pinned_command(home, release, digest, spec.entry, user_home=user, harness_home=harness_home), spec.id)
    if not all(canaries.values()):
        raise RuntimeError(
            f"Safe YOLO activation failed: release {version} failed its allow/deny check ({canaries}); "
            "nothing was changed.")
    command = _stable_command(home, spec.id, spec.entry)
    if spec.id == "opencode":
        payload = _render_opencode_plugin(release, command)
        owned = [payload, verified_current] if previous_receipt else [payload]
        original_bytes, original_mode = _prepare_opencode_plugin(target, release, owned)
    else:
        if spec.id == "cursor":
            candidate, original_bytes, original_mode = _prepare_cursor_hooks(target, home, command)
        elif spec.id in ANTIGRAVITY_IDS:
            def owns(group: Any) -> bool:
                if not previous_receipt:
                    return _is_hand_wired_antigravity_group(group, home)
                return owns_antigravity_group(group, **previous_pin)
            candidate, original_bytes, original_mode = _prepare_antigravity_hooks(target, command, owns)
        else:
            own_slots = None
            if previous_receipt and spec.id == "claude-code":
                # Claude Code runs every matching hook and a deny from any of them wins, so other
                # owners' hooks may stand beside this one. An update swaps only the hook this
                # installation wrote, which the wiring check above found exactly once.
                def own_slots(groups: Any) -> list[tuple[int, int]]:
                    return own_hook_slots(groups, **previous_pin)
            candidate, original_bytes, original_mode = _prepare_hooks(
                target, home, command, entry=spec.entry, label=spec.name, own_slots=own_slots
            )
        payload = (json.dumps(candidate, indent=2, allow_nan=spec.id not in ANTIGRAVITY_IDS) + "\n").encode()
    # Rewrite the harness file only when its Safe YOLO entry differs from the stable form, which
    # happens on a first install and on the one update that migrates a release-pinned command.
    config_changes = original_bytes is None or not _same_config(spec, original_bytes, payload)
    if not config_changes:
        payload = original_bytes
    backup_root = home / "backups" / (
        f"pre-{spec.id}-{version}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    )
    backup_root.mkdir(parents=True, mode=0o700)
    backup_path: Path | None = None
    if original_bytes is not None:
        backup_path = backup_root / target.name
        _atomic_write(backup_path, original_bytes, original_mode)
    launcher = _launcher_path(home, spec.id)
    receipt_path = _harness_receipt_path(home, spec.id)
    previous_launcher = launcher.read_bytes() if launcher.is_file() else None
    previous_receipt_bytes = receipt_path.read_bytes() if receipt_path.is_file() else None
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "active",
        "harness": spec.id,
        "version": version,
        "source_commit": source_commit,
        "release": str(release),
        "bootstrap": str(launcher),
        "launcher": str(launcher),
        "command": command,
        "manifest_sha256": digest,
        "config_path": str(target),
        "user_home": str(user),
        "harness_home": str(harness_home),
        "installed_config_sha256": hashlib.sha256(payload).hexdigest(),
        "previous_config_existed": original_bytes is not None,
        "previous_config_backup": str(backup_path) if backup_path else None,
        "previous_config_mode": original_mode,
        "healthy": True,
        "canaries": canaries,
        "next_action": _next_action(spec, config_changes),
    }
    if previous_receipt:
        receipt['original_install'] = previous_receipt.get('original_install', {
            key: previous_receipt[key] for key in ('previous_config_existed', 'previous_config_backup',
                                                 'previous_config_mode')})
        receipt['previous_install'] = {key: value for key, value in previous_receipt.items()
                                       if key != 'previous_install'}
    receipt_bytes = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    steps: list[Step] = [
        # The launcher first: a newer bootstrap still verifies the release an older receipt names.
        (lambda: _atomic_write(launcher, (release / "scripts" / "bootstrap.py").read_bytes(), 0o700),
         _restore_file(launcher, previous_launcher, 0o700)),
        # The cut-over: from here the unchanged command runs the new release.
        (lambda: _atomic_write(receipt_path, receipt_bytes), _restore_file(receipt_path, previous_receipt_bytes, 0o600)),
    ]
    if config_changes:
        def remove_new_config() -> None:
            _retire(spec.id, target, hashlib.sha256(payload).hexdigest(), home,
                    destination=backup_root / f"failed-{target.name}")
        steps.append((lambda: _atomic_write(target, payload, original_mode),
                      remove_new_config if original_bytes is None
                      else _restore_file(target, original_bytes, original_mode)))

    def check() -> None:
        wiring = _inspect_wiring(spec, target, home, _receipt_pin(receipt, home, spec))
        installed = (_installed_canaries(spec, command, target)
                     if wiring["healthy"] or spec.id not in ANTIGRAVITY_IDS else {"allow": False, "deny": False})
        if not wiring["healthy"] or not all(installed.values()):
            raise RuntimeError(f"doctor problems={wiring['problems']}; canaries={installed}")

    try:
        _apply_steps(steps, check)
    except RuntimeError as error:
        raise RuntimeError(f"Safe YOLO activation failed; {error}") from error
    return receipt


def _next_action(spec: HarnessSpec, config_changed: bool) -> str:
    if not config_changed:
        return (f"Nothing to do: the {spec.name} hook command did not change, so running sessions use this "
                "release on their next tool call.")
    return {
        "codex": (
            "Restart Codex, open /hooks, review this command, and trust its hash. Later updates keep the same "
            "command, so this is needed once after the switch to the stable command, and again only if the Python "
            "path in the command changes."
        ),
        "claude-code": "Restart Claude Code, then run /hooks and verify the Safe YOLO PreToolUse hook.",
        "cursor": "Cursor watches the user hooks file and reloads it automatically; verify Safe YOLO in Hooks.",
        "opencode": (
            "Run `opencode service restart` if the OpenCode background service is running, then start a new "
            "session. Doctor checks the plugin file and release but cannot prove OpenCode loaded the plugin: "
            "run `opencode api plugin.list` against the server and location your sessions use and confirm the "
            "safe-yolo entry has state status `active`, not `failed`, with this plugin file as its source "
            "(repeat it if the list is empty while plugins load), then in a session check that "
            "`echo hello` runs and `git push --force origin main` is denied in a new empty folder after "
            "`git init` (no remote, so nothing is pushed if the plugin did not load)."
        ),
        "antigravity": (
            "Start a new Antigravity session, run /hooks and confirm the safe-yolo PreToolUse hook is listed. "
            "Doctor runs the command in the hooks file but cannot prove Antigravity loaded the "
            "hook. Antigravity ignores a hook that crashes, times out or prints invalid output."
        ),
        "antigravity-t3": (
            "Start a new Antigravity thread in T3 Code and check that `git push --force origin main` is "
            "denied with a Safe YOLO reason in a new empty folder after `git init` (no remote, so nothing is "
            "pushed if the hook did not load; a git error about the remote is not proof). Doctor runs the command in the hooks file but cannot prove "
            "Antigravity loaded the hook. Antigravity ignores a hook that crashes, times out or prints "
            "invalid output."
        ),
    }[spec.id]


def doctor_harness(
    *, harness: str, safe_yolo_home: str | Path, user_home: str | Path
) -> dict[str, Any]:
    spec = _spec(harness)
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    receipt = _read_harness_receipt(home, spec)[0]
    problems: list[str] = []
    if receipt.get("status") != "active":
        problems.append("installation receipt is not active")
    config_path = Path(str(receipt.get("config_path", "")))
    if not config_path.is_file():
        problems.append("installed harness configuration is missing")
    elif _sha256(config_path) != receipt.get("installed_config_sha256"):
        problems.append("installed harness configuration changed after activation")
    release = Path(str(receipt.get("release", "")))
    release_report = inspect_release(release, str(receipt.get("manifest_sha256", "")))
    problems.extend(release_report["problems"])
    command = receipt.get("command")
    if not _is_stable_command(command, home, spec.id, spec.entry):
        problems.append("the hook command is not the stable Safe YOLO command; run `safe-yolo update` to switch to it")
        command = None
    launcher = _launcher_path(home, spec.id)
    bootstrap = release / "scripts" / "bootstrap.py"
    launcher_matches = launcher.is_file() and bootstrap.is_file() and launcher.read_bytes() == bootstrap.read_bytes()
    if not launcher_matches:
        problems.append(f"launcher {launcher} does not match the active release's bootstrap")
    wiring = _inspect_wiring(spec, config_path, home, _receipt_pin(receipt, home, spec))
    problems.extend(wiring["problems"])
    canaries = {"allow": False, "deny": False}
    # Doctor runs only a launcher it has checked; an unknown file under the hook path stays unrun.
    if command and launcher_matches and release_report["healthy"] and (
            wiring["healthy"] or spec.id not in ANTIGRAVITY_IDS):
        try:
            canaries = _installed_canaries(spec, command, config_path)
        except RuntimeError as error:
            problems.append(str(error))
    if not all(canaries.values()):
        problems.append("allow/deny runtime canaries failed")
    return {
        "healthy": not problems,
        "harness": spec.id,
        "status": receipt.get("status"),
        "version": receipt.get("version"),
        "release": str(release),
        "canaries": canaries,
        "problems": problems,
        "activation_check": receipt.get("next_action"),
    }


def deactivate_harness(
    *, harness: str, safe_yolo_home: str | Path, user_home: str | Path
) -> dict[str, Any]:
    spec = _spec(harness)
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    recorded, receipt_path = _read_harness_receipt(home, spec)
    receipt = _settled_receipt(recorded)
    if receipt.get("status") != "active":
        raise RuntimeError(f"Safe YOLO {spec.name} installation is not active.")
    baseline = receipt.get("original_install", receipt)
    if spec.id != "opencode":
        retained = _remove_own_hook(spec, receipt, home)
    elif baseline.get("previous_config_existed"):
        # The plugin file is wholly Safe YOLO's: put back the plugin it replaced, from before the first install.
        config_path = Path(str(receipt.get("config_path", "")))
        if (
            config_path.is_symlink()
            or not config_path.is_file()
            or _config_path_problem(spec.id, config_path)
            or _sha256(config_path) != receipt.get("installed_config_sha256")
        ):
            raise RuntimeError(
                f"{spec.name} configuration changed since installation; refusing to overwrite newer work."
            )
        backup = Path(str(baseline.get("previous_config_backup")))
        if not backup.is_file():
            raise RuntimeError("Previous configuration backup is missing; refusing an incomplete rollback.")
        _atomic_write(config_path, backup.read_bytes(), int(baseline.get("previous_config_mode", 0o600)))
        retained = None
    else:
        retained = _retire(spec.id, Path(str(receipt.get("config_path", ""))),
                           str(receipt.get("installed_config_sha256")), home)
    if retained:
        receipt["deactivated_config_backup"] = str(retained)
    receipt["status"] = "inactive"
    receipt["deactivated_at"] = datetime.now(UTC).isoformat()
    _atomic_write(receipt_path, (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
    return {
        "status": "inactive",
        "harness": spec.id,
        "restored_previous_config": bool(baseline.get("previous_config_existed")),
        "retained_release": str(receipt.get("release")),
        "next_action": f"Restart {spec.name} if it is running. Immutable release and rollback evidence were retained.",
    }


def install_codex(
    *, source: str | Path, safe_yolo_home: str | Path, codex_home: str | Path, expected_commit: str
) -> dict[str, Any]:
    receipt = install_harness(
        harness="codex",
        source=source,
        safe_yolo_home=safe_yolo_home,
        user_home=Path(codex_home).expanduser().parent,
        config_home=codex_home,
        expected_commit=expected_commit,
    )
    legacy = {
        **receipt,
        "hooks_path": receipt["config_path"],
        "installed_hooks_sha256": receipt["installed_config_sha256"],
        "previous_hooks_existed": receipt["previous_config_existed"],
        "previous_hooks_backup": receipt["previous_config_backup"],
        "previous_hooks_mode": receipt["previous_config_mode"],
    }
    _write_receipt(Path(safe_yolo_home).expanduser().resolve(strict=False), legacy)
    return legacy


def doctor_codex(*, safe_yolo_home: str | Path, codex_home: str | Path) -> dict[str, Any]:
    return doctor_harness(
        harness="codex",
        safe_yolo_home=safe_yolo_home,
        user_home=Path(codex_home).expanduser().parent,
    )


def deactivate_codex(*, safe_yolo_home: str | Path, codex_home: str | Path) -> dict[str, Any]:
    result = deactivate_harness(
        harness="codex",
        safe_yolo_home=safe_yolo_home,
        user_home=Path(codex_home).expanduser().parent,
    )
    return {**result, "restored_previous_hooks": result["restored_previous_config"]}


def _current_commit(source: Path) -> str:
    if (source / DISTRIBUTION_MANIFEST).is_file():
        return verify_bundle(source)
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=source,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("Safe YOLO must be installed from a Git checkout.")
    return completed.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="safe-yolo",
        description="Manage the harness-agnostic Safe YOLO private beta.",
    )
    parser.add_argument("--home", type=Path, default=Path("~/.safe-yolo").expanduser())
    parser.add_argument("--user-home", type=Path, default=Path.home())
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("harnesses", help="List adapters and honest lifecycle support levels.")
    observations = subparsers.add_parser("observations", help="Read grouped local deletion observations as JSON.")
    observations.add_argument("--state-dir", type=Path)
    install = subparsers.add_parser("install", help="Install and activate one supported harness integration.")
    install.add_argument("--harness", choices=tuple(HARNESS_BY_ID))
    install.add_argument("--source", type=Path, default=ROOT)
    install.add_argument("--config-home", type=Path)
    doctor = subparsers.add_parser("doctor", help="Verify release, wiring, and allow/deny canaries.")
    doctor_group = doctor.add_mutually_exclusive_group()
    doctor_group.add_argument("--harness", choices=tuple(HARNESS_BY_ID))
    doctor_group.add_argument("--all", action="store_true", help="Check every installed supported harness.")
    deactivate = subparsers.add_parser("deactivate", help="Restore one harness's exact pre-install state.")
    deactivate.add_argument("--harness", choices=tuple(HARNESS_BY_ID), required=True)
    update = subparsers.add_parser('update', help='Download the latest release or install a verified local bundle.')
    update.add_argument('--source', type=Path)
    for name in ('rollback', 'uninstall'):
        command = subparsers.add_parser(name)
        command.add_argument('--harness', choices=tuple(HARNESS_BY_ID))
    args = parser.parse_args(argv)
    try:
        if args.command == "harnesses":
            result: Any = {"harnesses": harness_catalog(args.user_home)}
        elif args.command == "observations":
            from engine.deletion_observation import report
            result = report(args.state_dir if args.state_dir is not None else args.home / "state")
        elif args.command == "install":
            source = args.source.resolve()
            if args.config_home and not args.harness:
                raise RuntimeError('--config-home requires --harness.')
            selected = [args.harness] if args.harness else [item['id'] for item in harness_catalog(args.user_home)
                        if item['detected'] and item['lifecycle_supported']]
            if (args.harness == 'antigravity' and not args.config_home
                    and _t3_antigravity_profiles(args.user_home.expanduser())):
                # One request covers every place Antigravity runs on this machine.
                selected.append('antigravity-t3')
            if not selected:
                raise RuntimeError('No supported harness detected. Run harnesses, then install --harness <id>.')
            revision = _current_commit(source)
            from scripts.global_cli import install_command
            launcher = install_command(source, args.home.resolve(), args.user_home.resolve())
            reports, skipped, refused = [], [], []
            for harness in selected:
                try:
                    reports.append(install_harness(harness=harness, source=source, safe_yolo_home=args.home,
                                   user_home=args.user_home, config_home=args.config_home,
                                   expected_commit=revision))
                except OpenCodeV1Error as error:
                    if args.harness:
                        raise
                    skipped.append({'harness': harness, 'reason': str(error)})
                except (RuntimeError, OSError) as error:
                    if len(selected) == 1 or not args.harness:
                        raise
                    refused.append(f'{harness}: {error}')
            if refused:
                done = ', '.join(report['harness'] for report in reports) or 'nothing'
                raise RuntimeError(f"Installed {done}. Not installed: {'; '.join(refused)}")
            result = reports[0] if len(selected) == 1 and args.harness else {
                'healthy': True, 'reports': reports, 'skipped': skipped}
            result['command'] = str(launcher) if launcher else None
            result['path_note'] = 'Add ~/.local/bin to PATH if safe-yolo is not found.'
        elif args.command == 'update':
            from scripts.global_cli import active_receipts, install_command
            receipts = active_receipts(args.home.resolve())
            if not receipts:
                raise RuntimeError('No active installations to update.')
            with tempfile.TemporaryDirectory(prefix='safe-yolo-update-') as temporary:
                if args.source:
                    source = args.source.resolve()
                else:
                    from scripts.download import download_latest
                    source = download_latest(Path(temporary))
                revision = _current_commit(source)
                if source != ROOT:
                    # Run the new management code, so future installer fixes take effect on update.
                    return subprocess.run([sys.executable, str(source / 'safe-yolo'), '--home',
                        str(args.home.resolve()), '--user-home', str(args.user_home.resolve()),
                        'update', '--source', str(source)], check=False).returncode
                launcher = install_command(source, args.home.resolve(), args.user_home.resolve())
                reports = [install_harness(harness=receipt['harness'], source=source,
                           safe_yolo_home=args.home, user_home=receipt.get('user_home', args.user_home),
                           config_home=receipt.get('harness_home') or Path(receipt['config_path']).parent,
                           expected_commit=revision)
                           for receipt in receipts]
                result = {'healthy': True, 'reports': reports, 'command': str(launcher)}
        elif args.command in {'rollback', 'uninstall'}:
            from scripts.global_cli import active_receipts, restore
            selected = [args.harness] if args.harness else [
                receipt['harness'] for receipt in active_receipts(args.home.resolve())
                # A harness installed once has nothing to roll back to; it must not stop the others.
                if args.command == 'uninstall' or receipt.get('previous_install')]
            if not selected:
                raise RuntimeError('No active installations found.' if not active_receipts(args.home.resolve())
                                   else 'No previous installation is available for rollback.')
            result = {'reports': [restore(args.home.resolve(), args.user_home.resolve(), harness,
                      uninstall=args.command == 'uninstall') for harness in selected],
                      'note': 'Inactive releases and the management command are retained for recovery.'}
        elif args.command == "doctor":
            if not args.harness:
                installed = [
                    spec.id
                    for spec in HARNESSES
                    if spec.lifecycle_supported
                    and _has_harness_receipt(args.home.expanduser(), spec)
                ]
                reports = [
                    doctor_harness(
                        harness=harness,
                        safe_yolo_home=args.home,
                        user_home=args.user_home,
                    )
                    for harness in installed
                ]
                result = {"healthy": bool(reports) and all(item["healthy"] for item in reports), "reports": reports}
            else:
                result = doctor_harness(
                    harness=args.harness,
                    safe_yolo_home=args.home,
                    user_home=args.user_home,
                )
        else:
            result = deactivate_harness(
                harness=args.harness,
                safe_yolo_home=args.home,
                user_home=args.user_home,
            )
    except (RuntimeError, OSError, ValueError) as error:
        print(f"safe-yolo: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("healthy", True) else 1


if __name__ == "__main__":
    raise SystemExit(main())
