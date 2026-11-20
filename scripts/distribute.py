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
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.activate_v3 import _ensure_release, verify_source
from scripts.doctor import (
    inspect_antigravity_wiring,
    inspect_claude_code_wiring,
    inspect_codex_wiring,
    inspect_release,
    owns_antigravity_group,
    pinned_hook_slots,
)
from scripts.harness_specs import HARNESS_BY_ID, HARNESS_HOME_ENV, HARNESSES, HarnessSpec
from scripts.package import MANIFEST as DISTRIBUTION_MANIFEST, verify_bundle
from scripts.harness_wiring import (
    inspect_cursor_wiring as _inspect_cursor_wiring,
    inspect_opencode_wiring as _inspect_opencode_wiring,
    is_hand_wired_antigravity_group as _is_hand_wired_antigravity_group,
    config_path_problem as _config_path_problem,
    pinned_command as _pinned_command,
    prepare_antigravity_hooks as _prepare_antigravity_hooks,
    prepare_command_hooks as _prepare_hooks,
    prepare_cursor_hooks as _prepare_cursor_hooks,
    prepare_opencode_plugin as _prepare_opencode_plugin,
    read_json_object as _read_json_object,
    render_opencode_plugin as _render_opencode_plugin,
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
            "detected": shutil.which(spec.binary) is not None or _harness_root(spec, home, None).exists(),
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


def _run_canaries(
    home: Path,
    release: Path,
    manifest_sha256: str,
    *,
    harness: str = "codex",
    entry: str = "codex_v3",
    user_home: Path | None = None,
    harness_home: Path | None = None,
) -> dict[str, bool]:
    command = shlex.split(
        _pinned_command(
            home,
            release,
            manifest_sha256,
            entry,
            user_home=user_home,
            harness_home=harness_home,
        )
    )
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
    elif harness == "antigravity":
        antigravity_base = {"stepIdx": 0, "conversationId": "canary", "workspacePaths": [str(Path.cwd())]}
        allowed_payload = {**antigravity_base, "toolCall": {"name": "run_command",
                                                            "args": {"CommandLine": "git status --short"}}}
        denied_payload = {**antigravity_base, "toolCall": {"name": "run_command",
                                                           "args": {"CommandLine": "git push --force-with-lease"}}}
    else:
        cursor_base = {"hook_event_name": "preToolUse", "cwd": str(Path.cwd()), "tool_name": "Shell"}
        allowed_payload = {**cursor_base, "tool_input": {"command": "git status --short"}}
        denied_payload = {**cursor_base, "tool_input": {"command": "git push --force-with-lease"}}
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
    if harness in ("opencode", "antigravity"):
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


def _has_harness_receipt(home: Path, spec: HarnessSpec) -> bool:
    return _harness_receipt_path(home, spec.id).is_file() or (
        spec.id == "codex" and _receipt_path(home).is_file()
    )


def _harness_root(spec: HarnessSpec, user_home: Path, config_home: str | Path | None) -> Path:
    """The configuration folder the harness itself reads, for discovery and install alike."""
    if config_home is not None:
        chosen = Path(config_home)
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


def _config_root(spec: HarnessSpec, config_path: Path) -> Path:
    """The harness configuration folder that holds this config file."""
    return config_path.parents[len(Path(spec.config_file).parts) - 1]


def _inspect_wiring(
    spec: HarnessSpec,
    config_path: Path,
    home: Path,
    release: Path,
    digest: str,
    *,
    user_home: Path | None = None,
    harness_home: Path | None = None,
    bootstrap: Path | None = None,
) -> dict[str, Any]:
    bootstrap_path = bootstrap or home / "bootstrap.py"
    if spec.id == "codex":
        return inspect_codex_wiring(
            config_path.parent / "config.toml",
            config_path,
            bootstrap_path,
            digest,
            release_path=release,
            entry=spec.entry,
            safe_yolo_home=home if user_home is not None else None,
            user_home=user_home,
            harness_home=harness_home,
        )
    if spec.id == "antigravity":
        return inspect_antigravity_wiring(
            config_path,
            bootstrap_path=bootstrap_path,
            release_path=release,
            manifest_sha256=digest,
            entry=spec.entry,
            safe_yolo_home=home if user_home is not None else None,
            user_home=user_home,
            harness_home=harness_home,
            state_dir=home / "state",
        )
    if spec.id == "claude-code":
        return inspect_claude_code_wiring(
            config_path,
            bootstrap_path,
            digest,
            release_path=release,
            entry=spec.entry,
            safe_yolo_home=home if user_home is not None else None,
            user_home=user_home,
            harness_home=harness_home,
            state_dir=home / "state",
        )
    if spec.id == "opencode":
        return _inspect_opencode_wiring(
            config_path,
            home,
            release,
            digest,
            user_home=user_home,
            harness_home=harness_home,
        )
    return _inspect_cursor_wiring(
        config_path,
        home,
        release,
        digest,
        user_home=user_home,
        harness_home=harness_home,
    )


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
        existing, _ = _read_harness_receipt(home, spec)
        if existing.get('status') == 'active':
            previous_receipt = existing
    if previous_receipt and Path(str(previous_receipt.get('config_path'))) != target:
        raise RuntimeError(
            f"The active {spec.name} installation is wired to {previous_receipt.get('config_path')}, "
            f"not {target}. Run `safe-yolo uninstall --harness {spec.id}` first, or select that folder again."
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
    if previous_receipt:
        current_wiring = _inspect_wiring(spec, target, home, Path(previous_receipt['release']),
                                        previous_receipt['manifest_sha256'], user_home=user,
                                        harness_home=harness_home, bootstrap=Path(previous_receipt['bootstrap']))
        if not current_wiring['healthy']:
            raise RuntimeError('Existing Safe YOLO hook changed; refusing to overwrite it.')
        verified_current = target.read_bytes()
        previous_receipt = {**previous_receipt, 'installed_config_sha256': hashlib.sha256(verified_current).hexdigest()}
    command = _pinned_command(
        home,
        release,
        digest,
        spec.entry,
        user_home=user,
        harness_home=harness_home,
    )
    if spec.id == "opencode":
        payload = _render_opencode_plugin(release, command)
        owned = [payload, verified_current] if previous_receipt else [payload]
        original_bytes, original_mode = _prepare_opencode_plugin(target, release, owned)
    else:
        if spec.id == "cursor":
            candidate, original_bytes, original_mode = _prepare_cursor_hooks(target, home, command)
        elif spec.id == "antigravity":
            def owns(group: Any) -> bool:
                if not previous_receipt:
                    return _is_hand_wired_antigravity_group(group, home)
                return owns_antigravity_group(
                    group,
                    bootstrap_path=Path(previous_receipt['bootstrap']),
                    release_path=Path(previous_receipt['release']),
                    manifest_sha256=previous_receipt['manifest_sha256'],
                    entry=spec.entry,
                    safe_yolo_home=home,
                    user_home=user,
                    harness_home=harness_home,
                    state_dir=home / "state",
                )
            candidate, original_bytes, original_mode = _prepare_antigravity_hooks(target, command, owns)
        else:
            own_slots = None
            if previous_receipt and spec.id == "claude-code":
                # Claude Code runs every matching hook and a deny from any of them wins, so other
                # owners' hooks may stand beside this one. An update swaps only the hook pinned
                # to the installed release, which the wiring check above found exactly once.
                def own_slots(groups: Any) -> list[tuple[int, int]]:
                    return pinned_hook_slots(
                        groups,
                        bootstrap_path=Path(previous_receipt['bootstrap']),
                        release_path=Path(previous_receipt['release']),
                        manifest_sha256=previous_receipt['manifest_sha256'],
                        entry=spec.entry,
                        safe_yolo_home=home,
                        user_home=user,
                        harness_home=harness_home,
                        state_dir=home / "state",
                    )
            candidate, original_bytes, original_mode = _prepare_hooks(
                target, home, command, entry=spec.entry, label=spec.name, own_slots=own_slots
            )
        payload = (json.dumps(candidate, indent=2, allow_nan=spec.id != "antigravity") + "\n").encode()
    backup_root = home / "backups" / (
        f"pre-{spec.id}-{version}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%fZ')}"
    )
    backup_root.mkdir(parents=True, mode=0o700)
    backup_path: Path | None = None
    if original_bytes is not None:
        backup_path = backup_root / target.name
        _atomic_write(backup_path, original_bytes, original_mode)
    _atomic_write(target, payload, original_mode)
    try:
        wiring = _inspect_wiring(
            spec,
            target,
            home,
            release,
            digest,
            user_home=user,
            harness_home=harness_home,
            bootstrap=release / "scripts" / "bootstrap.py",
        )
        canaries = _run_canaries(
            home,
            release,
            digest,
            harness=spec.id,
            entry=spec.entry,
            user_home=user,
            harness_home=harness_home,
        )
        if not wiring["healthy"] or not all(canaries.values()):
            raise RuntimeError(
                f"doctor problems={wiring['problems']}; canaries={canaries}"
            )
    except Exception as error:
        if original_bytes is None:
            _retire(spec.id, target, hashlib.sha256(payload).hexdigest(), home,
                    destination=backup_root / f"failed-{target.name}")
        else:
            _atomic_write(target, original_bytes, original_mode)
        raise RuntimeError(f"Safe YOLO activation failed; previous hooks restored: {error}") from error
    receipt: dict[str, Any] = {
        "schema_version": 1,
        "status": "active",
        "harness": spec.id,
        "version": version,
        "source_commit": source_commit,
        "release": str(release),
        "bootstrap": str(release / "scripts" / "bootstrap.py"),
        "manifest_sha256": digest,
        "config_path": str(target),
        "user_home": str(user),
        "harness_home": str(harness_home),
        "installed_config_sha256": _sha256(target),
        "previous_config_existed": original_bytes is not None,
        "previous_config_backup": str(backup_path) if backup_path else None,
        "previous_config_mode": original_mode,
        "healthy": True,
        "canaries": canaries,
        "next_action": {
            "codex": "Restart Codex, open /hooks, review this command, and trust its hash.",
            "claude-code": "Restart Claude Code, then run /hooks and verify the Safe YOLO PreToolUse hook.",
            "cursor": "Cursor watches the user hooks file and reloads it automatically; verify Safe YOLO in Hooks.",
            "opencode": (
                "Run `opencode service restart` if the OpenCode background service is running, then start a new "
                "session. Doctor checks the plugin file and release but cannot prove OpenCode loaded the plugin: "
                "run `opencode api plugin.list` against the server and location your sessions use and confirm the "
                "safe-yolo entry has state status `active`, not `failed`, with this plugin file as its source "
                "(repeat it if the list is empty while plugins load), then in a session check that "
                "`echo hello` runs and `git push --force origin main` in a scratch repository is denied."
            ),
            "antigravity": (
                "Start a new Antigravity session, run /hooks and confirm the safe-yolo PreToolUse hook is listed. "
                "Doctor checks the hooks file, release and pinned command but cannot prove Antigravity loaded the "
                "hook. Antigravity ignores a hook that crashes, times out or prints invalid output."
            ),
        }[spec.id],
    }
    if previous_receipt:
        receipt['original_install'] = previous_receipt.get('original_install', {
            key: previous_receipt[key] for key in ('previous_config_existed', 'previous_config_backup',
                                                 'previous_config_mode')})
        receipt['previous_install'] = {key: value for key, value in previous_receipt.items()
                                       if key != 'previous_install'}
    _atomic_write(
        _harness_receipt_path(home, spec.id),
        (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode(),
    )
    return receipt


def doctor_harness(
    *, harness: str, safe_yolo_home: str | Path, user_home: str | Path
) -> dict[str, Any]:
    spec = _spec(harness)
    home = Path(safe_yolo_home).expanduser().resolve(strict=False)
    receipt, _ = _read_harness_receipt(home, spec)
    problems: list[str] = []
    if receipt.get("status") != "active":
        problems.append("installation receipt is not active")
    config_path = Path(str(receipt.get("config_path", "")))
    if not config_path.is_file():
        problems.append("installed harness configuration is missing")
    elif _sha256(config_path) != receipt.get("installed_config_sha256"):
        problems.append("installed harness configuration changed after activation")
    release = Path(str(receipt.get("release", "")))
    digest = str(receipt.get("manifest_sha256", ""))
    receipt_user_home = receipt.get("user_home")
    receipt_harness_home = receipt.get("harness_home")
    user = Path(str(receipt_user_home)) if receipt_user_home else None
    harness_home = Path(str(receipt_harness_home)) if receipt_harness_home else None
    receipt_bootstrap = receipt.get("bootstrap")
    bootstrap = Path(str(receipt_bootstrap)) if receipt_bootstrap else home / "bootstrap.py"
    release_report = inspect_release(release, digest)
    problems.extend(release_report["problems"])
    wiring = _inspect_wiring(
        spec,
        config_path,
        home,
        release,
        digest,
        user_home=user,
        harness_home=harness_home,
        bootstrap=bootstrap,
    )
    problems.extend(wiring["problems"])
    canaries = (
        _run_canaries(
            home,
            release,
            digest,
            harness=spec.id,
            entry=spec.entry,
            user_home=user,
            harness_home=harness_home,
        )
        if release_report["healthy"]
        else {"allow": False, "deny": False}
    )
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
    receipt, receipt_path = _read_harness_receipt(home, spec)
    if receipt.get("status") != "active":
        raise RuntimeError(f"Safe YOLO {spec.name} installation is not active.")
    config_path = Path(str(receipt.get("config_path", "")))
    if receipt.get("previous_config_existed"):
        if (
            config_path.is_symlink()
            or not config_path.is_file()
            or _config_path_problem(spec.id, config_path)
            or _sha256(config_path) != receipt.get("installed_config_sha256")
        ):
            raise RuntimeError(
                f"{spec.name} configuration changed since installation; refusing to overwrite newer work."
            )
        backup = Path(str(receipt.get("previous_config_backup")))
        if not backup.is_file():
            raise RuntimeError("Previous configuration backup is missing; refusing an incomplete rollback.")
        _atomic_write(config_path, backup.read_bytes(), int(receipt.get("previous_config_mode", 0o600)))
    else:
        retained = _retire(spec.id, config_path, str(receipt.get("installed_config_sha256")), home)
        receipt["deactivated_config_backup"] = str(retained)
    receipt["status"] = "inactive"
    receipt["deactivated_at"] = datetime.now(UTC).isoformat()
    _atomic_write(receipt_path, (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode())
    return {
        "status": "inactive",
        "harness": spec.id,
        "restored_previous_config": bool(receipt.get("previous_config_existed")),
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
            if not selected:
                raise RuntimeError('No supported harness detected. Run harnesses, then install --harness <id>.')
            revision = _current_commit(source)
            from scripts.global_cli import install_command
            launcher = install_command(source, args.home.resolve(), args.user_home.resolve())
            reports, skipped = [], []
            for harness in selected:
                try:
                    reports.append(install_harness(harness=harness, source=source, safe_yolo_home=args.home,
                                   user_home=args.user_home, config_home=args.config_home,
                                   expected_commit=revision))
                except OpenCodeV1Error as error:
                    if args.harness:
                        raise
                    skipped.append({'harness': harness, 'reason': str(error)})
            result = reports[0] if args.harness else {'healthy': True, 'reports': reports, 'skipped': skipped}
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
            selected = [args.harness] if args.harness else [receipt['harness'] for receipt in active_receipts(args.home.resolve())]
            if not selected:
                raise RuntimeError('No active installations found.')
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
