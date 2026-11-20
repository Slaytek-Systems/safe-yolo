from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ENTRYPOINTS = {
    "codex": "adapters/codex.py",
    "codex_v2": "adapters/codex_v2.py",
    "codex_v3": "adapters/codex_v3.py",
    "devin_v3": "adapters/devin_v3.py",
    "claude_code_v3": "adapters/claude_code_v3.py",
    "grok_v3": "adapters/grok_v3.py",
    "cursor_v3": "adapters/cursor_v3.py",
    "opencode_v3": "adapters/opencode_v3.py",
    "antigravity_v3": "adapters/antigravity_v3.py",
    "prompt": "adapters/codex_prompt.py",
    "cursor": "adapters/cursor.py",
    "cursor_prompt": "adapters/cursor_prompt.py",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verified_entry(release_dir: str | Path, entry: str, *, expected_manifest_hash: str) -> Path:
    if entry not in ENTRYPOINTS:
        raise ValueError(f"Unknown Safe YOLO entrypoint: {entry}")
    if not expected_manifest_hash:
        raise ValueError("A trusted manifest hash is required.")
    release = Path(release_dir).resolve()
    manifest_path = release / "manifest.json"
    if not manifest_path.is_file() or _sha256(manifest_path) != expected_manifest_hash:
        raise ValueError("manifest hash mismatch")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"manifest unreadable: {type(error).__name__}") from error
    if manifest.get("entrypoints", {}).get(entry) != ENTRYPOINTS[entry]:
        raise ValueError(f"entrypoint mismatch: {entry}")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise ValueError("manifest files entry is invalid")
    for relative_path, expected_hash in files.items():
        path = release / relative_path
        if not path.is_file() or _sha256(path) != expected_hash:
            raise ValueError(f"release verification failed: {relative_path}")
    return release / ENTRYPOINTS[entry]


def _fail(entry: str, message: str) -> int:
    if entry == "antigravity_v3":
        print(json.dumps({"decision": "deny", "reason": f"Safe YOLO fail-closed: {message}"}))
        return 0
    print(f"Safe YOLO fail-closed: {message}", file=sys.stderr)
    return 2


def _requested_entry(argv: list[str]) -> str | None:
    entry = None
    index = 0
    while index < len(argv):
        if argv[index] == "--entry" and index + 1 < len(argv):
            entry = argv[index + 1]
            index += 1
        elif argv[index].startswith("--entry="):
            entry = argv[index].removeprefix("--entry=")
        index += 1
    return entry


def main() -> int:
    if _requested_entry(sys.argv[1:]) != "antigravity_v3":
        return _dispatch(_parser().parse_args())
    # Antigravity ignores a hook that exits non-zero or prints nothing, so stdout carries one decision and nothing else.
    try:
        with contextlib.redirect_stdout(sys.stderr):
            args = _parser().parse_args()
        return _dispatch(args)
    except SystemExit:
        return _fail("antigravity_v3", "the hook command's arguments are invalid")
    except Exception as error:
        return _fail("antigravity_v3", f"{type(error).__name__}: {error}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify a Safe YOLO release before dispatching a Codex hook.")
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--entry", choices=sorted(ENTRYPOINTS), required=True)
    parser.add_argument("--host-contract", type=Path)
    parser.add_argument("--audit-only", action="store_true")
    parser.add_argument("--state-dir", type=Path, default=Path(os.environ.get("SAFE_YOLO_STATE", "~/.safe-yolo/state")).expanduser())
    parser.add_argument("--safe-yolo-home", type=Path)
    parser.add_argument("--user-home", type=Path)
    parser.add_argument("--harness-home", type=Path)
    return parser


def _dispatch(args: argparse.Namespace) -> int:
    try:
        entry = verified_entry(args.release, args.entry, expected_manifest_hash=args.manifest_sha256)
    except ValueError as error:
        return _fail(args.entry, str(error))
    command = [sys.executable, str(entry), "--state-dir", str(args.state_dir)]
    if args.safe_yolo_home is not None:
        command.extend(["--safe-yolo-home", str(args.safe_yolo_home)])
    if args.user_home is not None:
        command.extend(["--user-home", str(args.user_home)])
    harness_home_flags = {
        "codex_v3": "--codex-home",
        "claude_code_v3": "--claude-home",
        "cursor_v3": "--cursor-home",
        "opencode_v3": "--opencode-config",
        "antigravity_v3": "--gemini-home",
    }
    if args.harness_home is not None:
        harness_flag = harness_home_flags.get(args.entry)
        if harness_flag is None:
            return _fail(args.entry, f"harness home is unsupported for {args.entry}")
        command.extend([harness_flag, str(args.harness_home)])
    if args.host_contract is not None:
        command.extend(["--host-contract", str(args.host_contract)])
    if args.audit_only:
        command.append("--audit-only")
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(args.release) if not existing_pythonpath else f"{args.release}{os.pathsep}{existing_pythonpath}"
    if args.entry != "antigravity_v3":
        return subprocess.run(command, check=False, env=environment).returncode
    try:
        completed = subprocess.run(command, check=False, env=environment, stdout=subprocess.PIPE, text=True)
        reply = json.loads(completed.stdout)
    except (OSError, ValueError):
        return _fail(args.entry, "the Antigravity adapter did not run or gave no decision")
    if completed.returncode != 0 or not isinstance(reply, dict) or reply.get("decision") not in ("allow", "deny"):
        return _fail(args.entry, f"the Antigravity adapter exited {completed.returncode} without a decision")
    sys.stdout.write(completed.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
