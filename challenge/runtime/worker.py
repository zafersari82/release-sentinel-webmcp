#!/usr/bin/env python3
"""Tiny untrusted-code adapter used only inside the public challenge container.

It deliberately does not import Release Sentinel. The only input is a published
JSON snapshot; the only output is a JSON object. The host evaluates that object
as hostile advisory data in a separate process.

IMPORTANT: this worker is fail-closed. It refuses to execute contestant code
unless the expected arena confinement contract is observable from inside the
process. The launcher remains responsible for creating that confinement.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import resource
import socket
import sys
from pathlib import Path

MAX_INPUT = 128 * 1024
MAX_OUTPUT = 64 * 1024
ARENA_UID = 10001
ARENA_ENV = "RELEASE_SENTINEL_ARENA_CONTAINER"


class ConfinementError(RuntimeError):
    """Raised when the worker is not running under the expected arena profile."""


def fail(message: str, code: int = 2) -> int:
    raw = json.dumps({"arena_error": message}, separators=(",", ":")).encode()
    sys.stdout.buffer.write(raw[:MAX_OUTPUT])
    return code


def _mount_options(mountpoint: str) -> set[str]:
    """Return VFS mount options for an exact mountpoint from /proc/self/mountinfo."""
    try:
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfinementError("cannot inspect mount namespace") from exc

    for line in lines:
        fields = line.split()
        # mountinfo fields: id parent major:minor root mountpoint options ... - fstype source superopts
        if len(fields) >= 6 and fields[4] == mountpoint:
            return set(fields[5].split(","))
    raise ConfinementError(f"required mountpoint missing: {mountpoint}")


def _proc_status() -> dict[str, str]:
    try:
        lines = Path("/proc/self/status").read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfinementError("cannot inspect process security status") from exc
    result: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def assert_arena_confinement() -> None:
    """Refuse to execute untrusted code outside the declared Docker arena profile.

    This is defense-in-depth, not the sandbox itself. It deliberately checks
    several independent properties so merely exporting one environment variable
    on the host is not enough to unlock contestant execution.
    """
    if os.environ.get(ARENA_ENV) != "1":
        raise ConfinementError("arena marker missing")
    if os.geteuid() != ARENA_UID:
        raise ConfinementError("unexpected worker uid")
    if not Path("/.dockerenv").is_file():
        raise ConfinementError("container marker missing")

    root_opts = _mount_options("/")
    if "ro" not in root_opts or "rw" in root_opts:
        raise ConfinementError("root filesystem is not read-only")

    submission_opts = _mount_options("/submission")
    if "ro" not in submission_opts or "rw" in submission_opts:
        raise ConfinementError("submission mount is not read-only")

    tmp_opts = _mount_options("/tmp")
    required_tmp = {"rw", "nosuid", "nodev", "noexec"}
    if not required_tmp.issubset(tmp_opts):
        raise ConfinementError("tmpfs hardening options are incomplete")

    status = _proc_status()
    if status.get("NoNewPrivs") != "1":
        raise ConfinementError("no-new-privileges is not active")
    if status.get("CapEff", "").strip("0"):
        raise ConfinementError("effective capabilities are not empty")
    # Docker's default seccomp profile reports mode 2 (filter). Refuse a worker
    # launched with seccomp disabled because arbitrary code would receive a
    # meaningfully weaker syscall boundary than the published arena contract.
    if status.get("Seccomp") != "2":
        raise ConfinementError("seccomp filter is not active")

    interfaces = {name for _, name in socket.if_nameindex()}
    if interfaces != {"lo"}:
        raise ConfinementError("network namespace is not isolated")

    soft_nofile, hard_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_nofile > 64 or hard_nofile > 64:
        raise ConfinementError("file-descriptor limit is too permissive")

    attack_path = Path("/submission/attack.py")
    if attack_path.is_symlink() or not attack_path.is_file():
        raise ConfinementError("submission must contain a regular attack.py")


def main() -> int:
    try:
        assert_arena_confinement()
    except ConfinementError as exc:
        return fail(f"arena confinement check failed: {exc}", code=78)

    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        return fail("snapshot too large")
    try:
        snapshot = json.loads(raw)
    except Exception:
        return fail("snapshot is not valid JSON")

    attack_path = Path("/submission/attack.py")
    spec = importlib.util.spec_from_file_location("public_attack", attack_path)
    if spec is None or spec.loader is None:
        return fail("could not load attack.py")
    module = importlib.util.module_from_spec(spec)
    try:
        # Suppress arbitrary contestant stdout/stderr so stdout remains a strict
        # machine channel owned by the arena worker.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            spec.loader.exec_module(module)
            fn = getattr(module, "attack", None)
            if not callable(fn):
                raise RuntimeError("attack.py must define attack(snapshot)")
            output = fn(snapshot)
        if not isinstance(output, dict):
            return fail("attack(snapshot) must return a dict")
        encoded = json.dumps(
            output,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except BaseException as exc:
        # Do not expose stack traces or host internals through the protocol.
        return fail(f"attack execution failed: {type(exc).__name__}")
    if len(encoded) > MAX_OUTPUT:
        return fail("attack output exceeds 64 KiB")
    sys.stdout.buffer.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
