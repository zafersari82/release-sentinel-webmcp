from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable, Mapping

from release_sentinel.domain.evidence import Decision
from release_sentinel.domain.release import ReleaseReport, ReleaseRequest
from release_sentinel.release.engine import advisory_projection
from release_sentinel.remediation.model import RepairContext, RepairProposal, RemediationOutcome


class RepairRejected(RuntimeError):
    """Fail-closed rejection of an untrusted repair proposal."""


_MAX_FILE_BYTES = 256 * 1024
_MAX_CHANGED_FILES = 16


def _safe_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RepairRejected(f"repository contains symlink: {path.relative_to(root)}")
        if path.is_file():
            files.append(path)
    return sorted(files, key=lambda p: p.relative_to(root).as_posix())


def repository_sha256(root: str | Path) -> str:
    """Hash the complete repository tree with names and bytes bound together."""
    base = Path(root).resolve()
    if not base.is_dir():
        raise ValueError("repository root must be a directory")
    digest = hashlib.sha256()
    for path in _safe_files(base):
        rel = path.relative_to(base).as_posix().encode("utf-8")
        data = path.read_bytes()
        digest.update(len(rel).to_bytes(4, "big"))
        digest.update(rel)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _normalize_relpath(raw: str) -> str:
    candidate = PurePosixPath(raw.replace("\\", "/"))
    if candidate.is_absolute() or not candidate.parts:
        raise RepairRejected("repair path must be relative")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise RepairRejected(f"unsafe repair path: {raw}")
    return candidate.as_posix()


def _validate_changes(changes: Mapping[str, str], allowed_paths: frozenset[str]) -> dict[str, str]:
    if not changes:
        raise RepairRejected("agent returned an empty repair")
    if len(changes) > _MAX_CHANGED_FILES:
        raise RepairRejected("agent attempted to modify too many files")
    normalized: dict[str, str] = {}
    for raw_path, content in changes.items():
        path = _normalize_relpath(str(raw_path))
        if path not in allowed_paths:
            raise RepairRejected(f"agent attempted an unauthorized write: {path}")
        encoded = str(content).encode("utf-8")
        if len(encoded) > _MAX_FILE_BYTES:
            raise RepairRejected(f"repair exceeds file-size limit: {path}")
        normalized[path] = str(content)
    return normalized


def materialize_repair(
    source: str | Path,
    destination: str | Path,
    proposal: RepairProposal,
    *,
    allowed_paths: Iterable[str],
) -> str:
    """Create a new source tree from a proposal without mutating the original."""
    src = Path(source).resolve()
    dst = Path(destination).resolve()
    allowed = frozenset(_normalize_relpath(path) for path in allowed_paths)
    if repository_sha256(src) != proposal.base_source_sha256:
        raise RepairRejected("proposal base digest does not match current source")
    changes = _validate_changes(proposal.files, allowed)
    if dst.exists():
        raise RepairRejected("repair destination must not already exist")
    # Reject symlinks before copy. The trusted coordinator never follows an
    # agent-created link out of the staging root.
    _safe_files(src)
    shutil.copytree(src, dst, symlinks=True)
    for rel, content in changes.items():
        target = (dst / rel).resolve()
        try:
            target.relative_to(dst)
        except ValueError as exc:
            raise RepairRejected(f"repair escaped staging root: {rel}") from exc
        if target.exists() and target.is_symlink():
            raise RepairRejected(f"agent attempted to replace a symlink: {rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    repaired = repository_sha256(dst)
    if repaired == proposal.base_source_sha256:
        raise RepairRejected("repair produced no source change")
    return repaired


Evaluator = Callable[[ReleaseRequest], ReleaseReport]
Remediator = Callable[[RepairContext], Mapping[str, str]]


class RemediationCoordinator:
    """Let an AI repair code while withholding all release authority.

    Security properties are structural:
    * the model receives a redacted immutable finding projection;
    * it can only propose full-file contents for an explicit allowlist;
    * the original repository is never mutated;
    * a new tree hash is computed after applying the proposal;
    * the evaluator is invoked again from scratch on the new tree;
    * the proposal itself has no decision field and cannot approve itself.
    """

    def __init__(
        self,
        evaluator: Evaluator,
        remediator: Remediator,
        *,
        producer_agent_id: str,
        allowed_paths: Iterable[str],
    ) -> None:
        self.evaluator = evaluator
        self.remediator = remediator
        self.producer_agent_id = producer_agent_id
        self.allowed_paths = frozenset(_normalize_relpath(path) for path in allowed_paths)
        if not self.allowed_paths:
            raise ValueError("remediation requires an explicit non-empty write allowlist")

    def run(self, request: ReleaseRequest) -> RemediationOutcome:
        original_sha = repository_sha256(request.repository_path)
        before = self.evaluator(request)
        if before.decision is Decision.GO:
            return RemediationOutcome(
                release_id=request.release_id,
                original_source_sha256=original_sha,
                repaired_source_sha256=None,
                before=before,
                after=None,
                proposal=None,
                reevaluated_from_scratch=False,
            )

        context = RepairContext(
            release_id=request.release_id,
            base_source_sha256=original_sha,
            findings=tuple(dict(item) for item in advisory_projection(before.findings)),
        )
        raw_changes = self.remediator(context)
        changes = _validate_changes(raw_changes, self.allowed_paths)
        proposal = RepairProposal(
            release_id=request.release_id,
            base_source_sha256=original_sha,
            producer_agent_id=self.producer_agent_id,
            files=changes,
        )

        with tempfile.TemporaryDirectory(prefix="release-sentinel-repair-") as tmp:
            staged = Path(tmp) / "repository"
            repaired_sha = materialize_repair(
                request.repository_path, staged, proposal, allowed_paths=self.allowed_paths
            )
            repaired_request = ReleaseRequest(
                release_id=f"{request.release_id}-repair-{repaired_sha[:12]}",
                repository_path=staged,
                commit_sha=request.commit_sha,
            )
            after = self.evaluator(repaired_request)

        return RemediationOutcome(
            release_id=request.release_id,
            original_source_sha256=original_sha,
            repaired_source_sha256=repaired_sha,
            before=before,
            after=after,
            proposal=proposal,
            reevaluated_from_scratch=True,
        )
