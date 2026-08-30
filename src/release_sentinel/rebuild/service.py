from __future__ import annotations

from pathlib import Path

from release_sentinel.rebuild.model import ProposalBundle, RebuildBaseline, fingerprint_tree


class RebuildError(RuntimeError):
    pass


class CandidateWriter:
    """Deterministic writer: models propose; only this gate commits files."""

    CONTROL = ".release-sentinel"

    def apply(
        self,
        target: Path,
        bundle: ProposalBundle,
        baseline: RebuildBaseline,
        *,
        pinned_source_sha256: str,
        pinned_reference_sha256: str,
        pinned_bundle_sha256: str,
    ) -> int:
        target = target.resolve()
        if any(target.iterdir()):
            raise RebuildError("candidate workspace must start empty")
        if pinned_source_sha256 != baseline.source_sha256:
            raise RebuildError("source baseline pin mismatch")
        if pinned_reference_sha256 != baseline.reference_sha256:
            raise RebuildError("reference pin mismatch")
        if pinned_bundle_sha256 != bundle.sha256:
            raise RebuildError("proposal bundle pin mismatch")
        seen: set[str] = set()
        for proposal in bundle.proposals:
            rel = Path(proposal.path)
            if rel.is_absolute() or ".." in rel.parts or not rel.parts or rel.parts[0] == self.CONTROL:
                raise RebuildError("proposal path is outside writable candidate namespace")
            key = rel.as_posix()
            if key in seen:
                raise RebuildError("duplicate proposal path")
            seen.add(key)
        for proposal in bundle.proposals:
            path = target / proposal.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(proposal.content, encoding="utf-8")
        return len(bundle.proposals)
