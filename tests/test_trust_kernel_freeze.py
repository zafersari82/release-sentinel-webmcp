from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).parents[1]

REQUIRED_TRUST_SURFACE = {
    "gatekeeper/internal/verdict/attestation.go",
    "gatekeeper/internal/verdict/verdict.go",
    "gatekeeper/cmd/gatekeeper/main.go",
    "src/release_sentinel/operations/attestation.py",
    "src/release_sentinel/interfaces/attestor_api.py",
    "src/release_sentinel/release/gatekeeper.py",
    "src/release_sentinel/release/engine.py",
    "src/release_sentinel/release/scanners.py",
    "src/release_sentinel/domain/evidence.py",
    "src/release_sentinel/domain/release.py",
    "src/release_sentinel/domain/immutable.py",
    "src/release_sentinel/policy/model.py",
    "src/release_sentinel/execution/base.py",
    "src/release_sentinel/execution/cloudrun.py",
    "src/release_sentinel/infrastructure/evidence_signing.py",
    "src/release_sentinel/infrastructure/settings.py",
    "deploy/evidence-key.sh",
    "deploy/attestor.sh",
    "deploy/gatekeeper.sh",
    "deploy/cloudrun.sh",
    "deploy/cloud-proof.sh",
    "deploy/bootstrap-gcp.sh",
    "tests/test_verdict_independence.py",
    "tests/test_release_authority.py",
    "tests/test_advisory_evidence_boundary.py",
    "tests/test_a2a_version_conformance.py",
    "tests/test_go_gatekeeper_a2a.py",
    "tests/test_trust_kernel_freeze.py",
    "packages/agentseal/src/agentseal/seal.py",
    "packages/agentseal/src/agentseal/stage.py",
    "packages/agentseal/src/agentseal/check.py",
    "packages/agentseal/src/agentseal/hostile.py",
    "packages/agentseal/src/agentseal/certificate.py",
    "src/release_sentinel/remediation/model.py",
    "src/release_sentinel/remediation/service.py",
    "tests/test_remediation_authority.py",
}


def _lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def test_frozen_trust_kernel_scope_and_hash_manifest_match_source():
    scope = ROOT / "trust" / "TRUST_KERNEL.files"
    manifest = ROOT / "trust" / "TRUST_KERNEL.sha256"
    assert scope.is_file() and manifest.is_file()

    declared = _lines(scope)
    rows = _lines(manifest)
    manifested = [row.split("  ", 1)[1] for row in rows]

    assert len(declared) == len(set(declared)), "trust scope must not contain duplicates"
    assert declared == manifested, "hash manifest must exactly follow the declared trust surface"
    assert REQUIRED_TRUST_SURFACE <= set(declared), "trust-critical lifecycle code must not fall out of the frozen surface"

    for row in rows:
        expected, rel = row.split("  ", 1)
        target = ROOT / rel
        assert target.is_file(), rel
        assert hashlib.sha256(target.read_bytes()).hexdigest() == expected, rel
