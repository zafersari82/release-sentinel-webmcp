from __future__ import annotations

import argparse
import json
from importlib.resources import files
from pathlib import Path

from release_sentinel import __version__
from release_sentinel.coverage.comparison import build_reference_demo_payload
from release_sentinel.agents.advisory import compromised_agent_simulation, deterministic_advisory
from release_sentinel.domain.release import ReleaseRequest
from release_sentinel.execution.cloudrun import CloudRunSandboxExecutor
from release_sentinel.execution.demo import BundledDemoExecutor
from release_sentinel.policy.model import build_policy
from release_sentinel.release.engine import ReleaseEngine
from release_sentinel.release.gatekeeper import A2AGatekeeperClient, LocalDeterministicGatekeeper, gatekeeper_from_env
from release_sentinel.operations.attestation import build_evidence_bundle, sign_evidence_bundle, demo_signer_from_env


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _fixture():
    base = Path(str(files("release_sentinel"))) / "demo_fixture"
    policy = build_policy(_load_json(base / "organization-policy.json"))
    expected = (base / "repository_vulnerable.sha256").read_text().strip()
    return base, policy, expected


def _demo() -> int:
    base, policy, expected = _fixture()
    report = ReleaseEngine(BundledDemoExecutor(expected), advisor=deterministic_advisory, gatekeeper=gatekeeper_from_env()).evaluate(
        ReleaseRequest("demo-release", base / "repository_vulnerable"), policy
    )
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    return 2 if report.decision.value == "NO_GO" else 0


def _verdict_proof(gatekeeper_url: str) -> int:
    base, policy, expected = _fixture()
    release_id = "jury-verdict-independence"
    # Collect machine evidence locally, then cryptographically attest it with an
    # ephemeral demo key. Production uses a separate Cloud Run attestor + Cloud KMS.
    source_report = ReleaseEngine(
        BundledDemoExecutor(expected), advisor=None, gatekeeper=LocalDeterministicGatekeeper()
    ).evaluate(ReleaseRequest(release_id, base / "repository_vulnerable"), policy)
    signed = sign_evidence_bundle(
        build_evidence_bundle(source_report, source_sha256=expected),
        demo_signer_from_env(),
    )
    advisory = compromised_agent_simulation(ReleaseRequest(release_id, base / "repository_vulnerable"), source_report.findings)
    opinions = list(advisory.get("opinions") or [])
    verdict = A2AGatekeeperClient(gatekeeper_url, audience=None).decide_attested(
        release_id=release_id, source_sha256=expected, policy_sha256=policy.sha256,
        signed_evidence_bundle=signed, agent_opinions=opinions,
    )
    proof = {
        "proof": "VERDICT_INDEPENDENCE",
        "agents": {"go": sum(1 for item in opinions if item.get("vote") == "GO"), "total": len(opinions)},
        "final_verdict": verdict.decision.value,
        "gatekeeper": verdict.to_dict(),
        "policy_sha256": policy.sha256,
        "evidence_bundle_sha256": signed.bundle_sha256,
        "evidence_key_id": signed.key_id,
        "signed_evidence": True,
        "blockers": len([f for f in source_report.findings if f.blocking_evidence()]),
    }
    print(json.dumps(proof, indent=2, ensure_ascii=False))
    return 0 if proof["agents"]["go"] == proof["agents"]["total"] == 4 and proof["final_verdict"] == "NO_GO" and proof["gatekeeper"]["agent_influence"] == 0 else 3


def _evaluate(repository: Path, policy_path: Path, release_id: str) -> int:
    policy = build_policy(_load_json(policy_path))
    report = ReleaseEngine(CloudRunSandboxExecutor(), advisor=deterministic_advisory, gatekeeper=LocalDeterministicGatekeeper()).evaluate(
        ReleaseRequest(release_id, repository), policy
    )
    print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
    return 2 if report.decision.value == "NO_GO" else 0



def _coverage_demo(challenge: str = "cross-tenant") -> int:
    print(json.dumps(build_reference_demo_payload(challenge), indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="release-sentinel")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Run the bundled offline evidence demo")
    proof = sub.add_parser("verdict-proof", help="Prove that 4/4 simulated compromised agents cannot override the Go gatekeeper")
    proof.add_argument("--gatekeeper-url", default="http://127.0.0.1:8091")
    coverage = sub.add_parser("coverage-demo", help="Compare deterministic offline Coverage Arena reference policies")
    coverage.add_argument("--challenge", choices=("cross-tenant", "path-traversal"), default="cross-tenant")
    ev = sub.add_parser("evaluate", help="Evaluate a repository with real sandbox execution and the local deterministic reference gate")
    ev.add_argument("repository", type=Path)
    ev.add_argument("--policy", type=Path, required=True)
    ev.add_argument("--release-id", default="release-local")
    args = parser.parse_args()
    if args.command == "demo":
        return _demo()
    if args.command == "verdict-proof":
        return _verdict_proof(args.gatekeeper_url)
    if args.command == "coverage-demo":
        return _coverage_demo(args.challenge)
    return _evaluate(args.repository, args.policy, args.release_id)


if __name__ == "__main__":
    raise SystemExit(main())
